package main

// The portable build is ONE exe: the program, and inside it, as an embedded zip, the pinned sing-box core and the
// licence texts. At every start the components are unpacked (or checked, when already there) into the program's
// own data folder, and the core is verified before it runs:
//
//   - the embedded zip must match the SHA-256 baked in at build time (payloadSHA256) and its manifest must agree
//     with it and with the core's baked hash (coreSHA256);
//   - the folder components\<first 16 hex of the payload hash>\ is content-addressed: a newer exe unpacks into
//     ANOTHER folder, so an update never touches the files of a running older instance;
//   - every file on disk is compared with the manifest at every start; anything missing or different is unpacked
//     again from the exe (the exe is the authority) into a temporary folder and swapped in with a rename;
//   - the core is then opened for reading WITHOUT write or delete sharing and kept open until the program ends, and
//     hashed once more through that very handle, so it cannot be replaced between the check and the start.
//
// Nothing is written next to the exe (it may sit in a read-only folder); nothing is registered anywhere.

import (
	"archive/zip"
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const (
	manifestName   = "MANIFEST.sha256"
	coreEntry      = "sing-box.exe"
	maxEntryBytes  = 200 << 20
	maxPayloadSize = 400 << 20
)

// payloadSpec is the embedded zip with the hashes baked into the program.
type payloadSpec struct {
	zip         []byte
	wantPayload string
	wantCore    string
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// readManifest parses MANIFEST.sha256 ("<sha256>  <path>" lines) from the zip and checks that it lists exactly the
// files of the zip.
func readManifest(zr *zip.Reader) (map[string]string, error) {
	var mf *zip.File
	names := map[string]bool{}
	for _, f := range zr.File {
		if f.Name == manifestName {
			mf = f
			continue
		}
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		names[f.Name] = true
	}
	if mf == nil {
		return nil, errors.New("no manifest")
	}
	rc, err := mf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(rc, 1<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		h, p, ok := strings.Cut(line, "  ")
		if !ok || !hexRe.MatchString(h) || !safeEntry(p) {
			return nil, errors.New("bad manifest line")
		}
		if _, dup := out[p]; dup {
			return nil, errors.New("duplicate manifest entry")
		}
		out[p] = h
	}
	if len(out) != len(names) {
		return nil, errors.New("manifest and zip differ")
	}
	for p := range names {
		if _, ok := out[p]; !ok {
			return nil, errors.New("manifest and zip differ")
		}
	}
	return out, nil
}

// safeEntry accepts only plain relative names under the two allowed roots: no "..", no drive, no backslash.
func safeEntry(p string) bool {
	if p == "" || strings.ContainsAny(p, "\\:") || strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return false
		}
	}
	return p == coreEntry || strings.HasPrefix(p, "licenses/")
}

func hashFile(p string) (string, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() { // a link or anything else is not what we unpacked
		return "", errors.New("not a regular file")
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyDir compares every manifest file with the disk.
func verifyDir(dir string, manifest map[string]string) error {
	for p, want := range manifest {
		got, err := hashFile(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil || got != want {
			return fmt.Errorf("component %s is missing or changed", p)
		}
	}
	return nil
}

var componentDirRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ensureComponents makes sure components\<hash16>\ under home holds exactly the verified payload and returns it.
func ensureComponents(home string, p payloadSpec) (string, error) {
	if !hexRe.MatchString(p.wantPayload) || !hexRe.MatchString(p.wantCore) {
		return "", errors.New("this build carries no component hashes")
	}
	if len(p.zip) == 0 || len(p.zip) > maxPayloadSize {
		return "", errors.New("the embedded components are missing")
	}
	if sha256Hex(p.zip) != p.wantPayload {
		return "", errors.New("the embedded components do not match this build (the program file is damaged)")
	}
	zr, err := zip.NewReader(bytesReaderAt(p.zip), int64(len(p.zip)))
	if err != nil {
		return "", errors.New("the embedded components cannot be read")
	}
	manifest, err := readManifest(zr)
	if err != nil {
		return "", errors.New("the component list is damaged")
	}
	if manifest[coreEntry] != p.wantCore {
		return "", errors.New("the component list does not match the pinned core")
	}
	base := filepath.Join(home, "components")
	final := filepath.Join(base, p.wantPayload[:16])
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("cannot create the program's data folder: %w", err)
	}
	defer cleanupComponents(base, p.wantPayload[:16])
	if verifyDir(final, manifest) == nil {
		return final, nil
	}

	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	tmp := filepath.Join(base, ".tmp-"+hex.EncodeToString(rnd))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return "", fmt.Errorf("cannot unpack the components: %w", err)
	}
	if err := unpackAll(zr, manifest, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	if err := verifyDir(tmp, manifest); err != nil {
		_ = os.RemoveAll(tmp)
		return "", errors.New("the unpacked components did not pass the check")
	}
	if _, err := os.Lstat(final); err == nil { // a damaged copy is moved aside, never edited in place
		old := filepath.Join(base, ".old-"+hex.EncodeToString(rnd))
		if err := os.Rename(final, old); err != nil {
			_ = os.RemoveAll(tmp)
			return "", errors.New("the components in the data folder are damaged and in use; close other copies of Runet Access")
		}
		defer os.RemoveAll(old)
	}
	if err := os.Rename(tmp, final); err != nil {
		if verifyDir(final, manifest) == nil { // somebody else (a second start) unpacked the same thing meanwhile
			_ = os.RemoveAll(tmp)
			return final, nil
		}
		_ = os.RemoveAll(tmp)
		return "", fmt.Errorf("cannot put the components in place: %w", err)
	}
	return final, nil
}

func unpackAll(zr *zip.Reader, manifest map[string]string, dst string) error {
	for _, f := range zr.File {
		if f.Name == manifestName || strings.HasSuffix(f.Name, "/") {
			continue
		}
		if !safeEntry(f.Name) {
			return errors.New("the embedded components contain an unsafe name")
		}
		if f.UncompressedSize64 > maxEntryBytes {
			return errors.New("the embedded components are too large")
		}
		target := filepath.Join(dst, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("cannot unpack the components: %w", err)
		}
		rc, err := f.Open()
		if err != nil {
			return errors.New("the embedded components cannot be read")
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			rc.Close()
			return fmt.Errorf("cannot unpack the components: %w", err)
		}
		h := sha256.New()
		_, cerr := io.Copy(io.MultiWriter(out, h), io.LimitReader(rc, maxEntryBytes+1))
		rc.Close()
		if err := out.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return fmt.Errorf("cannot unpack the components: %w", cerr)
		}
		if hex.EncodeToString(h.Sum(nil)) != manifest[f.Name] {
			return errors.New("an embedded component does not match its recorded hash")
		}
	}
	return nil
}

// cleanupComponents removes what only this program makes: left-over temporary/aside folders and the folders of other
// builds (their instance cannot be running: the data folder has one lock). Best effort; a folder still in use stays.
func cleanupComponents(base, keep string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() || n == keep {
			continue
		}
		if strings.HasPrefix(n, ".tmp-") || strings.HasPrefix(n, ".old-") || componentDirRe.MatchString(n) {
			_ = os.RemoveAll(filepath.Join(base, n))
		}
	}
}

// openHeld opens the file for reading with NO write and NO delete sharing: while the handle is open nobody can change,
// replace or delete it.
func openHeld(p string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), p), nil
}

// prepareCore unpacks/verifies the components and returns the core's path and the handle that keeps it unchangeable.
func prepareCore(home string, p payloadSpec) (corePath string, hold *os.File, err error) {
	dir, err := ensureComponents(home, p)
	if err != nil {
		return "", nil, err
	}
	corePath = filepath.Join(dir, coreEntry)
	hold, err = openHeld(corePath)
	if err != nil {
		return "", nil, fmt.Errorf("cannot lock the core file: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, hold); err != nil || hex.EncodeToString(h.Sum(nil)) != p.wantCore {
		hold.Close()
		return "", nil, errors.New("the core file changed while it was being locked")
	}
	return corePath, hold, nil
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
