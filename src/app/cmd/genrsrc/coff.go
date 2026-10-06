package main

import "encoding/binary"

// build returns a COFF object (amd64) with one ".rsrc" section containing a resource tree:
// RT_MANIFEST (24) -> id 1 -> language 0x0409 -> data. The data entry's address is fixed up
// by the linker through one IMAGE_REL_AMD64_ADDR32NB relocation.
func build(manifest []byte) []byte {
	le := binary.LittleEndian
	const (
		hdrSize   = 20
		secSize   = 40
		dirSize   = 16
		entrySize = 8
		dataEntry = 16
	)
	// resource section layout
	off0 := 0                          // type directory
	off1 := off0 + dirSize + entrySize // name directory
	off2 := off1 + dirSize + entrySize // language directory
	offE := off2 + dirSize + entrySize // data entry
	offD := offE + dataEntry           // raw data
	pad := (4 - len(manifest)%4) % 4
	rsrcLen := offD + len(manifest) + pad

	sec := make([]byte, rsrcLen)
	dir := func(at int) { le.PutUint16(sec[at+14:], 1) } // NumberOfIdEntries = 1
	dir(off0)
	le.PutUint32(sec[off0+16:], 24)                      // RT_MANIFEST
	le.PutUint32(sec[off0+20:], 0x80000000|uint32(off1)) // subdirectory
	dir(off1)
	le.PutUint32(sec[off1+16:], 1) // resource id 1
	le.PutUint32(sec[off1+20:], 0x80000000|uint32(off2))
	dir(off2)
	le.PutUint32(sec[off2+16:], 0x0409) // en-US
	le.PutUint32(sec[off2+20:], uint32(offE))
	le.PutUint32(sec[offE:], uint32(offD)) // OffsetToData: section-relative, + RVA via relocation
	le.PutUint32(sec[offE+4:], uint32(len(manifest)))
	copy(sec[offD:], manifest)

	ptrData := hdrSize + secSize
	ptrReloc := ptrData + rsrcLen
	ptrSym := ptrReloc + 10

	out := make([]byte, 0, ptrSym+18+4)
	h := make([]byte, hdrSize)
	le.PutUint16(h[0:], 0x8664) // IMAGE_FILE_MACHINE_AMD64
	le.PutUint16(h[2:], 1)      // sections
	le.PutUint32(h[8:], uint32(ptrSym))
	le.PutUint32(h[12:], 1) // symbols
	out = append(out, h...)

	s := make([]byte, secSize)
	copy(s[0:], ".rsrc")
	le.PutUint32(s[16:], uint32(rsrcLen))
	le.PutUint32(s[20:], uint32(ptrData))
	le.PutUint32(s[24:], uint32(ptrReloc))
	le.PutUint16(s[32:], 1)          // relocations
	le.PutUint32(s[36:], 0xC0000040) // initialized data, readable, writable
	out = append(out, s...)
	out = append(out, sec...)

	r := make([]byte, 10)
	le.PutUint32(r[0:], uint32(offE))
	le.PutUint32(r[4:], 0) // symbol 0
	le.PutUint16(r[8:], 3) // IMAGE_REL_AMD64_ADDR32NB
	out = append(out, r...)

	sym := make([]byte, 18)
	copy(sym[0:], ".rsrc")
	le.PutUint16(sym[12:], 1) // section number
	sym[16] = 3               // IMAGE_SYM_CLASS_STATIC
	out = append(out, sym...)
	out = append(out, 4, 0, 0, 0) // empty string table
	return out
}
