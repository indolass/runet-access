# Helper for tests that need a REAL system clipboard without touching the clipboard of the person at
# the computer. Windows keeps one clipboard per *window station*, so the test (node, RunetAccess.exe,
# Chrome, Set-Clipboard) runs on a private window station with its own desktop and its own clipboard.
# Nothing it shows is visible, nothing it copies reaches WinSta0. Dot-source it:
#   . .\tests\window-station.ps1; [WS]::Create('MyTest'); $pid = [WS]::Start('node tests\x.mjs')
# [WS]::OwnerClipboardSeq() returns the sequence number of the caller's (WinSta0) clipboard: it changes
# whenever that clipboard's content changes, and reading it does not read the content.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WS {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
    public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2;
    public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr CreateWindowStation(string name, int flags, uint access, IntPtr sa);
  [DllImport("user32.dll", SetLastError = true)] static extern IntPtr GetProcessWindowStation();
  [DllImport("user32.dll", SetLastError = true)] static extern bool SetProcessWindowStation(IntPtr h);
  [DllImport("user32.dll", SetLastError = true)] static extern bool CloseWindowStation(IntPtr h);
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr CreateDesktop(string name, IntPtr dev, IntPtr devmode, int flags, uint access, IntPtr sa);
  [DllImport("user32.dll", SetLastError = true)] static extern bool CloseDesktop(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool GetUserObjectInformation(IntPtr h, int index, System.Text.StringBuilder info, int len, out int needed);
  static string name; static IntPtr station, desk;
  public static string Name { get { return name; } }
  // A NAMED window station needs administrator rights (ERROR_ACCESS_DENIED otherwise); an unnamed one is
  // allowed for ordinary users and gets a system-generated name, which is read back for lpDesktop.
  public static void Create(string ignored) {
    station = CreateWindowStation(null, 0, 0x37F /* WINSTA_ALL_ACCESS */, IntPtr.Zero);
    if (station == IntPtr.Zero) throw new Exception("CreateWindowStation failed: " + Marshal.GetLastWin32Error());
    var sb = new System.Text.StringBuilder(256); int needed;
    if (!GetUserObjectInformation(station, 2 /* UOI_NAME */, sb, sb.Capacity * 2, out needed)) throw new Exception("GetUserObjectInformation failed: " + Marshal.GetLastWin32Error());
    name = sb.ToString();
    // CreateDesktop works on the process's current window station: switch, create, switch back.
    IntPtr old = GetProcessWindowStation();
    if (!SetProcessWindowStation(station)) throw new Exception("SetProcessWindowStation failed: " + Marshal.GetLastWin32Error());
    try {
      desk = CreateDesktop("Default", IntPtr.Zero, IntPtr.Zero, 0, 0x10000000 /* GENERIC_ALL */, IntPtr.Zero);
      if (desk == IntPtr.Zero) throw new Exception("CreateDesktop failed: " + Marshal.GetLastWin32Error());
    } finally { SetProcessWindowStation(old); }
  }
  // Starts a command line on the private window station/desktop; the environment of this process is inherited.
  public static int Start(string commandLine) {
    var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si); si.lpDesktop = name + "\\Default";
    PROCESS_INFORMATION pi;
    if (!CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi))
      throw new Exception("CreateProcess failed: " + Marshal.GetLastWin32Error());
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return pi.dwProcessId;
  }
  public static uint OwnerClipboardSeq() { return GetClipboardSequenceNumber(); }
  public static void Close() { if (desk != IntPtr.Zero) CloseDesktop(desk); if (station != IntPtr.Zero) CloseWindowStation(station); desk = IntPtr.Zero; station = IntPtr.Zero; }
}
'@
