#!/usr/bin/env python3
"""E2E test of the REAL rsb_client.py against a mini protocol-v2 server.

Runs Client/rsb_client.py as a subprocess (its portable commands work on
Linux: framing, ls/pwd/cd/get/put/whoami/hostname/help/exit). The
Windows-only commands (ps/sysinfo/ipconfig/regq) use ctypes and are
covered by test/selftest_windows.bat on a real Windows box.
"""
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(HERE, "rsb_client.py")
PORT = 4451


def recv_all(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf


def send_framed(s, payload):
    s.sendall(struct.pack("<I", len(payload)))
    s.sendall(payload)


def recv_framed(s):
    n = struct.unpack("<I", recv_all(s, 4))[0]
    assert 0 < n <= 256 * 1024 * 1024
    return recv_all(s, n)


def main():
    # payloads
    big = os.urandom(64 * 1024)
    with open("/tmp/rsb_get_src.bin", "wb") as f:
        f.write(big)
    with open("/tmp/rsb_put_src.bin", "wb") as f:
        f.write(b"upload-payload-123")
    for p in ("/tmp/rsb_get_dst.bin", "/tmp/rsb_put_dst.bin"):
        try:
            os.remove(p)
        except OSError:
            pass

    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", PORT))
    ls.listen(1)

    proc = subprocess.Popen([sys.executable, CLIENT, "127.0.0.1", str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    c, _ = ls.accept()
    ls.close()

    # whoami
    send_framed(c, b"whoami")
    who = recv_framed(c)
    assert who.endswith(b"\n") and b"\\" in who, who
    # hostname
    send_framed(c, b"hostname")
    hn = recv_framed(c)
    assert hn == (socket.gethostname() + "\n").encode(), hn
    # pwd / ls / cd
    send_framed(c, b"pwd")
    pwd = recv_framed(c).decode().strip()
    assert os.path.isdir(pwd), pwd
    send_framed(c, b"ls")
    listing = recv_framed(c).decode()
    assert "rsb_client.py" in listing, "ls missing expected file"
    send_framed(c, b"cd /tmp")
    assert recv_framed(c) == b"OK\n"
    send_framed(c, b"pwd")
    assert recv_framed(c).decode().strip() == "/tmp"
    # get 64 KB
    send_framed(c, b"get /tmp/rsb_get_src.bin")
    payload = recv_framed(c)
    assert payload[0] == ord("1"), payload[:32]
    assert payload[1:] == big, "get payload mismatch"
    # get error path
    send_framed(c, b"get /tmp/does-not-exist.bin")
    payload = recv_framed(c)
    assert payload[0] == ord("0") and b"ERROR" in payload, payload
    # put
    send_framed(c, b"put /tmp/rsb_put_dst.bin")
    with open("/tmp/rsb_put_src.bin", "rb") as f:
        data = f.read()
    send_framed(c, b"1" + data)
    ack = recv_framed(c)
    assert b"written 18 bytes" in ack, ack
    with open("/tmp/rsb_put_dst.bin", "rb") as f:
        assert f.read() == data, "put payload mismatch"
    # help
    send_framed(c, b"help")
    assert b"regq" in recv_framed(c)
    # unknown
    send_framed(c, b"nonsense")
    assert b"unknown command" in recv_framed(c)
    # exit
    send_framed(c, b"exit")
    c.close()
    rc = proc.wait(timeout=10)
    assert rc == 0, f"client exited {rc}"

    print("[PASS] whoami/hostname/pwd/ls/cd")
    print("[PASS] get 64 KB exact bytes")
    print("[PASS] get error path")
    print("[PASS] put 17 bytes exact bytes + ack")
    print("[PASS] help + unknown command")
    print("[PASS] exit handshake, client rc=0")
    print("\nReal rsb_client.py verified E2E (portable commands).")


if __name__ == "__main__":
    sys.exit(main())
