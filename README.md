# MTA:SA Server Shield (x64)

A high-performance C++ module developed for 64-bit MTA:SA (Multi Theft Auto: San Andreas) servers (Windows & Linux). It provides kernel-level memory safety, packet filtering, and protection against known exploits, buffer overflows, and Lua VM panics.

---

## 🛡️ Protected Vulnerabilities

This module injects dynamic hooks, socket-level datagram filtering, and resilient SEH / VEH / POSIX signal handlers to protect the server from being crashed:

### 1. Cascade (BitStream Buffer Overflow & Oversized Datagrams)
- **Target:** `net.dll` / `net.so` (`BitStream::WriteBits`, `recvfrom`)
- **Threat:** Negative or excessively large bit count parameters causing integer overflows in `numberOfBitsToWrite`, or malformed oversized UDP datagrams causing `0xC0000005` (Access Violation), `0xC0000374` (Heap Corruption), or `SIGSEGV` on Linux.
- **Mitigation:** Socket-level filtering drops abnormal datagrams exceeding 4096 bytes; parameters are validated and normalized before execution, safely discarding exploit payloads.

### 2. Pulse Strike (Entity & Argument Deserializer Exploit)
- **Target:** `deathmatch.dll` / `deathmatch.so`
- **Threat:** Malicious or forged memory pointers (e.g. `0x414141414140`) sent via network RPCs/events, forcing read/write access violations during argument deserialization.
- **Mitigation:** Strict pointer validation, boundary verification for non-empty argument vectors, and scoped SEH (`__try / __except`) exception handling ensure invalid objects are trapped and discarded without interrupting normal gameplay or crashing the server.

### 3. Whisper (Lua nil / NaN Key Crash)
- **Target:** `lua5.1.dll` (`luaH_set`) and Lua Panic Handler
- **Threat:** Injecting `nil` or `NaN` (Not a Number) keys into Lua tables, triggering an unhandled `table index is nil / NaN` panic that forces the server console to terminate.
- **Mitigation:** Intercepts `luaH_set` to safely sink illegal/NaN keys into a dummy buffer, neutralizing panics and keeping the server alive.

---

## 📁 Repository Structure

```text
mta_server_shield/
├── bin/
│   └── x64/
│       ├── mta_server_shield.dll   # Windows x64 compiled module
│       └── mta_server_shield.so    # Linux x64 compiled module
├── src/
│   └── mta_server_shield.cpp       # Cross-platform C++ source code (Win + Linux)
├── .gitignore                      # Git ignore rules
├── build.bat                       # Windows MSVC x64 build script
├── build.sh                        # Linux GCC/Clang build script
├── Makefile                        # Linux makefile
└── README.md                       # Documentation
```

---

## 🚀 Installation

### 🪟 Windows Servers:
1. Copy `bin/x64/mta_server_shield.dll` to your server's `x64/modules/` (or `modules/`) folder.
2. Open `mtaserver.conf` and add the module entry inside `<config>`:
```xml
<module src="mta_server_shield.dll" />
```
3. Start your server.

### 🐧 Linux Servers (Ubuntu, Debian, CentOS):
1. Copy `bin/x64/mta_server_shield.so` to your server's `x64/modules/` (or `modules/`) folder.
2. Open `mtaserver.conf` and add:
```xml
<module src="mta_server_shield.so" />
```
3. Or alternatively, preload directly via socket layer:
```bash
LD_PRELOAD=./x64/modules/mta_server_shield.so ./mta-server64
```
4. Start your server. The console will display a green startup banner confirming active status:
```text
[MTGuard] ACTIVE & PROTECTION OPERATIONAL (LINUX)
```

---

## 🛠️ Building from Source

### Windows (MSVC x64):
1. Run `build.bat` from the root directory (or use `x64 Native Tools Command Prompt for VS`).
2. Output: `bin/x64/mta_server_shield.dll`

### Linux (GCC / Clang):
Compile directly on your server:
```bash
# Install dependencies (Ubuntu / Debian):
sudo apt update && sudo apt install -y build-essential

# Build:
make
# or
chmod +x build.sh && ./build.sh
```
Output: `bin/x64/mta_server_shield.so`

---

## 📜 License

This project is developed for educational and server security research purposes. Open-source and free to adapt.
