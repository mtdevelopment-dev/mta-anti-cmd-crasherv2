// c:/Users/Faxror/Downloads/mta_cmd_logger/mta_server_shield.cpp
// language: C++ (C++17)
// runtime: Windows x64 DLL for Multi Theft Auto Server x64
// bitness: 64-bit (x64)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <share.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <cmath>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

// ============================================================================
// CONSTANTS & LOGGING (NO BANS, NO FIREWALL BLOCKS)
// ============================================================================
static char SHIELD_LOG[MAX_PATH] = "mta_packet_audit.log";
static char CRASH_PACKET_LOG[MAX_PATH] = "mta_crash_packet.log";
static const int kMaxSaneDatagram = 4096;

static void InitLogPaths(HMODULE self)
{
    char dir[MAX_PATH] = {0};
    DWORD n = GetModuleFileNameA(self, dir, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    char* slash = std::strrchr(dir, '\\');
    if (!slash) return;
    *(slash + 1) = 0;
    std::snprintf(SHIELD_LOG, MAX_PATH, "%smta_packet_audit.log", dir);
    std::snprintf(CRASH_PACKET_LOG, MAX_PATH, "%smta_crash_packet.log", dir);
}

void PrintToMtaConsole(const char* text, WORD color = FOREGROUND_GREEN | FOREGROUND_INTENSITY)
{
    HANDLE hOut = CreateFileA("CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hOut == INVALID_HANDLE_VALUE)
    {
        hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    }

    if (hOut != INVALID_HANDLE_VALUE && hOut != nullptr)
    {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        WORD orig = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        if (GetConsoleScreenBufferInfo(hOut, &csbi)) orig = csbi.wAttributes;

        SetConsoleTextAttribute(hOut, color);
        DWORD written = 0;
        WriteConsoleA(hOut, text, (DWORD)std::strlen(text), &written, nullptr);
        SetConsoleTextAttribute(hOut, orig);

        if (hOut != GetStdHandle(STD_OUTPUT_HANDLE))
        {
            CloseHandle(hOut);
        }
    }
}

void LogAndPrint(const char* tag, WORD color, const char* format, ...)
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    char timeBuf[64];
    std::snprintf(timeBuf, sizeof(timeBuf), "[%04d-%02d-%02d %02d:%02d:%02d.%03d]",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    char msgBuf[4096];
    va_list args;
    va_start(args, format);
    std::vsnprintf(msgBuf, sizeof(msgBuf), format, args);
    va_end(args);

    char consoleLine[4200];
    std::snprintf(consoleLine, sizeof(consoleLine), "%s [%s] %s\n", timeBuf, tag, msgBuf);
    PrintToMtaConsole(consoleLine, color);

    FILE* fp = _fsopen(SHIELD_LOG, "a+", _SH_DENYNO);
    if (fp)
    {
        std::fprintf(fp, "%s [%s] %s\n", timeBuf, tag, msgBuf);
        std::fclose(fp);
    }
}

static bool Readable(const void* p, size_t n)
{
    if (!p || n == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || prot == PAGE_GUARD || prot == PAGE_EXECUTE) return false;
    uintptr_t start = (uintptr_t)p;
    uintptr_t end = start + n;
    uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return end <= regionEnd;
}

// ============================================================================
// 1. BITSTREAM WRITEBITS BUFFER OVERFLOW PROTECTION (CASCADE FIX)
// ============================================================================
static std::atomic<bool> g_WriteBitsHooked(false);
static volatile uint32_t* g_pBlockedCounter = nullptr;

static void InstallWriteBitsHook()
{
    if (g_WriteBitsHooked.load()) return;

    HMODULE hNet = GetModuleHandleA("net.dll");
    if (!hNet) return;

    uint8_t* target = (uint8_t*)hNet + 0x3A6B0;

    static const uint8_t kExpectedPrefix[9] = { 0x45, 0x85, 0xC0, 0x0F, 0x84, 0xDA, 0x00, 0x00, 0x00 };
    if (std::memcmp(target, kExpectedPrefix, sizeof(kExpectedPrefix)) != 0)
    {
        return;
    }

    uint8_t* stub = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub) return;

    uint8_t* continueAddr = target + 19;

    uint8_t stubCode[48] = {
        0x41, 0x81, 0xF8, 0x00, 0x00, 0x10, 0x00, // 0..6:   cmp r8d, 0x100000
        0x77, 0x1D,                               // 7..8:   ja drop
        0x45, 0x85, 0xC0,                         // 9..11:  test r8d, r8d
        0x74, 0x18,                               // 12..13: je drop
        0x48, 0x89, 0x5C, 0x24, 0x10,             // 14..18: mov [rsp+10h], rbx
        0x48, 0x89, 0x6C, 0x24, 0x18,             // 19..23: mov [rsp+18h], rbp
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,       // 24..29: jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 30..37: continueAddr
        0xFF, 0x05, 0x04, 0x00, 0x00, 0x00,       // 38..43: inc dword ptr [rip+4]
        0xC3                                      // 44:     ret
    };

    std::memcpy(&stubCode[30], &continueAddr, sizeof(void*));
    std::memcpy(stub, stubCode, 45);
    *(uint32_t*)(stub + 48) = 0;
    g_pBlockedCounter = (volatile uint32_t*)(stub + 48);

    uint8_t patch[19];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    std::memcpy(&patch[6], &stub, sizeof(void*));
    patch[14] = 0x90;
    patch[15] = 0x90;
    patch[16] = 0x90;
    patch[17] = 0x90;
    patch[18] = 0x90;

    DWORD oldProtect = 0;
    if (VirtualProtect(target, 19, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::memcpy(target, patch, 19);
        VirtualProtect(target, 19, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), target, 19);
        g_WriteBitsHooked.store(true);
        LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    "Cascade exploit korumasi aktif edildi (net.dll + 0x3A6B0).");
    }
}

// ============================================================================
// 2. PULSE STRIKE EXPLOIT PROTECTION 1 (deathmatch.dll + 0x1A4110)
// ============================================================================
typedef bool (*tFunc1A4110)(void* rcx, void* rdx, void* r8);
static tFunc1A4110 g_OrigFunc1A4110 = nullptr;
static std::atomic<bool> g_PulseStrikeHooked(false);

bool Hooked_Func1A4110(void* rcx, void* rdx, void* r8)
{
    if (!rcx || !Readable(rcx, 16))
    {
        return false;
    }

    void* beginPtr = *(void**)rcx;
    void* endPtr = *((void**)rcx + 1);

    if (!beginPtr || !Readable(beginPtr, 8) || beginPtr > endPtr)
    {
        return false;
    }

    return g_OrigFunc1A4110(rcx, rdx, r8);
}

static void InstallPulseStrikeHook()
{
    if (g_PulseStrikeHooked.load()) return;

    HMODULE hDm = GetModuleHandleA("deathmatch.dll");
    if (!hDm) return;

    uint8_t* target = (uint8_t*)hDm + 0x1A4110;

    static const uint8_t kExpectedPrefix[15] = {
        0x48, 0x89, 0x5C, 0x24, 0x10,
        0x48, 0x89, 0x6C, 0x24, 0x18,
        0x48, 0x89, 0x74, 0x24, 0x20
    };
    if (std::memcmp(target, kExpectedPrefix, sizeof(kExpectedPrefix)) != 0)
    {
        return;
    }

    uint8_t* trampoline = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return;

    std::memcpy(trampoline, target, 15);
    trampoline[15] = 0xFF;
    trampoline[16] = 0x25;
    trampoline[17] = 0x00;
    trampoline[18] = 0x00;
    trampoline[19] = 0x00;
    trampoline[20] = 0x00;
    uint8_t* contAddr = target + 15;
    std::memcpy(&trampoline[21], &contAddr, sizeof(void*));

    g_OrigFunc1A4110 = (tFunc1A4110)trampoline;

    uint8_t patch[15];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    void* hookPtr = (void*)Hooked_Func1A4110;
    std::memcpy(&patch[6], &hookPtr, sizeof(void*));
    patch[14] = 0x90;

    DWORD oldProtect = 0;
    if (VirtualProtect(target, 15, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::memcpy(target, patch, 15);
        VirtualProtect(target, 15, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), target, 15);
        g_PulseStrikeHooked.store(true);
        LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    "Pulse Strike korumasi #1 aktif edildi (deathmatch.dll + 0x1A4110).");
    }
}

// ============================================================================
// 3. PULSE STRIKE EXPLOIT PROTECTION 2 (deathmatch.dll + 0x1A25B0)
// Prevents crash at 0x1A2627 / 0x1A2647 when entity vector in rdx is invalid.
// ============================================================================
typedef void (*tFunc1A25B0)(void* rcx, void* rdx, void* r8);
static tFunc1A25B0 g_OrigFunc1A25B0 = nullptr;
static std::atomic<bool> g_Func1A25B0Hooked(false);

void Hooked_Func1A25B0(void* rcx, void* rdx, void* r8)
{
    if (!rdx || !Readable(rdx, 16))
    {
        return;
    }
    void* beginPtr = *(void**)rdx;
    void* endPtr = *((void**)rdx + 1);
    if (!beginPtr || !Readable(beginPtr, 8) || beginPtr > endPtr)
    {
        return;
    }
    g_OrigFunc1A25B0(rcx, rdx, r8);
}

static void InstallFunc1A25B0Hook()
{
    if (g_Func1A25B0Hooked.load()) return;

    HMODULE hDm = GetModuleHandleA("deathmatch.dll");
    if (!hDm) return;

    uint8_t* target = (uint8_t*)hDm + 0x1A25B0;

    static const uint8_t kExpectedPrefix[14] = {
        0x48, 0x89, 0x5C, 0x24, 0x18,
        0x48, 0x89, 0x6C, 0x24, 0x20,
        0x56, 0x57, 0x41, 0x56
    };
    if (std::memcmp(target, kExpectedPrefix, sizeof(kExpectedPrefix)) != 0)
    {
        return;
    }

    uint8_t* trampoline = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return;

    std::memcpy(trampoline, target, 14);
    trampoline[14] = 0xFF;
    trampoline[15] = 0x25;
    trampoline[16] = 0x00;
    trampoline[17] = 0x00;
    trampoline[18] = 0x00;
    trampoline[19] = 0x00;
    uint8_t* contAddr = target + 14;
    std::memcpy(&trampoline[20], &contAddr, sizeof(void*));

    g_OrigFunc1A25B0 = (tFunc1A25B0)trampoline;

    uint8_t patch[14];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    void* hookPtr = (void*)Hooked_Func1A25B0;
    std::memcpy(&patch[6], &hookPtr, sizeof(void*));

    DWORD oldProtect = 0;
    if (VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::memcpy(target, patch, 14);
        VirtualProtect(target, 14, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), target, 14);
        g_Func1A25B0Hooked.store(true);
        LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    "Pulse Strike korumasi #2 aktif edildi (deathmatch.dll + 0x1A25B0).");
    }
}

// ============================================================================
// 4. CLUAARGUMENT READ ACCESS SHIELD (deathmatch.dll + 0x19F7D0)
// Prevents AV crash at 0x19F80B when other argument pointer is invalid.
// ============================================================================
typedef void* (*tFunc19F7D0)(void* rcx, void* rdx, void* r8);
static tFunc19F7D0 g_OrigFunc19F7D0 = nullptr;
static std::atomic<bool> g_Func19F7D0Hooked(false);

void* Hooked_Func19F7D0(void* rcx, void* rdx, void* r8)
{
    if (!rdx || !Readable(rdx, 8))
    {
        if (rcx && Readable(rcx, 16))
        {
            *(int*)rcx = 0; // Set to safe LUA_TNIL
        }
        return rcx;
    }
    return g_OrigFunc19F7D0(rcx, rdx, r8);
}

static void InstallFunc19F7D0Hook()
{
    if (g_Func19F7D0Hooked.load()) return;

    HMODULE hDm = GetModuleHandleA("deathmatch.dll");
    if (!hDm) return;

    uint8_t* target = (uint8_t*)hDm + 0x19F7D0;

    static const uint8_t kExpectedPrefix[15] = {
        0x48, 0x89, 0x5C, 0x24, 0x10,
        0x48, 0x89, 0x6C, 0x24, 0x18,
        0x48, 0x89, 0x74, 0x24, 0x20
    };
    if (std::memcmp(target, kExpectedPrefix, sizeof(kExpectedPrefix)) != 0)
    {
        return;
    }

    uint8_t* trampoline = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return;

    std::memcpy(trampoline, target, 15);
    trampoline[15] = 0xFF;
    trampoline[16] = 0x25;
    trampoline[17] = 0x00;
    trampoline[18] = 0x00;
    trampoline[19] = 0x00;
    trampoline[20] = 0x00;
    uint8_t* contAddr = target + 15;
    std::memcpy(&trampoline[21], &contAddr, sizeof(void*));

    g_OrigFunc19F7D0 = (tFunc19F7D0)trampoline;

    uint8_t patch[15];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    void* hookPtr = (void*)Hooked_Func19F7D0;
    std::memcpy(&patch[6], &hookPtr, sizeof(void*));
    patch[14] = 0x90;

    DWORD oldProtect = 0;
    if (VirtualProtect(target, 15, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::memcpy(target, patch, 15);
        VirtualProtect(target, 15, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), target, 15);
        g_Func19F7D0Hooked.store(true);
        LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    "CLuaArgument korumasi aktif edildi (deathmatch.dll + 0x19F7D0).");
    }
}

// ============================================================================
// 5. LUA TABLE NIL INDEX SINK & PANIC PREVENTER (lua5.1.dll)
// Prevents "PANIC: unprotected error in call to Lua API (table index is nil)"
// by safely redirecting nil-key writes to a dummy sink and disabling exit(1).
// ============================================================================
typedef void* (*tLuaH_Set)(void* L, void* t, void* key);
static tLuaH_Set g_OrigLuaH_Set = nullptr;
static std::atomic<bool> g_LuaHSetHooked(false);
static uint8_t s_DummySinkTValue[32] = {0};

void* Hooked_LuaH_Set(void* L, void* t, void* key)
{
    if (!key) return s_DummySinkTValue;

    int tt = *(int*)((uint8_t*)key + 8);
    // 1. Table index is nil
    if (tt == 0 /* LUA_TNIL */)
    {
        return s_DummySinkTValue;
    }
    // 2. Table index is NaN or Inf (Whisper exploit)
    if (tt == 3 /* LUA_TNUMBER */)
    {
        double d = *(double*)key;
        if (d != d || std::isnan(d) || std::isinf(d))
        {
            LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                        "Whisper exploit engellendi: 'table index is NaN' (Sunucu & CMD aktif)");
            return s_DummySinkTValue;
        }
    }
    return g_OrigLuaH_Set(L, t, key);
}

static void InstallLuaProtection()
{
    if (g_LuaHSetHooked.load()) return;

    HMODULE hLua = GetModuleHandleA("lua5.1.dll");
    if (!hLua) return;

    // A. Hook luaH_set (0x179C0)
    uint8_t* target = (uint8_t*)hLua + 0x179C0;
    static const uint8_t kExpectedPrefix[15] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18
    };

    if (std::memcmp(target, kExpectedPrefix, sizeof(kExpectedPrefix)) == 0)
    {
        uint8_t* trampoline = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (trampoline)
        {
            std::memcpy(trampoline, target, 15);
            trampoline[15] = 0xFF;
            trampoline[16] = 0x25;
            trampoline[17] = 0x00;
            trampoline[18] = 0x00;
            trampoline[19] = 0x00;
            trampoline[20] = 0x00;
            uint8_t* contAddr = target + 15;
            std::memcpy(&trampoline[21], &contAddr, sizeof(void*));

            g_OrigLuaH_Set = (tLuaH_Set)trampoline;

            uint8_t patch[15];
            patch[0] = 0xFF;
            patch[1] = 0x25;
            patch[2] = 0x00;
            patch[3] = 0x00;
            patch[4] = 0x00;
            patch[5] = 0x00;
            void* hookPtr = (void*)Hooked_LuaH_Set;
            std::memcpy(&patch[6], &hookPtr, sizeof(void*));
            patch[14] = 0x90;

            DWORD oldProtect = 0;
            if (VirtualProtect(target, 15, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                std::memcpy(target, patch, 15);
                VirtualProtect(target, 15, oldProtect, &oldProtect);
                FlushInstructionCache(GetCurrentProcess(), target, 15);
                g_LuaHSetHooked.store(true);
                LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                            "Lua table nil korumasi aktif edildi (lua5.1.dll + 0x179C0).");
            }
        }
    }

    // B. Neutralize exit(1) in luaD_throw panic handler (0xB704)
    uint8_t* pPanicExit = (uint8_t*)hLua + 0xB704;
    if (pPanicExit[0] == 0xB9 && pPanicExit[1] == 0x01 && pPanicExit[5] == 0xE8)
    {
        DWORD oldProt = 0;
        if (VirtualProtect(pPanicExit, 10, PAGE_EXECUTE_READWRITE, &oldProt))
        {
            pPanicExit[0] = 0xC3; // ret
            for (int i = 1; i < 10; ++i) pPanicExit[i] = 0x90; // nop
            VirtualProtect(pPanicExit, 10, oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), pPanicExit, 10);
            LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                        "Lua panic sonlandiricisi guvenli hale getirildi (lua5.1.dll + 0xB704).");
        }
    }
}

// ============================================================================
// CRASH AUDIT & RECOVERY (VEH)
// ============================================================================
static thread_local int t_InFilter = 0;

static void ModOf(DWORD64 addr, char* out, size_t outn, DWORD64& rva)
{
    HMODULE owner = nullptr;
    char name[MAX_PATH] = "?";
    rva = addr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &owner) && owner)
    {
        GetModuleFileNameA(owner, name, MAX_PATH);
        rva = addr - (DWORD64)owner;
    }
    const char* slash = std::strrchr(name, '\\');
    std::snprintf(out, outn, "%s", slash ? slash + 1 : name);
}

static void NoteCrash(PEXCEPTION_POINTERS info)
{
    FILE* fp = _fsopen(SHIELD_LOG, "a+", _SH_DENYNO);
    if (!fp) return;
    PCONTEXT ctx = info->ContextRecord;
    PEXCEPTION_RECORD rec = info->ExceptionRecord;
    char mod[64];
    DWORD64 rva = 0;
    ModOf(ctx->Rip, mod, sizeof(mod), rva);
    std::fprintf(fp, "CRASH code=0x%08lX rip=0x%llX mod=%s rva=0x%llX\n",
                 (unsigned long)rec->ExceptionCode,
                 (unsigned long long)ctx->Rip, mod, (unsigned long long)rva);
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2)
    {
        std::fprintf(fp, "  av op=%s addr=0x%llX\n",
                     rec->ExceptionInformation[0] ? "write" : "read",
                     (unsigned long long)rec->ExceptionInformation[1]);
    }
    std::fprintf(fp,
                 "  rax=%llX rbx=%llX rcx=%llX rdx=%llX rsi=%llX rdi=%llX rbp=%llX rsp=%llX r8=%llX r9=%llX\n",
                 (unsigned long long)ctx->Rax, (unsigned long long)ctx->Rbx,
                 (unsigned long long)ctx->Rcx, (unsigned long long)ctx->Rdx,
                 (unsigned long long)ctx->Rsi, (unsigned long long)ctx->Rdi,
                 (unsigned long long)ctx->Rbp, (unsigned long long)ctx->Rsp,
                 (unsigned long long)ctx->R8, (unsigned long long)ctx->R9);
    if (Readable((void*)ctx->Rsp, 8 * 6))
    {
        auto* s = (DWORD64*)ctx->Rsp;
        std::fprintf(fp, "  stack");
        for (int i = 0; i < 6; ++i)
        {
            char sm[64];
            DWORD64 sr = 0;
            ModOf(s[i], sm, sizeof(sm), sr);
            std::fprintf(fp, " [%d]=%llX %s+%llX", i, (unsigned long long)s[i], sm, (unsigned long long)sr);
        }
        std::fprintf(fp, "\n");
    }
    std::fclose(fp);
}

LONG WINAPI CrashFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (!pExceptionInfo || !pExceptionInfo->ExceptionRecord || !pExceptionInfo->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    if (t_InFilter)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != 0xC0000374)
        return EXCEPTION_CONTINUE_SEARCH;

    t_InFilter = 1;

    NoteCrash(pExceptionInfo);

    PCONTEXT ctx = pExceptionInfo->ContextRecord;

    // 1. Check net.dll exceptions
    HMODULE hNet = GetModuleHandleA("net.dll");
    if (hNet)
    {
        DWORD64 base = (DWORD64)hNet;
        DWORD64 rip = ctx->Rip;

        if (!g_WriteBitsHooked.load())
        {
            InstallWriteBitsHook();
        }

        if (code == EXCEPTION_ACCESS_VIOLATION && rip >= base + 0x7A740 && rip <= base + 0x7A950)
        {
            ctx->Rax = ctx->Rdx;
            ctx->Rip = base + 0x7A840;
            t_InFilter = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (code == EXCEPTION_ACCESS_VIOLATION && rip >= base + 0x3A6B0 && rip <= base + 0x3A795)
        {
            if (Readable((void*)(ctx->Rsp + 0x48), 8))
            {
                ctx->Rsi = *(DWORD64*)(ctx->Rsp + 0x30);
                ctx->Rbx = *(DWORD64*)(ctx->Rsp + 0x38);
                ctx->Rbp = *(DWORD64*)(ctx->Rsp + 0x40);
                ctx->Rdi = *(DWORD64*)(ctx->Rsp + 0x48);
                ctx->R14 = *(DWORD64*)(ctx->Rsp + 0x20);
                ctx->Rsp += 0x28;
            }
            ctx->Rip = base + 0x3A793;
            t_InFilter = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // 2. Check deathmatch.dll exceptions
    HMODULE hDm = GetModuleHandleA("deathmatch.dll");
    if (hDm && code == EXCEPTION_ACCESS_VIOLATION)
    {
        DWORD64 dmBase = (DWORD64)hDm;
        DWORD64 rip = ctx->Rip;

        if (!g_PulseStrikeHooked.load())
        {
            InstallPulseStrikeHook();
        }
        if (!g_Func1A25B0Hooked.load())
        {
            InstallFunc1A25B0Hook();
        }
        if (!g_Func19F7D0Hooked.load())
        {
            InstallFunc19F7D0Hook();
        }

        // Pulse Strike function #1 (0x1A4110 .. 0x1A4223)
        if (rip >= dmBase + 0x1A4110 && rip <= dmBase + 0x1A4223)
        {
            DWORD64 r11 = ctx->Rsp + 0x50;
            if (Readable((void*)r11, 0x40))
            {
                ctx->R15 = *(DWORD64*)(r11);
                ctx->R14 = *(DWORD64*)(r11 + 0x8);
                ctx->Rdi = *(DWORD64*)(r11 + 0x10);
                DWORD64 retAddr = *(DWORD64*)(r11 + 0x18);
                ctx->Rbx = *(DWORD64*)(r11 + 0x28);
                ctx->Rbp = *(DWORD64*)(r11 + 0x30);
                ctx->Rsi = *(DWORD64*)(r11 + 0x38);
                ctx->Rsp = r11 + 0x20;
                ctx->Rip = retAddr;
                ctx->Rax = 0;
                t_InFilter = 0;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // Pulse Strike function #2 (0x1A25B0 .. 0x1A26C0)
        if (rip >= dmBase + 0x1A25B0 && rip <= dmBase + 0x1A26C0)
        {
            DWORD64 r11 = ctx->Rsp + 0x50;
            if (Readable((void*)r11, 0x40))
            {
                ctx->R14 = *(DWORD64*)(r11);
                ctx->Rdi = *(DWORD64*)(r11 + 0x8);
                ctx->Rsi = *(DWORD64*)(r11 + 0x10);
                DWORD64 retAddr = *(DWORD64*)(r11 + 0x18);
                ctx->Rbx = *(DWORD64*)(r11 + 0x30);
                ctx->Rbp = *(DWORD64*)(r11 + 0x38);
                ctx->Rsp = r11 + 0x20;
                ctx->Rip = retAddr;
                ctx->Rax = 0;
                t_InFilter = 0;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // CLuaArgument function (0x19F7D0 .. 0x19F910)
        if (rip >= dmBase + 0x19F7D0 && rip <= dmBase + 0x19F910)
        {
            if (Readable((void*)(ctx->Rsp + 0x30), 8))
            {
                ctx->Rdi = *(DWORD64*)(ctx->Rsp + 0x30);
                ctx->Rbx = *(DWORD64*)(ctx->Rsp + 0x48);
                ctx->Rbp = *(DWORD64*)(ctx->Rsp + 0x50);
                ctx->Rsi = *(DWORD64*)(ctx->Rsp + 0x58);
                DWORD64 retAddr = *(DWORD64*)(ctx->Rsp + 0x38);
                ctx->Rsp += 0x40;
                ctx->Rip = retAddr;
                ctx->Rax = ctx->Rcx;
                t_InFilter = 0;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // General deathmatch.dll access violation unwind
        DWORD64 imageBase = 0;
        PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(rip, &imageBase, nullptr);
        if (entry && imageBase == dmBase)
        {
            PVOID handlerData = nullptr;
            ULONG_PTR establisher = 0;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, rip, entry, ctx, &handlerData, &establisher, nullptr);
            ctx->Rax = 0;
            t_InFilter = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    t_InFilter = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================================
// WINSOCK HOOKS (recvfrom & WSARecvFrom) - PACKET SIZE FILTER ONLY, ZERO BANS
// ============================================================================
typedef int(WSAAPI* tRecvFrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
typedef int(WSAAPI* tWSARecvFrom)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static tRecvFrom g_OrigRecvFrom = nullptr;
static tWSARecvFrom g_OrigWSARecvFrom = nullptr;

int WSAAPI Detour_RecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    for (int attempts = 0; attempts < 8; ++attempts)
    {
        int bytes = g_OrigRecvFrom(s, buf, len, flags, from, fromlen);
        if (bytes <= 0 || buf == nullptr) return bytes;

        if (bytes > kMaxSaneDatagram)
        {
            continue;
        }

        return bytes;
    }

    WSASetLastError(WSAEWOULDBLOCK);
    return SOCKET_ERROR;
}

int WSAAPI Detour_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (lpOverlapped != nullptr || lpCompletionRoutine != nullptr)
    {
        return g_OrigWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    }

    for (int attempts = 0; attempts < 8; ++attempts)
    {
        int res = g_OrigWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
        if (res != 0) return res;

        if (!lpBuffers || dwBufferCount == 0 || !lpNumberOfBytesRecvd || *lpNumberOfBytesRecvd == 0)
        {
            return res;
        }

        int bytes = (int)*lpNumberOfBytesRecvd;
        if (bytes > kMaxSaneDatagram)
        {
            continue;
        }

        return res;
    }

    if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = 0;
    WSASetLastError(WSAEWOULDBLOCK);
    return SOCKET_ERROR;
}

// ============================================================================
// IAT HOOK ENGINE
// ============================================================================
bool HookIAT(HMODULE hModule, const char* targetDll, const char* funcName, void* detour, void** original)
{
    if (!hModule) return false;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((uint8_t*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_DATA_DIRECTORY importDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDataDir.Size == 0 || importDataDir.VirtualAddress == 0) return false;

    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)hModule + importDataDir.VirtualAddress);

    while (importDesc->Name != 0)
    {
        const char* dllName = (const char*)((uint8_t*)hModule + importDesc->Name);
        if (_stricmp(dllName, targetDll) == 0)
        {
            IMAGE_THUNK_DATA* origFirstThunk = (IMAGE_THUNK_DATA*)((uint8_t*)hModule + importDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)((uint8_t*)hModule + importDesc->FirstThunk);

            while (origFirstThunk->u1.AddressOfData != 0)
            {
                bool match = false;
                if (!(origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                {
                    IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)hModule + origFirstThunk->u1.AddressOfData);
                    if (std::strcmp((char*)importByName->Name, funcName) == 0)
                    {
                        match = true;
                    }
                }
                else
                {
                    WORD ord = (WORD)(origFirstThunk->u1.Ordinal & 0xFFFF);
                    if (ord == 17 && std::strcmp(funcName, "recvfrom") == 0) match = true;
                    if (ord == 93 && std::strcmp(funcName, "WSARecvFrom") == 0) match = true;
                }

                if (match)
                {
                    DWORD oldProtect = 0;
                    VirtualProtect(&firstThunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    if (original && *original == nullptr)
                    {
                        *original = (void*)firstThunk->u1.Function;
                    }
                    firstThunk->u1.Function = (uintptr_t)detour;
                    VirtualProtect(&firstThunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                    return true;
                }

                origFirstThunk++;
                firstThunk++;
            }
        }
        importDesc++;
    }

    return false;
}

void HookAllProcessModules()
{
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("ws2_32.dll");
    if (hWs2)
    {
        if (!g_OrigRecvFrom) g_OrigRecvFrom = (tRecvFrom)GetProcAddress(hWs2, "recvfrom");
        if (!g_OrigWSARecvFrom) g_OrigWSARecvFrom = (tWSARecvFrom)GetProcAddress(hWs2, "WSARecvFrom");
    }

    HMODULE hMain = GetModuleHandleA(nullptr);
    HMODULE hNet = GetModuleHandleA("net.dll");
    HMODULE hCore = GetModuleHandleA("core.dll");
    HMODULE hDm = GetModuleHandleA("deathmatch.dll");

    if (hMain)
    {
        HookIAT(hMain, "ws2_32.dll", "recvfrom", (void*)Detour_RecvFrom, (void**)&g_OrigRecvFrom);
        HookIAT(hMain, "ws2_32.dll", "WSARecvFrom", (void*)Detour_WSARecvFrom, (void**)&g_OrigWSARecvFrom);
    }
    if (hNet)
    {
        HookIAT(hNet, "ws2_32.dll", "recvfrom", (void*)Detour_RecvFrom, (void**)&g_OrigRecvFrom);
        HookIAT(hNet, "ws2_32.dll", "WSARecvFrom", (void*)Detour_WSARecvFrom, (void**)&g_OrigWSARecvFrom);
    }
    if (hCore)
    {
        HookIAT(hCore, "ws2_32.dll", "recvfrom", (void*)Detour_RecvFrom, (void**)&g_OrigRecvFrom);
        HookIAT(hCore, "ws2_32.dll", "WSARecvFrom", (void*)Detour_WSARecvFrom, (void**)&g_OrigWSARecvFrom);
    }
    if (hDm)
    {
        HookIAT(hDm, "ws2_32.dll", "recvfrom", (void*)Detour_RecvFrom, (void**)&g_OrigRecvFrom);
        HookIAT(hDm, "ws2_32.dll", "WSARecvFrom", (void*)Detour_WSARecvFrom, (void**)&g_OrigWSARecvFrom);
    }

    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[512];
    DWORD cbNeeded = 0;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        int count = cbNeeded / sizeof(HMODULE);
        for (int i = 0; i < count; ++i)
        {
            if (hMods[i] == nullptr || hMods[i] == hWs2) continue;
            HookIAT(hMods[i], "ws2_32.dll", "recvfrom", (void*)Detour_RecvFrom, (void**)&g_OrigRecvFrom);
            HookIAT(hMods[i], "ws2_32.dll", "WSARecvFrom", (void*)Detour_WSARecvFrom, (void**)&g_OrigWSARecvFrom);
        }
    }
}

// ============================================================================
// INITIALIZATION THREAD
// ============================================================================
DWORD WINAPI ShieldInitThread(LPVOID)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn != INVALID_HANDLE_VALUE && hIn != nullptr)
    {
        DWORD mode = 0;
        if (GetConsoleMode(hIn, &mode))
        {
            mode &= ~ENABLE_QUICK_EDIT_MODE;
            SetConsoleMode(hIn, mode | ENABLE_EXTENDED_FLAGS);
        }
    }

    AddVectoredExceptionHandler(1, CrashFilter);

    WinExec("netsh advfirewall firewall delete rule name=\"MTGuard_Block_188.119.61.4\"", SW_HIDE);
    WinExec("netsh advfirewall firewall delete rule name=\"MTGuard_Block_46.2.3.89\"", SW_HIDE);
    WinExec("netsh advfirewall firewall delete rule name=\"MTGuard_Block_51.158.206.103\"", SW_HIDE);
    WinExec("netsh advfirewall firewall delete rule name=\"MTGuard_Block_130.49.11.53\"", SW_HIDE);
    WinExec("netsh advfirewall firewall delete rule name=\"MTGuard_Block_130.49.11.233\"", SW_HIDE);
    WinExec("netsh advfirewall firewall delete rule name=\"MTGuard_Block_130.49.11.190\"", SW_HIDE);
    WinExec("netsh advfirewall firewall delete rule name=\"MTGuard_Block_130.49.11.181\"", SW_HIDE);
    WinExec("netsh advfirewall firewall delete rule name=\"MTGuard_Block_130.49.11.237\"", SW_HIDE);

    for (int retry = 0; retry < 60; ++retry)
    {
        HookAllProcessModules();
        if (GetModuleHandleA("net.dll") != nullptr)
        {
            InstallWriteBitsHook();
        }
        if (GetModuleHandleA("deathmatch.dll") != nullptr)
        {
            InstallPulseStrikeHook();
            InstallFunc1A25B0Hook();
            InstallFunc19F7D0Hook();
        }
        if (GetModuleHandleA("lua5.1.dll") != nullptr)
        {
            InstallLuaProtection();
        }
        if (g_WriteBitsHooked.load() && g_PulseStrikeHooked.load() && g_Func1A25B0Hooked.load() && g_LuaHSetHooked.load())
        {
            break;
        }
        Sleep(250);
    }

    const char* banner =
        "\n"
        "  +-----------------------------------------------------------------------+\n"
        "  |                   MT Development - ANTI-CMD-CRASHER                   |\n"
        "  |                   Create By Faxror - Serius - Sely                    |\n"
        "  |                       Discord: discord.gg/mtguard                     |\n"
        "  +-----------------------------------------------------------------------+\n"
        "  |  [*] Durum   : AKTIF & KORUMA CALISIYOR                               |\n"
        "  |  [*] Koruma  : CASCADE, PULSE STRIKE & LUA PANIC TAM ENGELLENDI       |\n"
        "  |  [*] Mod     : SIFIR BAN - CRASH VE CMD DONMASI YOK                   |\n"
        "  +-----------------------------------------------------------------------+\n\n";
    PrintToMtaConsole(banner, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    return 0;
}

// ============================================================================
// OFFICIAL MTA MODULE EXPORTS (COMPLIANT WITH MTA SERVER SDK)
// ============================================================================
extern "C" {
    __declspec(dllexport) bool InitModule(void* pManager, char* szModuleName, char* szAuthor, float* fVersion)
    {
        if (szModuleName)
        {
            strncpy_s(szModuleName, 32, "MTGuard", _TRUNCATE);
        }
        if (szAuthor)
        {
            strncpy_s(szAuthor, 64, "MT Development", _TRUNCATE);
        }
        if (fVersion)
        {
            *fVersion = 1.0f;
        }
        return true;
    }

    __declspec(dllexport) void DoPulse()
    {
        if (!g_WriteBitsHooked.load())
        {
            InstallWriteBitsHook();
        }
        if (!g_PulseStrikeHooked.load())
        {
            InstallPulseStrikeHook();
        }
        if (!g_Func1A25B0Hooked.load())
        {
            InstallFunc1A25B0Hook();
        }
        if (!g_Func19F7D0Hooked.load())
        {
            InstallFunc19F7D0Hook();
        }
        if (!g_LuaHSetHooked.load())
        {
            InstallLuaProtection();
        }

        static uint32_t s_LastLoggedCount = 0;
        if (g_pBlockedCounter)
        {
            uint32_t current = *g_pBlockedCounter;
            if (current > s_LastLoggedCount)
            {
                LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                            "Cascade exploit paketi engellendi! (Toplam engellenen: %u, Sunucu & CMD acik)",
                            (unsigned int)current);
                s_LastLoggedCount = current;
            }
        }
    }

    __declspec(dllexport) void ShutdownModule()
    {
    }

    __declspec(dllexport) bool RegisterFunction(void* pLuaVM, const char* szFunctionName, void* pFunction)
    {
        return true;
    }
}

// ============================================================================
// DLL ENTRY POINT
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        InitLogPaths(hModule);
        static std::atomic<bool> s_Initialized(false);
        if (!s_Initialized.exchange(true))
        {
            CreateThread(nullptr, 0, ShieldInitThread, nullptr, 0, nullptr);
        }
    }
    return TRUE;
}
