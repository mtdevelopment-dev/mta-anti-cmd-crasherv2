#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <share.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#define MTA_EXPORT __declspec(dllexport)
#else
#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <signal.h>
#include <ucontext.h>
#include <link.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#define MTA_EXPORT __attribute__((visibility("default")))
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif
#endif

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <string>
#include <vector>
#include <unordered_set>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <cmath>

static char SHIELD_LOG[MAX_PATH] = "mta_packet_audit.log";
static char CRASH_PACKET_LOG[MAX_PATH] = "mta_crash_packet.log";
static const int kMaxSaneDatagram = 4096;

#ifdef _WIN32
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

    FILE* fpTxt = _fsopen("mta_packet_audit.txt", "a+", _SH_DENYNO);
    if (fpTxt)
    {
        std::fprintf(fpTxt, "%s [%s] %s\n", timeBuf, tag, msgBuf);
        std::fclose(fpTxt);
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
#else
enum LinuxColor {
    COLOR_DEFAULT = 0,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_YELLOW,
    COLOR_CYAN
};

static void InitLogPathsLinux()
{
    Dl_info info;
    if (dladdr((void*)InitLogPathsLinux, &info) && info.dli_fname)
    {
        char dir[1024] = {0};
        std::strncpy(dir, info.dli_fname, sizeof(dir) - 1);
        char* slash = std::strrchr(dir, '/');
        if (slash)
        {
            *(slash + 1) = 0;
            std::snprintf(SHIELD_LOG, sizeof(SHIELD_LOG), "%smta_packet_audit.txt", dir);
            std::snprintf(CRASH_PACKET_LOG, sizeof(CRASH_PACKET_LOG), "%smta_crash_packet.txt", dir);
            return;
        }
    }
    std::snprintf(SHIELD_LOG, sizeof(SHIELD_LOG), "mta_packet_audit.txt");
    std::snprintf(CRASH_PACKET_LOG, sizeof(CRASH_PACKET_LOG), "mta_crash_packet.txt");
}

void PrintToMtaConsole(const char* text, int colorCode = COLOR_GREEN)
{
    const char* prefix = "\033[1;32m";
    switch (colorCode)
    {
        case COLOR_RED: prefix = "\033[1;31m"; break;
        case COLOR_YELLOW: prefix = "\033[1;33m"; break;
        case COLOR_CYAN: prefix = "\033[1;36m"; break;
        case COLOR_DEFAULT: prefix = "\033[0m"; break;
        default: prefix = "\033[1;32m"; break;
    }
    std::printf("%s%s\033[0m", prefix, text);
    std::fflush(stdout);
}

void LogAndPrint(const char* tag, int colorCode, const char* format, ...)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    struct tm tm_val;
    localtime_r(&tv.tv_sec, &tm_val);

    char timeBuf[64];
    std::snprintf(timeBuf, sizeof(timeBuf), "[%04d-%02d-%02d %02d:%02d:%02d.%03ld]",
                  tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday,
                  tm_val.tm_hour, tm_val.tm_min, tm_val.tm_sec, tv.tv_usec / 1000);

    char msgBuf[4096];
    va_list args;
    va_start(args, format);
    std::vsnprintf(msgBuf, sizeof(msgBuf), format, args);
    va_end(args);

    char consoleLine[4200];
    std::snprintf(consoleLine, sizeof(consoleLine), "%s [%s] %s\n", timeBuf, tag, msgBuf);
    PrintToMtaConsole(consoleLine, colorCode);

    // 1. Sunucu ana calisma dizinine mta_packet_audit.txt olarak kaydet
    FILE* fpRoot = fopen("mta_packet_audit.txt", "a");
    if (fpRoot)
    {
        std::fprintf(fpRoot, "%s", consoleLine);
        std::fflush(fpRoot);
        std::fclose(fpRoot);
    }

    // 2. Modul dizininde de farkli bir konum varsa oraya da kaydet
    if (std::strcmp(SHIELD_LOG, "mta_packet_audit.txt") != 0 && SHIELD_LOG[0] != '\0')
    {
        FILE* fp = fopen(SHIELD_LOG, "a");
        if (fp)
        {
            std::fprintf(fp, "%s", consoleLine);
            std::fflush(fp);
            std::fclose(fp);
        }
    }
}

static bool Readable(const void* p, size_t n)
{
    if (!p || n == 0) return false;
    uintptr_t start = (uintptr_t)p & ~0xFFFULL;
    uintptr_t end = ((uintptr_t)p + n + 0xFFFULL) & ~0xFFFULL;
    for (uintptr_t addr = start; addr < end; addr += 4096)
    {
        if (msync((void*)addr, 4096, MS_ASYNC) != 0 && errno == ENOMEM)
        {
            return false;
        }
    }
    return true;
}
#endif

#ifdef _WIN32
static std::atomic<bool> g_WriteBitsHooked(false);
static volatile uint32_t* g_pBlockedCounter = nullptr;
static uint8_t* g_pWriteBitsTarget = nullptr;

static uint8_t* ScanPattern(HMODULE hMod, const uint8_t* pattern, const char* mask, size_t len)
{
    if (!hMod) return nullptr;
    __try
    {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)hMod + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        {
            if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                uint8_t* start = (uint8_t*)hMod + sec->VirtualAddress;
                size_t size = sec->Misc.VirtualSize;
                if (size == 0) size = sec->SizeOfRawData;

                for (size_t off = 0; off + len <= size; ++off)
                {
                    bool match = true;
                    for (size_t j = 0; j < len; ++j)
                    {
                        if (mask[j] != '?' && start[off + j] != pattern[j])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match) return start + off;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
    return nullptr;
}

static void InstallWriteBitsHook()
{
    if (g_WriteBitsHooked.load()) return;

    HMODULE hNet = GetModuleHandleA("net.dll");
    if (!hNet) return;

    static const uint8_t kPattern[] = {
        0x45, 0x85, 0xC0, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x5C, 0x24, 0x00,
        0x48, 0x89, 0x6C, 0x24, 0x00
    };
    static const char kMask[] = "xxxxx????xxxx?xxxx?";
    uint8_t* target = ScanPattern(hNet, kPattern, kMask, sizeof(kPattern));

    if (!target)
    {
        target = (uint8_t*)hNet + 0x3A6B0;
        static const uint8_t kExpectedPrefix[9] = { 0x45, 0x85, 0xC0, 0x0F, 0x84, 0xDA, 0x00, 0x00, 0x00 };
        if (std::memcmp(target, kExpectedPrefix, sizeof(kExpectedPrefix)) != 0)
        {
            return;
        }
    }

    g_pWriteBitsTarget = target;

    uint8_t* stub = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub) return;

    uint8_t* continueAddr = target + 19;

    uint8_t stubCode[48] = {
        0x41, 0x81, 0xF8, 0x00, 0x00, 0x10, 0x00,
        0x77, 0x1D,
        0x45, 0x85, 0xC0,
        0x74, 0x1E,
        0x48, 0x89, 0x5C, 0x24, 0x10,
        0x48, 0x89, 0x6C, 0x24, 0x18,
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0x05, 0x04, 0x00, 0x00, 0x00,
        0xC3
    };

    std::memcpy(&stubCode[13], target + 9, 10);
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
        DWORD64 rva = (DWORD64)target - (DWORD64)hNet;
        LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    "Cascade exploit korumasi aktif edildi (net.dll + 0x%llX).", (unsigned long long)rva);
    }
}

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

    if (beginPtr != nullptr && beginPtr != endPtr)
    {
        if (beginPtr > endPtr)
        {
            LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                        "Pulse Strike exploit engellendi: Gecersiz vektor sinirlari!");
            return false;
        }

        size_t bytes = (uintptr_t)endPtr - (uintptr_t)beginPtr;
        if (bytes > 0x40000 || (bytes % sizeof(void*)) != 0 || !Readable(beginPtr, bytes))
        {
            LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                        "Pulse Strike exploit engellendi: Bozuk arguman dizisi!");
            return false;
        }

        void** cur = (void**)beginPtr;
        void** end = (void**)endPtr;
        while (cur < end)
        {
            void* elem = *cur;
            if (elem != nullptr && !Readable(elem, 8))
            {
                LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                            "Pulse Strike exploit engellendi: Gecersiz nesne pointer'i (0x%p)!", elem);
                return false;
            }
            cur++;
        }
    }

    __try
    {
        return g_OrigFunc1A4110(rcx, rdx, r8);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    "Pulse Strike exploit engellendi (Func1A4110 icinde guvenle yakalandi).");
        return false;
    }
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
                    "Pulse Strike korumasi #1 aktif edildi (deathmatch.dll).");
    }
}

typedef void (*tFunc1A25B0)(void* rcx, void* rdx, void* r8);
static tFunc1A25B0 g_OrigFunc1A25B0 = nullptr;
static std::atomic<bool> g_Func1A25B0Hooked(false);

void Hooked_Func1A25B0(void* rcx, void* rdx, void* r8)
{
    if (!rcx || !Readable(rcx, 16) || !rdx || !Readable(rdx, 16))
    {
        return;
    }

    void* beginPtr = *(void**)rdx;
    void* endPtr = *((void**)rdx + 1);

    if (beginPtr != nullptr && beginPtr != endPtr)
    {
        if (beginPtr > endPtr)
        {
            LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                        "Pulse Strike korumasi #2: Gecersiz vektor sinirlari!");
            return;
        }

        size_t bytes = (uintptr_t)endPtr - (uintptr_t)beginPtr;
        if (bytes > 0x40000 || (bytes % sizeof(void*)) != 0 || !Readable(beginPtr, bytes))
        {
            LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                        "Pulse Strike korumasi #2: Bozuk arguman dizisi!");
            return;
        }

        void** cur = (void**)beginPtr;
        void** end = (void**)endPtr;
        while (cur < end)
        {
            void* elem = *cur;
            if (elem != nullptr && !Readable(elem, 8))
            {
                LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                            "Pulse Strike korumasi #2: Gecersiz nesne pointer'i (0x%p)!", elem);
                return;
            }
            cur++;
        }
    }

    __try
    {
        g_OrigFunc1A25B0(rcx, rdx, r8);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    "Pulse Strike korumasi #2 (Func1A25B0 icinde guvenle yakalandi).");
    }
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

typedef void* (*tFunc19F7D0)(void* rcx, void* rdx, void* r8);
static tFunc19F7D0 g_OrigFunc19F7D0 = nullptr;
static std::atomic<bool> g_Func19F7D0Hooked(false);

void* Hooked_Func19F7D0(void* rcx, void* rdx, void* r8)
{
    if (!rdx || !Readable(rdx, 8))
    {
        if (rcx && Readable(rcx, 16))
        {
            *(int*)rcx = 0;
        }
        return rcx;
    }
    __try
    {
        return g_OrigFunc19F7D0(rcx, rdx, r8);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (rcx && Readable(rcx, 16))
        {
            *(int*)rcx = 0;
        }
        return rcx;
    }
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

typedef void* (*tLuaH_Set)(void* L, void* t, void* key);
static tLuaH_Set g_OrigLuaH_Set = nullptr;
static std::atomic<bool> g_LuaHSetHooked(false);
static uint8_t s_DummySinkTValue[32] = {0};

void* Hooked_LuaH_Set(void* L, void* t, void* key)
{
    if (!key) return s_DummySinkTValue;

    int tt = *(int*)((uint8_t*)key + 8);
    if (tt == 0)
    {
        return s_DummySinkTValue;
    }
    if (tt == 3)
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

    uint8_t* target = (uint8_t*)hLua + 0x179C0;
    static const uint8_t kExpectedPrefix[15] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18
    };
    if (std::memcmp(target, kExpectedPrefix, sizeof(kExpectedPrefix)) != 0)
    {
        target = nullptr;
    }

    if (target)
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

    uint8_t* pPanicExit = (uint8_t*)hLua + 0xB704;
    if (pPanicExit[0] == 0xB9 && pPanicExit[1] == 0x01 && pPanicExit[5] == 0xE8)
    {
        DWORD oldProt = 0;
        if (VirtualProtect(pPanicExit, 10, PAGE_EXECUTE_READWRITE, &oldProt))
        {
            pPanicExit[0] = 0xC3;
            for (int i = 1; i < 10; ++i) pPanicExit[i] = 0x90;
            VirtualProtect(pPanicExit, 10, oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), pPanicExit, 10);
            LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                        "Lua panic sonlandiricisi guvenli hale getirildi (lua5.1.dll + 0xB704).");
        }
    }
}

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

    HMODULE hFaultMod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)ctx->Rip, &hFaultMod) && hFaultMod)
    {
        char modPath[MAX_PATH] = {0};
        if (GetModuleFileNameA(hFaultMod, modPath, MAX_PATH))
        {
            char* slash = std::strrchr(modPath, '\\');
            const char* modName = slash ? slash + 1 : modPath;

            bool isMtaModule = (_stricmp(modName, "deathmatch.dll") == 0 ||
                                _stricmp(modName, "net.dll") == 0 ||
                                _stricmp(modName, "core.dll") == 0 ||
                                _stricmp(modName, "lua5.1.dll") == 0 ||
                                _stricmp(modName, "xmll.dll") == 0 ||
                                _stricmp(modName, "MTA Server.exe") == 0 ||
                                _stricmp(modName, "MTA Server64.exe") == 0);

            if (isMtaModule)
            {
                DWORD64 rva = ctx->Rip - (DWORD64)hFaultMod;
                LogAndPrint("MTGuard", FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                            "Exploit crash engellendi! [%s + 0x%llX] - Sunucu korundu.",
                            modName, (unsigned long long)rva);

                uint8_t* wbTarget = g_pWriteBitsTarget ? g_pWriteBitsTarget : ((uint8_t*)hFaultMod + 0x3A6B0);
                if (_stricmp(modName, "net.dll") == 0 && (ctx->Rip >= (DWORD64)wbTarget && ctx->Rip <= (DWORD64)wbTarget + 0xF0))
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
                    ctx->Rip = (DWORD64)wbTarget + 0xE3;
                    t_InFilter = 0;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                DWORD64 imageBase = (DWORD64)hFaultMod;
                PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(ctx->Rip, &imageBase, nullptr);
                if (entry)
                {
                    PVOID handlerData = nullptr;
                    ULONG_PTR establisher = 0;
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, ctx->Rip, entry, ctx, &handlerData, &establisher, nullptr);
                    ctx->Rax = 0;
                    t_InFilter = 0;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                if (Readable((void*)ctx->Rsp, 8))
                {
                    DWORD64 retAddr = *(DWORD64*)ctx->Rsp;
                    ctx->Rsp += 8;
                    ctx->Rip = retAddr;
                    ctx->Rax = 0;
                    t_InFilter = 0;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
    }

    t_InFilter = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

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
#else
// ============================================================================
// LINUX IMPLEMENTATION (x86_64 ELF)
// ============================================================================
typedef ssize_t (*t_real_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
static t_real_recvfrom g_RealRecvFrom = nullptr;
static struct sigaction g_OldSigSegv = {};
static struct sigaction g_OldSigBus = {};
static volatile sig_atomic_t g_InFilterLinux = 0;

extern "C" MTA_EXPORT ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

static void InitRealRecvFrom()
{
    if (g_RealRecvFrom && g_RealRecvFrom != (t_real_recvfrom)&recvfrom)
        return;

    void* libc = dlopen("libc.so.6", RTLD_LAZY | RTLD_NOLOAD);
    if (!libc) libc = dlopen("libc.so.6", RTLD_LAZY);
    if (libc)
    {
        g_RealRecvFrom = (t_real_recvfrom)dlsym(libc, "recvfrom");
    }
    if (!g_RealRecvFrom || g_RealRecvFrom == (t_real_recvfrom)&recvfrom)
    {
        g_RealRecvFrom = (t_real_recvfrom)dlsym(RTLD_NEXT, "recvfrom");
    }
    if (g_RealRecvFrom == (t_real_recvfrom)&recvfrom)
    {
        g_RealRecvFrom = nullptr;
    }
}

static ssize_t DirectRecvFrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    if (g_RealRecvFrom && g_RealRecvFrom != (t_real_recvfrom)&recvfrom)
    {
        return g_RealRecvFrom(sockfd, buf, len, flags, src_addr, addrlen);
    }
#if defined(__NR_recvfrom)
    return (ssize_t)syscall(__NR_recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
#elif defined(SYS_recvfrom)
    return (ssize_t)syscall(SYS_recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
#else
    return -1;
#endif
}

extern "C" MTA_EXPORT ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    if (!g_RealRecvFrom)
    {
        InitRealRecvFrom();
    }

    for (int attempts = 0; attempts < 8; ++attempts)
    {
        ssize_t bytes = DirectRecvFrom(sockfd, buf, len, flags, src_addr, addrlen);
        if (bytes <= 0 || buf == nullptr) return bytes;

        if (bytes > kMaxSaneDatagram)
        {
            continue;
        }

        return bytes;
    }

    errno = EWOULDBLOCK;
    return -1;
}

static void LinuxCrashSignalHandler(int sig, siginfo_t* info, void* ucontext)
{
    if (g_InFilterLinux)
    {
        signal(sig, SIG_DFL);
        raise(sig);
        return;
    }
    g_InFilterLinux = 1;

    ucontext_t* uc = (ucontext_t*)ucontext;
    uintptr_t rip = 0;
#if defined(__x86_64__) || defined(_M_X64)
    if (uc)
    {
        rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    }
#endif

    char crashMsg[256];
    int len = std::snprintf(crashMsg, sizeof(crashMsg),
                            "[MTGuard] Crash engellendi: signal=%d rip=0x%lx addr=%p\n",
                            sig, (unsigned long)rip, info ? info->si_addr : nullptr);
    if (len > 0)
    {
        int fd = open("mta_packet_audit.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0)
        {
            (void)write(fd, crashMsg, (size_t)len);
            close(fd);
        }
        (void)write(STDOUT_FILENO, crashMsg, (size_t)len);
    }

#if defined(__x86_64__) || defined(_M_X64)
    if (uc)
    {
        uintptr_t rsp = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
        if (rsp >= 0x1000 && Readable((void*)rsp, sizeof(uintptr_t)))
        {
            uintptr_t retAddr = *(uintptr_t*)rsp;
            if (retAddr >= 0x1000)
            {
                uc->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t);
                uc->uc_mcontext.gregs[REG_RIP] = retAddr;
                uc->uc_mcontext.gregs[REG_RAX] = 0;
                g_InFilterLinux = 0;
                return;
            }
        }
    }
#endif

    g_InFilterLinux = 0;
    if (sig == SIGSEGV)
    {
        if ((g_OldSigSegv.sa_flags & SA_SIGINFO) && g_OldSigSegv.sa_sigaction)
        {
            g_OldSigSegv.sa_sigaction(sig, info, ucontext);
            return;
        }
        else if (g_OldSigSegv.sa_handler && g_OldSigSegv.sa_handler != SIG_DFL && g_OldSigSegv.sa_handler != SIG_IGN)
        {
            g_OldSigSegv.sa_handler(sig);
            return;
        }
    }
    else if (sig == SIGBUS)
    {
        if ((g_OldSigBus.sa_flags & SA_SIGINFO) && g_OldSigBus.sa_sigaction)
        {
            g_OldSigBus.sa_sigaction(sig, info, ucontext);
            return;
        }
        else if (g_OldSigBus.sa_handler && g_OldSigBus.sa_handler != SIG_DFL && g_OldSigBus.sa_handler != SIG_IGN)
        {
            g_OldSigBus.sa_handler(sig);
            return;
        }
    }

    signal(sig, SIG_DFL);
    raise(sig);
}

static void InstallLinuxCrashProtection()
{
    static std::atomic<bool> s_Installed(false);
    if (s_Installed.exchange(true)) return;

    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = LinuxCrashSignalHandler;
    sa.sa_flags = SA_SIGINFO;
    sigfillset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, &g_OldSigSegv);
    sigaction(SIGBUS, &sa, &g_OldSigBus);
}

__attribute__((constructor)) static void OnLinuxModuleLoaded()
{
    InitLogPathsLinux();
    InitRealRecvFrom();
}
#endif

// ============================================================================
// MTA SERVER MODULE EXPORTS (COMMON)
// ============================================================================
extern "C" {
    MTA_EXPORT bool InitModule(void* pManager, char* szModuleName, char* szAuthor, float* fVersion)
    {
        (void)pManager;
#ifndef _WIN32
        InitRealRecvFrom();
        InstallLinuxCrashProtection();

        LogAndPrint("MTGuard", COLOR_GREEN, "Linux Server Shield baslatildi (mta_server_shield.so).");

        const char* banner =
            "\n"
            "  +-----------------------------------------------------------------------+\n"
            "  |             MT Development - ANTI-CMD-CRASHER (LINUX x64)             |\n"
            "  |                   Create By Faxror - Serius - Sely                    |\n"
            "  |                       Discord: discord.gg/mtguard                     |\n"
            "  +-----------------------------------------------------------------------+\n"
            "  |  [*] Durum   : AKTIF & KORUMA CALISIYOR (LINUX)                       |\n"
            "  |  [*] Koruma  : CASCADE, PULSE STRIKE & MALFORMED PACKET FILTRESI      |\n"
            "  |  [*] Mod     : SIFIR BAN - CRASH VE SUNUCU KAPANMASI ENGELLENDI       |\n"
            "  +-----------------------------------------------------------------------+\n\n";
        PrintToMtaConsole(banner, COLOR_GREEN);
#endif
        if (szModuleName)
        {
#ifdef _WIN32
            strncpy_s(szModuleName, 32, "MTGuard", _TRUNCATE);
#else
            std::strncpy(szModuleName, "MTGuard", 31);
            szModuleName[31] = '\0';
#endif
        }
        if (szAuthor)
        {
#ifdef _WIN32
            strncpy_s(szAuthor, 64, "MT Development", _TRUNCATE);
#else
            std::strncpy(szAuthor, "MT Development", 63);
            szAuthor[63] = '\0';
#endif
        }
        if (fVersion)
        {
            *fVersion = 1.0f;
        }
        return true;
    }

    MTA_EXPORT bool DoPulse()
    {
#ifdef _WIN32
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
#endif
        return true;
    }

    MTA_EXPORT bool ShutdownModule()
    {
        return true;
    }

    MTA_EXPORT void RegisterFunctions(void* luaVM)
    {
        (void)luaVM;
    }

    MTA_EXPORT bool ResourceStopping(void* luaVM)
    {
        (void)luaVM;
        return true;
    }

    MTA_EXPORT bool ResourceStopped(void* luaVM)
    {
        (void)luaVM;
        return true;
    }

    MTA_EXPORT bool RegisterFunction(void* pLuaVM, const char* szFunctionName, void* pFunction)
    {
        (void)pLuaVM;
        (void)szFunctionName;
        (void)pFunction;
        return true;
    }
}

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        HMODULE hSelf = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)hModule, &hSelf);

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
#endif
