#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")

#define MESSAGE_SIZE 2048

/*
This function will check if the binary is signed. However there is a logical bug inside.
If the binary is signed, whether or not the signature is verified, allowed or trusted, the function return True

Thus, if an attacker is able to sign its binary with a custom certificate, the function will always return True
*/
BOOL VerifyEmbeddedSignature(const wchar_t* binaryPath) {
    LONG lStatus;
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = binaryPath;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initializing necessary structures
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID and Wintrust_Data.
    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    BOOL isSigned;
    switch (lStatus) {
        // The file is signed and the signature was verified
    case ERROR_SUCCESS:
        isSigned = TRUE;
        break;

        // File is signed but the signature is not verified or is not trusted
    case TRUST_E_SUBJECT_FORM_UNKNOWN || TRUST_E_PROVIDER_UNKNOWN || TRUST_E_EXPLICIT_DISTRUST || CRYPT_E_SECURITY_SETTINGS || TRUST_E_SUBJECT_NOT_TRUSTED:
        isSigned = TRUE;
        break;

        // The file is not signed
    case TRUST_E_NOSIGNATURE:
        isSigned = FALSE;
        break;

        // Shouldn't happen but hey may be!
    default:
        isSigned = FALSE;
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return isSigned;
}

/*
This function parses the IAT table in order to retrieve loaded DLL's and then manually check if the binary
uses dumping functions which are:
- OpenProcess: used to obtain a handle on a process
- VirtualAllocEx: used to allocate memory to write a shellcode
- WriteProcessMemory: used to write the shellcode in the previously allocated memory space
- CreateRemoteThread: used to execute our thread

A binary can hide its IAT or simply dynamically load functions it needs using GetProcAddress.
Doing so, it will bypass this check.
*/
BOOL ListImportedFunctions(const wchar_t* binaryPath) {
    BOOL isOpenProcessPresent = FALSE;
    BOOL isVirtualAllocExPresent = FALSE;
    BOOL isWriteProcessMemoryPresent = FALSE;
    BOOL isCreateRemoteThreadPresent = FALSE;
    // Load the target binary so that we can parse its content
    HMODULE hModule = LoadLibraryEx(binaryPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule != NULL) {
        // Get NT headers from the binary
        IMAGE_NT_HEADERS* ntHeaders = ImageNtHeader(hModule);
        if (ntHeaders != NULL) {
            // Locate the IAT
            IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            // Loop over the DLL's
            while (importDesc->Name != 0) {
                const char* moduleName = (const char*)((BYTE*)hModule + importDesc->Name);

                // Loop over the functions of the DLL
                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->OriginalFirstThunk);
                while (thunk->u1.AddressOfData != 0) {
                    if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        //printf("\tOrdinal: %llu\n", IMAGE_ORDINAL(thunk->u1.Ordinal));
                    }
                    else {
                        IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hModule + thunk->u1.AddressOfData);
                        //printf("\tFunction: %s\n", importByName->Name);
                        // Checks if the following functions are used by the binary

                        if (strcmp("OpenProcess", importByName->Name) == 0) {
                            isOpenProcessPresent = TRUE;
                        }

                        if (strcmp("VirtualAllocEx", importByName->Name) == 0) {
                            isVirtualAllocExPresent = TRUE;
                        }

                        if (strcmp("WriteProcessMemory", importByName->Name) == 0) {
                            isWriteProcessMemoryPresent = TRUE;
                        }

                        if (strcmp("CreateRemoteThread", importByName->Name) == 0) {
                            isCreateRemoteThreadPresent = TRUE;
                        }

                    }
                    thunk++;
                }
                importDesc++;
            }
            FreeLibrary(hModule);
        }
        FreeLibrary(hModule);
    }

    if (isOpenProcessPresent && isVirtualAllocExPresent && isWriteProcessMemoryPresent && isCreateRemoteThreadPresent) {
        return TRUE;
    }
    else {
        return FALSE;
    }
    return FALSE;
}

/*
This function looks for the SeDebugPrivilege string inside the binary.
Stripping the binary will hide it ;)
*/
BOOL lookForSeDebugPrivilegeString(const wchar_t* filename) {
    FILE* file;
    _wfopen_s(&file, filename, L"rb");
    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);
        char* buffer = (char*)malloc(file_size);
        if (buffer != NULL) {
            if (fread(buffer, 1, file_size, file) == file_size) {
                const char* search_string = "SeDebugPrivilege";
                size_t search_length = strlen(search_string);
                int i, j;
                int found = 0;
                for (i = 0; i <= file_size - search_length; i++) {
                    for (j = 0; j < search_length; j++) {
                        if (buffer[i + j] != search_string[j]) {
                            break;
                        }
                    }
                    if (j == search_length) {
                        return TRUE;
                    }
                }
            }
            free(buffer);
        }
        fclose(file);
    }
    return FALSE;
}

int main() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\dumbedr-analyzer";
    DWORD bytesRead = 0;
    wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };

    printf("Launching analyzer named pipe server\n");

    // Creates a named pipe
    HANDLE hServerPipe = CreateNamedPipe(
        pipeName,                 // Pipe name to create
        PIPE_ACCESS_DUPLEX,       // Whether the pipe is supposed to receive or send data (can be both)
        PIPE_TYPE_MESSAGE,        // Pipe mode (whether or not the pipe is waiting for data)
        PIPE_UNLIMITED_INSTANCES, // Maximum number of instances from 1 to PIPE_UNLIMITED_INSTANCES
        MESSAGE_SIZE,             // Number of bytes for output buffer
        MESSAGE_SIZE,             // Number of bytes for input buffer
        0,                        // Pipe timeout 
        NULL                      // Security attributes (anonymous connection or may be needs credentials. )
    );

    while (TRUE) {

        // ConnectNamedPipe enables a named pipe server to start listening for incoming connections
        BOOL isPipeConnected = ConnectNamedPipe(
            hServerPipe, // Handle to the named pipe
            NULL         // Whether or not the pipe supports overlapped operations
        );

        wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };
        if (isPipeConnected) {
            // Read from the named pipe
            ReadFile(
                hServerPipe,         // Handle to the named pipe
                &target_binary_file, // Target buffer where to stock the output
                MESSAGE_SIZE,        // Size of the buffer
                &bytesRead,          // Number of bytes read from ReadFile
                NULL                 // Whether or not the pipe supports overlapped operations
            );

            printf("~> Received binary file %ws\n", target_binary_file);
            int res = 0;

            BOOL isSeDebugPrivilegeStringPresent = lookForSeDebugPrivilegeString(target_binary_file);
            if (isSeDebugPrivilegeStringPresent == TRUE) {
                printf("\t\033[31mFound SeDebugPrivilege string.\033[0m\n");
            }
            else {
                printf("\t\033[32mSeDebugPrivilege string not found.\033[0m\n");
            }

            BOOL isDangerousFunctionsFound = ListImportedFunctions(target_binary_file);
            if (isDangerousFunctionsFound == TRUE) {
                printf("\t\033[31mDangerous functions found.\033[0m\n");
            }
            else {
                printf("\t\033[32mNo dangerous functions found.\033[0m\n");
            }

            BOOL isSigned = VerifyEmbeddedSignature(target_binary_file);
            if (isSigned == TRUE) {
                printf("\t\033[32mBinary is signed.\033[0m\n");
            }
            else {
                printf("\t\033[31mBinary is not signed.\033[0m\n");
            }

            // Here there is a logical bug. If the binary is signed, all others checks are ignored
            wchar_t response[MESSAGE_SIZE] = { 0 };
            if (isSigned == TRUE) {
                swprintf_s(response, MESSAGE_SIZE, L"OK\0");
                printf("\t\033[32mStaticAnalyzer allows\033[0m\n");
            }
            else {
                // If the following conditions are met, the binary is blocked
                if (isDangerousFunctionsFound || isSeDebugPrivilegeStringPresent) {
                    swprintf_s(response, MESSAGE_SIZE, L"KO\0");
                    printf("\n\t\033[31mStaticAnalyzer denies\033[0m\n");
                }
                else {
                    swprintf_s(response, MESSAGE_SIZE, L"OK\0");
                    printf("\n\t\033[32mStaticAnalyzer allows\033[0m\n");
                }
            }

            DWORD bytesWritten = 0;
            // Write to the named pipe
            WriteFile(
                hServerPipe,   // Handle to the named pipe
                response,      // Buffer to write from
                MESSAGE_SIZE,  // Size of the buffer 
                &bytesWritten, // Numbers of bytes written
                NULL           // Whether or not the pipe supports overlapped operations
            );

        }

        // Disconnect
        DisconnectNamedPipe(
            hServerPipe // Handle to the named pipe
        );

        printf("\n\n");
    }
    return 0;
}