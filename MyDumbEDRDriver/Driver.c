#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

// Needs to be set on the project properties as well
#pragma comment(lib, "FltMgr.lib")

// Maximum size of the buffers used to communicate via Named Pipes
#define MESSAGE_SIZE 2048

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\MyDumbEDR"); // Internal driver device name, cannot be used userland
UNICODE_STRING SYM_LINK = RTL_CONSTANT_STRING(L"\\??\\MyDumbEDR");        // Symlink used to reach the driver, can be used userland

/*
This function is sending the path as well as the name of the binary being launched
to the DumbEDRAnalyzer agent running in userland
*/
int analyze_binary(wchar_t* binary_file_path) {

    UNICODE_STRING pipeName; // String containing the name of the named
    // Initialize a UNICODE_STRING structure containing the name of the named pipe
    RtlInitUnicodeString(
        &pipeName,                      // Variable in which we will store the UNICODE_STRING structure
        L"\\??\\pipe\\dumbedr-analyzer" // Wide string containing the name of the named pipe
    );

    HANDLE hPipe;                     // Handle that we will use to communicate with the named pipe
    OBJECT_ATTRIBUTES fattrs = { 0 }; // Objects Attributes used to store information when calling ZwCreateFile
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Initialize an OBJECT_ATTRIBUTE structure pointing to our named pipe
    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);

    // Reads from the named pipe
    NTSTATUS status = ZwCreateFile(
        &hPipe,                                         // Handle to the named pipe
        FILE_WRITE_DATA | FILE_READ_DATA | SYNCHRONIZE, // File attribute (we need both read and write)
        &fattrs,                                        // Structure containing the file attribute
        &io_stat_block,                                 // Structure containing the I/O queue
        NULL,                                           // Allocation size, not needed in that case
        0,                                              // Specific files attributes (not needed as well
        FILE_SHARE_READ | FILE_SHARE_WRITE,             // File sharing access
        FILE_OPEN,                                      // Specify the action we want to do on the file 
        FILE_NON_DIRECTORY_FILE,                        // Specifying that the file is not a directory
        NULL,                                           // Always NULL
        0                                               // Always zero
    );

    // If we can obtain a handle on the named pipe then 
    if (NT_SUCCESS(status)) {

        // Now we'll send the binary path to the userland agent
        status = ZwWriteFile(
            hPipe,            // Handle to the named pipe
            NULL,             // Optionally a handle on an even object
            NULL,             // Always NULL
            NULL,             // Always NULL
            &io_stat_block,   // Structure containing the I/O queue
            binary_file_path, // Buffer in which is stored the binary path
            MESSAGE_SIZE,     // Maximum size of the buffer
            NULL,             // Bytes offset (optional)
            NULL              // Always NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWriteFile: 0x%0.8x\n", status);

        /*
        This function is needed when you are running read/write files operation so that the kernel driver
        makes sure that the reading/writing phase is done and you can keep running the code
        */

        status = ZwWaitForSingleObject(
            hPipe, // Handle the named pipe
            FALSE, // Whether or not we want the wait to be alertable
            NULL   // An optional timeout
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);

        wchar_t response[MESSAGE_SIZE] = { 0 };
        // Reading the respons from the named pipe (ie: if the binary is malicious or not based on static analysis)
        status = ZwReadFile(
            hPipe,          // Handle to the named pipe
            NULL,           // Optionally a handle on an even object
            NULL,           // Always NULL
            NULL,           // Always NULL
            &io_stat_block, // Structure containing the I/O queue
            &response,      // Buffer in which to store the answer
            MESSAGE_SIZE,   // Maximum size of the buffer
            NULL,           // Bytes offset (optional)
            NULL            // Always NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwReadFile: 0x%0.8x\n", status);

        // Waiting again for the operation to be completed
        status = ZwWaitForSingleObject(
            hPipe,
            FALSE,
            NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);

        // Used to close a connection to the named pipe
        ZwClose(
            hPipe // Handle to the named pipe
        );

        if (wcscmp(response, L"OK\0") == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            StaticAnalyzer: OK\n", response);
            return 0;
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            StaticAnalyzer: KO\n", response);
            return 0;
            // return 1;
        }
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            StaticAnalyzer unreachable. Allowing.\n");
        return 0;
    }
}

int inject_dll(int pid) {
    UNICODE_STRING pipeName; // String containing the name of the named
    // Initialize a UNICODE_STRING structure containing the name of the named pipe
    RtlInitUnicodeString(
        &pipeName,                      // Variable in which we will store the UNICODE_STRING structure
        L"\\??\\pipe\\dumbedr-injector" // Wide string containing the name of the named pipe
    );

    HANDLE hPipe;                     // Handle that we will use to communicate with the named pipe
    OBJECT_ATTRIBUTES fattrs = { 0 }; // Objects Attributes used to store information when calling ZwCreateFile
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Initialize an OBJECT_ATTRIBUTE structure pointing to our named pipe
    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);

    // Reads from the named pipe
    NTSTATUS status = ZwCreateFile(
        &hPipe,                                         // Handle to the named pipe
        FILE_WRITE_DATA | FILE_READ_DATA | SYNCHRONIZE, // File attribute (we need both read and write)
        &fattrs,                                        // Structure containing the file attribute
        &io_stat_block,                                 // Structure containing the I/O queue
        NULL,                                           // Allocation size, not needed in that case
        0,                                              // Specific files attributes (not needed as well
        FILE_SHARE_READ | FILE_SHARE_WRITE,             // File sharing access
        FILE_OPEN,                                      // Specify the action we want to do on the file 
        FILE_NON_DIRECTORY_FILE,                        // Specifying that the file is not a directory
        NULL,                                           // Always NULL
        0                                               // Always zero
    );

    // If we can obtain a handle on the named pipe then 
    if (NT_SUCCESS(status)) {

        wchar_t pid_to_inject[MESSAGE_SIZE] = { 0 };
        swprintf_s(pid_to_inject, MESSAGE_SIZE, L"%d\0", pid);
        // Now we'll send the binary path to the userland agent
        status = ZwWriteFile(
            hPipe,          // Handle to the named pipe
            NULL,           // Optionally a handle on an even object
            NULL,           // Always NULL
            NULL,           // Always NULL
            &io_stat_block, // Structure containing the I/O queue
            pid_to_inject,  // Buffer in which is stored the binary path
            MESSAGE_SIZE,   // Maximum size of the buffer
            NULL,           // Bytes offset (optional)
            NULL            // Always NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWriteFile: 0x%0.8x\n", status);

        /*
        This function is needed when you are running read/write files operation so that the kernel driver
        makes sure that the reading/writing phase is done and you can keep running the code
        */

        status = ZwWaitForSingleObject(
            hPipe, // Handle the named pipe
            FALSE, // Whether or not we want the wait to be alertable
            NULL   // An optional timeout
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);
        
        wchar_t response[MESSAGE_SIZE] = { 0 };
        // Reading the response from the named pipe (ie: if the binary is malicious or not based on static analysis)
        status = ZwReadFile(
            hPipe,          // Handle to the named pipe
            NULL,           // Optionally a handle on an even object
            NULL,           // Always NULL
            NULL,           // Always NULL
            &io_stat_block, // Structure containing the I/O queue
            &response,      // Buffer in which to store the answer
            MESSAGE_SIZE,   // Maximum size of the buffer
            NULL,           // Bytes offset (optional)
            NULL            // Always NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwReadFile: 0x%0.8x\n", status);

        // Waiting again for the operation to be completed
        status = ZwWaitForSingleObject(
            hPipe,
            FALSE,
            NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);
        
        // Used to close a connection to the named pipe
        ZwClose(
            hPipe // Handle to the named pipe
        );
        
        if (wcscmp(response, L"OK\0") == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector: OK\n", response);
            return 0;
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector: KO\n", response);
            return 1;
        }
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector unreachable. Allowing.\n");
        return 0;
    }
}

void CreateProcessNotifyRoutine(PEPROCESS parent_process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
    UNREFERENCED_PARAMETER(parent_process);

    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;

    PsLookupProcessByProcessId(pid, &process);
    SeLocateProcessImageName(process, &processName);

    // Never forget this if check because if you don't, you'll end up crashing your Windows system ;P
    if (createInfo != NULL) {
        createInfo->CreationStatus = STATUS_SUCCESS;

        // Retrieve parent process ID and process name
        PsLookupProcessByProcessId(createInfo->ParentProcessId, &parent_process);
        PUNICODE_STRING parent_processName = NULL;
        SeLocateProcessImageName(parent_process, &parent_processName);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ created\n", processName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d\n", pid);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            Created by: %wZ\n", parent_processName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ImageBase: %ws\n", createInfo->ImageFileName->Buffer);

        POBJECT_NAME_INFORMATION objFileDosDeviceName;
        IoQueryFileDosDeviceName(createInfo->FileObject, &objFileDosDeviceName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            DOS path: %ws\n", objFileDosDeviceName->Name.Buffer);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            CommandLine: %ws\n", createInfo->CommandLine->Buffer);

        // Compare the image base of the launched process to the dump_lasss string
        if (wcsstr(createInfo->ImageFileName->Buffer, L"ShellcodeInject.exe") != NULL) {

            // Checks if the notepad keyword is found in the CommandLine
            if (wcsstr(createInfo->CommandLine->Buffer, L"notepad.exe") != NULL) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: DENIED command line\n");
                createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }

            if (createInfo->FileOpenNameAvailable && createInfo->ImageFileName) {
                int analyzer_ret = analyze_binary(objFileDosDeviceName->Name.Buffer);
                if (analyzer_ret == 0) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: Sending to injector\n");
                    int injector_ret = inject_dll((int)(intptr_t)pid);
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: return injector '%d'\n", injector_ret);

                    if (injector_ret == 0) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: PROCESS ALLOWED\n");
                        createInfo->CreationStatus = STATUS_SUCCESS;
                        return;
                    }
                    else {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: PROCESS DENIED\n");
                        createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                        return;
                    }
                }
                else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            State: Denied by StaticAnalyzer\n");
                    createInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    return;
                }
            }
        }
    }
    // Logical bug here, if the agent is not running, the driver will always allow the creation of the process
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ killed\n", processName);
    }
}

void UnloadMyDumbEDR(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[MyDumbEDR] Unloading routine called\n");
    // Unset the callback
    PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateProcessNotifyRoutine, TRUE);
    // Delete the driver device 
    IoDeleteDevice(DriverObject->DeviceObject);
    // Delete the symbolic link
    IoDeleteSymbolicLink(&SYM_LINK);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    // Prevent compiler error such as unreferenced parameter (error 4)
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Initializing the EDR's driver\n");

    // Variable that will store the output of WinAPI functions
    NTSTATUS status;

    // Setting the unload routine to execute
    DriverObject->DriverUnload = UnloadMyDumbEDR;

    // Initializing a device object and creating it
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING deviceName = DEVICE_NAME;
    UNICODE_STRING symlinkName = SYM_LINK;
    status = IoCreateDevice(
        DriverObject,		   // our driver object,
        0,					   // no need for extra bytes,
        &deviceName,           // the device name,
        FILE_DEVICE_UNKNOWN,   // device type,
        0,					   // characteristics flags,
        FALSE,				   // not exclusive,
        &DeviceObject		   // the resulting pointer
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Device creation failed\n");
        return status;
    }

    // Creating the symlink that we will use to contact our driver
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Symlink creation failed\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }

    NTSTATUS ret = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
    if (ret == STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Driver launched successfully\n");
    }
    else if (ret == STATUS_INVALID_PARAMETER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Invalid parameter\n");
    }
    else if (ret == STATUS_ACCESS_DENIED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Access denied\n");
    }

    return 0;
}