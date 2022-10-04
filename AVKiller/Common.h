#include <ntifs.h>
#include <minwindef.h>
//#include <winnt.h>
#define ZwReadVirtualMemory		0xBA
typedef NTSTATUS(*PQUERY_INFO_PROCESS) (
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);
PQUERY_INFO_PROCESS ZwQueryInformationProcess = NULL;
struct InputData
{
	ULONG pid;
};

