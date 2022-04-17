#include "dll-payload.h"

#include <Windows.h>
#include <stdint.h>
#include <random>
#include <iostream>

void foo(void* FileInformation, int pos)
{
	std::random_device dev;
	std::mt19937 rng(dev());
	std::uniform_int_distribution<std::mt19937::result_type> dist6(1, 13); // distribution in range [1, 6]
	uint64_t randarr[] = { 0x0, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFFFF / 2, 0xFFFF / 2 + 1, 0xFFFF / 2 - 1,0xFFFFFFFFFF,0xFFFFFFFFFFF,0xFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF };
	int num = dist6(rng);

	*((uint64_t*)FileInformation + pos) = randarr[num];
}

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FilePositionInformation = 14,
	FileEndOfFileInformation = 20,
	FileNetworkOpenInformation = 34,
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;



typedef NTSTATUS(WINAPI* pNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(WINAPI* pRtlNtStatusToDosError)(NTSTATUS Status);


unsigned long Mine_GetFastFileInformation(void* hFile, void* FileInformation)
{
	NTSTATUS v4; // eax
	signed int v5; // eax
	signed int Error; // ecx
	//__int64 FileInformationa[4]; // [rsp+30h] [rbp-68h] BYREF
	int v9; // [rsp+50h] [rbp-48h]
	__int64 v10[3]; // [rsp+58h] [rbp-40h] BYREF
	struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+70h] [rbp-28h] BYREF
	pNtQueryInformationFile NtQueryInformationFile = NULL;
	pRtlNtStatusToDosError RtlNtStatusToDosError = NULL;



	/* retrieve current timestamps including file attributes which we want to preserve */
	NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationFile");
	if (NtQueryInformationFile == NULL)
	{
		OutputDebugStringA("Fail");
		return 0;
	}

	RtlNtStatusToDosError = (pRtlNtStatusToDosError)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlNtStatusToDosError");
	if (RtlNtStatusToDosError == NULL)
	{
		OutputDebugStringA("Fail");
		return 0;
	}

	v4 = NtQueryInformationFile(hFile, &IoStatusBlock, FileInformation, 0x38u, FileNetworkOpenInformation);
	v5 = RtlNtStatusToDosError(v4);
	Error = v5;
	if (v5 > 0)
		Error = (unsigned __int16)v5 | 0x80070000;

	for (int i = 0; i < 7; i++)
	{
		foo(FileInformation, i);
	}
	return Error;

}
