#pragma once
#define DllExport   __declspec( dllexport )

extern "C"
{
	DllExport unsigned long Mine_GetFastFileInformation(void* hFile, void* FileInformation);

}
