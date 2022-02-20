#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <fstream>
#include "vmprotect.h"
#include "injector.h"
#include "injecthelper.h"
#include "external.h"
#include "driver.h"

CONTEXT origctx;
int ChangeTheadContext(HANDLE threadhndl, uintptr_t address, bool restore)
{
	Protect();
	
	printf(E("Suspending thread...\n"));
	DWORD suspend = SuspendThread(threadhndl);
	if (suspend == -1)
	{
		printf(E("Failed to suspend thread! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}

	printf(E("Getting thread context...\n"));
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	bool context = GetThreadContext(threadhndl, &ctx);
	if (!context)
	{
		printf(E("Failed to get thread context! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}
	if (!restore)
		origctx = ctx;

	printf(E("Setting thread context (0x%llx, %i)...\n"), address, restore);
	ctx.Rip = address;
	bool set = SetThreadContext(threadhndl, restore ? &origctx : &ctx);
	if (!set)
	{
		printf(E("Failed to set thread context! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}

	printf(E("Resuming thread...\n"));
	DWORD resume = ResumeThread(threadhndl);
	if (resume == -1)
	{
		printf(E("Failed to resume thread! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}

	End();

	return 0;
}

int Inject(int PID, int prefered, const char* dllpath, bool restore)
{
	Protect();
	
	printf(E("Opening process and thread...\n"));
	HANDLE prochndl = OpenProcess(PROCESS_QUERY_INFORMATION, false, PID);
	if (prochndl == INVALID_HANDLE_VALUE || !prochndl)
	{
		printf(E("Failed to open process! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}

	int TID = InjectHelper::GetMainThreadBasedOnTime(PID);
	if (!TID)
	{
		printf(E("Failed to get main thread identifier! GetLastError() 0x%x\n"), GetLastError());
	}
	HANDLE threadhndl = OpenThread(THREAD_QUERY_INFORMATION, false, TID);
	if (threadhndl == INVALID_HANDLE_VALUE || !threadhndl)
	{
		printf(E("Failed to open thread! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}

	printf(E("Elevating handles...\n"));
	bool elevate = Driver::ElevateHandles(PID, TID);
	if (!elevate)
	{
		printf(E("Failed to elevate handles!\n"));
		return -1;
	}

	printf(E("Reading dll file to memory...\n"));
	std::vector<uint8_t> dllbuffer;
	bool read = InjectHelper::ReadFile(dllpath, &dllbuffer);
	if (!read)
	{
		printf(E("Failed to read dll file!\n"));
		return -1;
	}

	printf(E("Parsing...\n"));
	IMAGE_DOS_HEADER* header = InjectHelper::GetDosHeader(dllbuffer.data());
	if (header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf(E("Dll has invalid dos signature!\n"));
		return -1;
	}
	IMAGE_NT_HEADERS64* ntheader = InjectHelper::GetNtHeaders(header);
	if (ntheader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf(E("Dll has invalid nt signature!\n"));
		return -1;
	}
	int dllsize = ntheader->OptionalHeader.SizeOfImage;
	int entrypoint = ntheader->OptionalHeader.AddressOfEntryPoint;
	printf(E("Entry: 0x%x Size: %u\n"), entrypoint, dllsize);

	printf(E("Allocating memory for dll...\n"));
	LPVOID allocbase = VirtualAllocEx(prochndl, nullptr, dllsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!allocbase)
	{
		printf(E("Failed to allocate memory for dll! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}
	Sleep(100);

	printf(E("Copying headers...\n"));
	SIZE_T written = 0;
	bool headers = WriteProcessMemory(prochndl, allocbase, dllbuffer.data(), ntheader->OptionalHeader.SizeOfHeaders, &written);
	if (!headers)
	{
		printf(E("Failed to copy header into target process! GetLastError() 0x%x Written: 0x%llu\n"), GetLastError(), written);
		return -1;
	}

	printf(E("Allocating memory for shellcode...\n"));
	LPVOID shellbase = VirtualAllocEx(prochndl, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellbase)
	{
		printf(E("Failed to allocate memory for shellcode! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}
	Sleep(100);

	printf(E("Copying shellcode...\n"));
	External::loaderdata loaddata;
	loaddata.ImageBase = allocbase;
	loaddata.NtHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)allocbase + header->e_lfanew);
	loaddata.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)allocbase + ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	loaddata.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)allocbase + ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	loaddata.fnLoadLibraryA = LoadLibraryA;
	loaddata.fnGetProcAddress = GetProcAddress;
	written = 0;
	bool loadinfo = WriteProcessMemory(prochndl, shellbase, &loaddata, sizeof(loaddata), &written);
	if (!loadinfo)
	{
		printf(E("Failed to copy loader information into target process! GetLastError() 0x%x Written: 0x%llu\n"), GetLastError(), written);
		return -1;
	}
	bool code = WriteProcessMemory(prochndl, (PVOID)((External::loaderdata*)shellbase + 1), External::LibraryLoader, (DWORD64)External::stub - (DWORD64)External::LibraryLoader, &written);
	if (!code)
	{
		printf(E("Failed to copy loader shellcode into target process! GetLastError() 0x%x Written: 0x%llu\n"), GetLastError(), written);
		return -1;
	}

	printf(E("Prepairing loader code...\n"));
	LPVOID sbuffer = VirtualAlloc(NULL, sizeof(External::code + 10), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ZeroMemory(sbuffer, sizeof(External::code + 10));
	memcpy(sbuffer, External::code, sizeof(External::code));

	for (BYTE* ptr = (LPBYTE)sbuffer; ptr < ((LPBYTE)sbuffer + 300); ptr++)
	{
		DWORD64 address = *(DWORD64*)ptr;
		if (address == 0xCCCCCCCCCCCCCCCC)
		{
			*(DWORD64*)ptr = (DWORD64)shellbase;
		}

		if (address == 0xAAAAAAAAAAAAAAAA)
		{
			*(DWORD64*)ptr = (DWORD64)((External::loaderdata*)shellbase + 1);
		}
	}

	printf(E("Allocating memory for loader code...\n"));
	LPVOID loadercbase = VirtualAllocEx(prochndl, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!loadercbase)
	{
		printf(E("Failed to allocate memory for loader code! GetLastError() 0x%x\n"), GetLastError());
		return -1;
	}
	Sleep(100);

	printf(E("Copying loader code...\n"));
	bool loadcode = WriteProcessMemory(prochndl, loadercbase, sbuffer, sizeof(External::code), &written);
	if (!loadcode)
	{
		printf(E("Failed to copy loader code into target process! GetLastError() 0x%x Written: 0x%llu\n"), GetLastError(), written);
		return -1;
	}
	uintptr_t shellstart = (uintptr_t)loadercbase;

	PIMAGE_SECTION_HEADER sectionheader = (PIMAGE_SECTION_HEADER)(ntheader + 1);
	for (int i = 0; i < ntheader->FileHeader.NumberOfSections; i++)
	{
		printf(E("Copying section 0x%lx with size %lu...\n"), sectionheader[i].VirtualAddress, sectionheader[i].SizeOfRawData);
		if (!WriteProcessMemory(prochndl, (PVOID)((LPBYTE)allocbase + sectionheader[i].VirtualAddress), (PVOID)((LPBYTE)dllbuffer.data() + sectionheader[i].PointerToRawData), sectionheader[i].SizeOfRawData, &written))
		{
			printf(E("Failed to copy section into target process! GetLastError() 0x%x Written: %llu\n"), GetLastError(), written);
			return -1;
		}
	}

	int change = ChangeTheadContext(threadhndl, shellstart, false);
	if (change != 0)
	{
		return change;
	}

	if (restore)
	{
		printf(E("Waiting...\n"));
		Sleep(3000);

		printf(E("Elevating handles (again)...\n"));
		bool elevate2 = Driver::ElevateHandles(PID, TID);
		if (!elevate2)
		{
			printf(E("Failed to elevate handles!\n"));
			return -1;
		}

		printf(E("Restoring thread...\n"));
		int res = ChangeTheadContext(threadhndl, 0, true);
		if (res != 0)
		{
			return change;
		}

		char* zeroedbuffer = (char*)malloc(dllsize);
		ZeroMemory(zeroedbuffer, dllsize);

		// zero out the dll
		WriteProcessMemory(prochndl, allocbase, zeroedbuffer, dllsize, nullptr);

		// free the memory
		VirtualFreeEx(prochndl, allocbase, dllsize, MEM_DECOMMIT);
		free(zeroedbuffer);
	}

	printf(E("Cleaning up...\n"));
	CloseHandle(prochndl);
	CloseHandle(threadhndl);

	End();

	return 0;
}