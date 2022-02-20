#pragma once

namespace External
{
	UCHAR code[] = {
	  0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // mov -16 to rax
	  0x48, 0x21, 0xC4,                                             // and rsp, rax
	  0x48, 0x83, 0xEC, 0x20,                                       // subtract 32 from rsp
	  0x48, 0x8b, 0xEC,                                             // mov rbp, rsp
	  0x90, 0x90,                                                   // nop nop
	  0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,   // mov rcx,CCCCCCCCCCCCCCCC
	  0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,   // mov rax,AAAAAAAAAAAAAAAA
	  0xFF, 0xD0,                                                   // call rax
	  0x90,                                                         // nop
	  0x90,                                                         // nop
	  0xEB, 0xFC                                                    // JMP to nop
	};


	typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
	typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

	typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);


	struct loaderdata
	{
		PVOID ImageBase;
		PIMAGE_NT_HEADERS NtHeaders;
		PIMAGE_BASE_RELOCATION BaseRelocation;
		PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
		pLoadLibraryA fnLoadLibraryA;
		pGetProcAddress fnGetProcAddress;

	};

	DWORD64 __stdcall LibraryLoader(LPVOID Memory)
	{

		loaderdata* ManualInject = (loaderdata*)Memory;

		HMODULE hModule;
		DWORD64 i, Function, count, delta;

		DWORD64* ptr;
		PWORD list;

		PIMAGE_BASE_RELOCATION pIBR;
		PIMAGE_IMPORT_DESCRIPTOR pIID;
		PIMAGE_IMPORT_BY_NAME pIBN;
		PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

		PDLL_MAIN EntryPoint;

		pIBR = ManualInject->BaseRelocation;
		delta = (DWORD64)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

		while (pIBR->VirtualAddress)
		{
			if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
			{
				count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				list = (PWORD)(pIBR + 1);

				for (i = 0; i < count; i++)
				{
					if (list[i])
					{
						ptr = (DWORD64*)((LPBYTE)ManualInject->ImageBase + ((DWORD64)pIBR->VirtualAddress + (list[i] & 0xFFF)));
						*ptr += delta;
					}
				}
			}

			pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
		}

		pIID = ManualInject->ImportDirectory;

		// Resolve DLL imports

		while (pIID->Characteristics)
		{
			OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
			FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

			hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

			if (!hModule)
			{
				return FALSE;
			}

			while (OrigFirstThunk->u1.AddressOfData)
			{
				if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					// Import by ordinal

					Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

					if (!Function)
					{
						return FALSE;
					}

					FirstThunk->u1.Function = Function;
				}

				else
				{
					// Import by name

					pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
					Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

					if (!Function)
					{
						return FALSE;
					}

					FirstThunk->u1.Function = Function;
				}

				OrigFirstThunk++;
				FirstThunk++;
			}

			pIID++;
		}

		if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
		{
			EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
			return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
		}

		return TRUE;
	}

	DWORD64 __stdcall stub()
	{
		return 0;
	}
};