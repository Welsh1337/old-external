#pragma once

namespace InjectHelper
{
	bool ReadFile(const std::string& file_path, std::vector<uint8_t>* out_buffer)
	{
		std::ifstream file_ifstream(file_path, std::ios::binary);

		if (!file_ifstream)
			return false;

		out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
		file_ifstream.close();

		return true;
	}

	PIMAGE_DOS_HEADER GetDosHeader(void* data)
	{
		return (PIMAGE_DOS_HEADER)data;
	}

	PIMAGE_NT_HEADERS64 GetNtHeaders(PIMAGE_DOS_HEADER header)
	{
		return (PIMAGE_NT_HEADERS64)((uintptr_t)header + header->e_lfanew);
	}

	DWORD GetMainThreadId(int pid)
	{
		HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnapshot == INVALID_HANDLE_VALUE)
		{
			return 0;
		}
		
		THREADENTRY32 tEntry;
		tEntry.dwSize = sizeof(THREADENTRY32);
		DWORD result = 0;
		DWORD currentPID = pid;
		for (BOOL success = Thread32First(hThreadSnapshot, &tEntry);
			!result && success && GetLastError() != ERROR_NO_MORE_FILES;
			success = Thread32Next(hThreadSnapshot, &tEntry))
		{
			printf("owner: %i id: %i\n", tEntry.th32OwnerProcessID, tEntry.th32ThreadID);
			if (tEntry.th32OwnerProcessID == currentPID)
			{
				result = tEntry.th32ThreadID;
			}
		}
		return result;
	}



#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

	int GetMainThreadBasedOnTime(DWORD dwProcID)
	{
		DWORD dwMainThreadID = 0;
		ULONGLONG ullMinCreateTime = MAXULONGLONG;

		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap != INVALID_HANDLE_VALUE) 
		{
			THREADENTRY32 th32;
			th32.dwSize = sizeof(THREADENTRY32);
			BOOL bOK = TRUE;
			for (bOK = Thread32First(hThreadSnap, &th32); bOK;
				bOK = Thread32Next(hThreadSnap, &th32)) 
			{
				if (th32.th32OwnerProcessID == dwProcID) 
				{
					HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
						TRUE, th32.th32ThreadID);
					if (hThread) 
					{
						FILETIME afTimes[4] = { 0 };
						if (GetThreadTimes(hThread,
							&afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3]))
						{
							ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime,
								afTimes[0].dwHighDateTime);
							if (ullTest && ullTest < ullMinCreateTime) 
							{
								ullMinCreateTime = ullTest;
								dwMainThreadID = th32.th32ThreadID;
							}
						}
						CloseHandle(hThread);
					}
				}
			}

			CloseHandle(hThreadSnap);
		}

		return dwMainThreadID;
	}

};