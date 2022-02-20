#pragma once
#include <process.h>

void UnregisterCallbacks()
{
	printf(E("Starting new instance...\n"));

	char path[MAX_PATH];
	GetModuleFileNameA(nullptr, path, MAX_PATH);

	STARTUPINFO info = { sizeof(info) };
	PROCESS_INFORMATION processInfo;
	if (CreateProcessA(path, (char*)E("native.exe A"), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &info, &processInfo))
	{
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
		printf(E("New instance started\n"));
	} else
	{
		printf(E("Failed to create new instance! GetLastError() 0x%x\n"), GetLastError());
	}	
}

void Reset()
{
	printf(E("Waiting...\n"));
	Sleep(4000);

	printf(E("Unregistering callbacks...\n"));
	Driver::ElevateHandles(0, 0);
}