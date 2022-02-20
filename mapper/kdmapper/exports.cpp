#include "kdmapper.hpp"
#include "injector.h"
#include "vmprotect.h"
#include "version.h"
#include "driver.h"
#include "reset.h"

#define EXPORT extern "C" __declspec(dllexport)
#define GAME_EXE E("RustClient.exe")

void DebugWait(int seconds)
{
	printf(E("Waiting... "));
	for (int i = 1; i <= seconds; i++)
	{
		Sleep(1000);
		printf("%i ", i);
	}
	printf("\n");
}

__forceinline int FakeMapDriver()
{	
	HANDLE iqvw64e_device_handle = intel_driver::Load();
	
	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << E("Failed to load vulnerable driver") << std::endl;
		return -1;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle))
	{
		std::cout << E("Failed to map driver") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	std::cout << E("Finished") << std::endl;

	return 0;
}

__forceinline int dll_MapDriver()
{	
	//AllocConsole();
	//freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	//freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
	//ShowWindow(GetConsoleWindow(), SW_SHOW);

	int status = FakeMapDriver();

	//Sleep(3000);
	//ShowWindow(GetConsoleWindow(), SW_HIDE);

	return status;
}

__forceinline int dll_Inject(int PID, int prefered, const char* dllpath, bool restore)
{	
	//AllocConsole();
	//freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	//freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
	//ShowWindow(GetConsoleWindow(), SW_SHOW);

	int status = Inject(PID, prefered, dllpath, restore);

	//Sleep(3000);
	//ShowWindow(GetConsoleWindow(), SW_HIDE);

	return status;
}

int Find(const char* proc)
{
	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	auto pe = PROCESSENTRY32{ sizeof(PROCESSENTRY32) };

	if (Process32First(snapshot, &pe)) {
		do {
			if (strcmp(proc, pe.szExeFile) == 0) {
				CloseHandle(snapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(snapshot, &pe));
	}
	CloseHandle(snapshot);
	return 0;
}

int fakemain(const int argc, char** argv) 
{
	Protect();

	printf(E("Checking version...\n"));
	auto version = GetRealOSVersion();
	printf("Build: %lu Major: %lu Minor: %lu\n", version.dwBuildNumber, version.dwMajorVersion, version.dwMinorVersion);

	if (strcmp(argv[1], "A") == 0)
	{
		Reset();
		return 0;
	}
	
	if (argc < 2)
	{
		printf("Invalid args #1\n");
		return -1;
	}

	if (strcmp(argv[1], "B") == 0)
	{
		printf(E("Checking if game is running...\n"));
		if (Find(GAME_EXE))
		{
			printf(E("Game is already running!\n"));
			return -1;
		}
		
		dll_MapDriver();

		printf(E("Waiting for game to start (you have to open the game now)...\n"));
		int pid = Find(GAME_EXE);
		while (!pid)
		{
			Sleep(1000);
			pid = Find(GAME_EXE);
		}

		DebugWait(20);

		int tid = 0;
		const char* path = argv[2];
		dll_Inject(pid, tid, path, true);

		UnregisterCallbacks();
	}

	return 0;

	End();
}

int main(const int argc, char** argv) 
{	
	fakemain(argc, argv);
	
	DebugWait(3);
	
	return 0;
}