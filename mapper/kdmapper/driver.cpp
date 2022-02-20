#include <Windows.h>
#include "driver.h"
#include "vmprotect.h"

namespace Driver
{
    bool ElevateHandles(int target, int tid)
    {
        // KTM:  TmCommitTransactionExt for tx d688eaf0
        HANDLE transactionHandle = CreateTransaction(NULL, 0, 0, 0, 0, 0, (wchar_t*)(L"test-shit"));
        printf(E("Handle: %p Error: %x\n"), transactionHandle, GetLastError());
        CommitTransaction(transactionHandle);

        // It takes some time for the driver to process it
        Sleep(10);

        return true; // TODO: add real check
    }
}
