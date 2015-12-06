#pragma once
#include "global.h"
#include "dispatch.h"

NTSTATUS setNtHook(HANDLE hProcess, ULONG_PTR originalNtFunc, ULONG_PTR customNtFunc);
NTSTATUS removeNtHook(HANDLE hProcess, ULONG_PTR originalNtFunc);
//__declspec(noinline) ULONG_PTR getSomeAddress(void);