#include "global.h"
#include "hook.h"


#define MIN_VM_ACCESS_MASK (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)
NTSTATUS openProcByName(PHANDLE pProcess, PUNICODE_STRING pProcName, BOOLEAN useDebugPrivilege) {
	SYSTEM_PROCESS_INFORMATION procInfo;
	OBJECT_ATTRIBUTES procAttr;
	OBJECT_BASIC_INFORMATION processHandleInfo;
	CLIENT_ID cid;
	BOOLEAN oldValue;
	HANDLE pid;

	NTSTATUS status = STATUS_CACHE_PAGE_LOCKED;
	ULONG procListSize = 0;
	ULONGLONG memSize = 0;
	ULONG obQueryLen = 0;
	PVOID pProcListHead = NULL;
	PSYSTEM_PROCESS_INFORMATION pProcEntry = NULL;

	do {
		if (!pProcName || !pProcess) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		*pProcess = NULL;

		///Since we specify a buffer size of 0 the buffer must overflow for sure even if there was running a
		///single process only. If we don't receive the dedicated error, something other has gone wrong
		///and we cannot rely on the return length.
		status = NtQuerySystemInformation(SystemProcessInformation, &procInfo, procListSize, &procListSize);
		if (STATUS_INFO_LENGTH_MISMATCH != status)
			break;

		memSize = PAGE_ROUND_UP(procListSize) + PAGE_SIZE; ///We better allocate one page extra
														   ///since between our "test" call and the real call below
														   ///additional processes might be started. (race condition)
		status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, 0, &memSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (status) {
			pProcListHead = NULL;
			break;
		}

		///By now, we have allocated a buffer large enough for the complete process list,
		///even if some new processes have been started in the mean time.
		///Hence, the next call is entirely expected to succeed.
		procListSize = (ULONG)memSize;
		status = NtQuerySystemInformation(SystemProcessInformation, pProcListHead, procListSize, &procListSize);
		if (status)
			break;

		pid = NULL;
		pProcEntry = pProcListHead;				///The list of all system processes is a so called singly linked list.
		while (pProcEntry->NextEntryOffset) {	///If NextEntryOffset member is NULL, we have reached the list end (tail).
			pProcEntry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcEntry + pProcEntry->NextEntryOffset);
			//DebugPrint2A("PID: %d, %wZ", pProcEntry->UniqueProcessId, pProcEntry->ImageName);
			if (0 == RtlCompareUnicodeString(pProcName, &pProcEntry->ImageName, TRUE)) {
				pid = pProcEntry->UniqueProcessId;
				break;
			}
		}

		if (!pid) {
			status = STATUS_OBJECT_NAME_NOT_FOUND;
			break;
		}

		if (useDebugPrivilege) {
			status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &oldValue);
			if (status) {			///Since we're for some reason supposed to use the SeDebugPrivilege,
				useDebugPrivilege = FALSE;
				break;				///we fail deliberately if we can't enable it.
			}
		}

		InitializeObjectAttributes(&procAttr, NULL, 0, NULL, NULL);
		cid.UniqueThread = (HANDLE)0;
		cid.UniqueProcess = pid;

		///Opening a process for full access might be less suspicious than opening with our real intentions.
		status = NtOpenProcess(pProcess, PROCESS_ALL_ACCESS, &procAttr, &cid);
		if (status) {
			///Most likely STATUS_ACCESS_DENIED if
			///either we didn't specify the useDebugPrivilege flag when opening a cross session process
			///or if we tried to open an elevated process while running non-elevated
			///or if the process being opened is a so-called "Protected Process".

			///In x64 windows, HIPS or AV drivers have the possibility to legally
			///receive a notification if a process is about to open a handle to another process.
			///In those ObCallback routines they cannot completely deny the opening.
			///However, they are able to modify the access masks, so a handle supposed for VM operations still
			///will be lacking the PROCESS_VM_XXX rights, for example. If we therefore query the handle rights
			///we can still return an appropriate error if wasn't granted the rights we want
			///And are not going to fail at first when performing our process operations.
			*pProcess = NULL;
			break;
		}

		status = NtQueryObject(*pProcess, ObjectBasicInformation, &processHandleInfo, sizeof(OBJECT_BASIC_INFORMATION), &obQueryLen);
		if (status)	///Not sure if this call ever will fail...
			break;

		///Maybe, HIPS just wanted to deny PROCESS_TERMINATE/PROCESS_SUSPEND right?
		///If so, we don't care. We're only interested in VM rights.
		if (MIN_VM_ACCESS_MASK & ~processHandleInfo.GrantedAccess) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}
	} while (status);

	if (status && pProcess) {
		if (*pProcess) {
			NtClose(*pProcess);
			*pProcess = NULL;
		}
	}

	if (pProcListHead) {
		memSize = 0;
		NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, &memSize, MEM_RELEASE); ///We don't need the list anymore.
	}

	if (useDebugPrivilege)
		RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, oldValue, FALSE, &oldValue);		///We don't need the privilege anymore.

	return status;
}

void mymain(void) {
//	__debugbreak();
	ULONG_PTR originalNtUserGetUpdateRect = (ULONG_PTR)0x00007ff9e5e02900;
	NTSTATUS status = STATUS_PENDING;
	PVOID pDllbase = NULL;
	//ULONG loadflags = LOAD_LIBRARY_SEARCH_SYSTEM32;
	UNICODE_STRING uProc;
	UNICODE_STRING uUser32;
	HANDLE hProc = NULL;
	//dispStatus(NULL, NULL, status);
	RtlInitUnicodeString(&uUser32, L"user32.dll");
	RtlInitUnicodeString(&uProc, L"notepad.exe");
	status = openProcByName(&hProc, &uProc, FALSE);
	//__debugbreak();
	//dispStatus(NULL, NULL, status);
	status = LdrLoadDll(L"\\systemroot\\system32\\", NULL, &uUser32, &pDllbase);
	//myWPrintf
	//dispStatus(NULL, NULL, status);
	//myWPrintf(NULL, L"uivvvzuovzzovozvuvuzivzui");
	//myWPrintf(NULL, L"uixcvui");
	//myWPrintf(NULL, L"uixceq");
	//__debugbreak();
	setNtHook(hProc, (ULONG_PTR)originalNtUserGetUpdateRect, (ULONG_PTR)newNtUserGetUpdateRect);
	myWPrintf(L"uiibbiubiouvvuavvasdasdvsvdaasdvzivzui");
	//setHook(hProc);
	NtSuspendProcess(NtCurrentProcess(), status);
}
//__declspec(noinline) NTSTATUS setNtHook(HANDLE hProcess, ULONG_PTR originalNtFunc, ULONG_PTR newNtFunc) {
//	NTSTATUS status = STATUS_SUCCESS;
//	//status = (NTSTATUS)(ULONG_PTR)hProcess * (ULONG)(ULONG_PTR)newNtFunc - (ULONG)(ULONG_PTR)&originalNtFunc;
//	//BOOLEAN s_dispatchCodeCopied = FALSE;
//	//__debugbreak();
//	myWPrintf(NULL, L"zuucczuzozvi");
//	//myWPrintf(NULL, L"ui");
//	//myWPrintf(NULL, L"i");
//	//do {
//	//	if (!hProcess || !originalNtFunc || !newNtFunc) {
//	//		status = STATUS_INVALID_PARAMETER;
//	//		break;
//	//	}
//
//	//	if (SYSCALL_STUB_MAGIC != *(PULONG)originalNtFunc) {
//	//		status = STATUS_INVALID_SYSTEM_SERVICE;
//	//		break;
//	//	}
//
//	//	if (!s_dispatchCodeCopied) {
//	//		status = copyDispatchCode(hProcess, NULL);
//	//		if (status)
//	//			break;
//	//	}
//
//	//} while (status);
//	////dispStatus(NULL, NULL, status);
//	return status;
//}

//__declspec(noinline) ULONG_PTR getSomeAddress(ULONG_PTR ptr1) {
//	myWPrintf(NULL, L"someNextOutput");
//	return (ULONG_PTR)&getSomeAddress - (ULONG)ptr1;
//}

//void mymain(void) {
//	ULONG status = (ULONG)STATUS_SUCCESS;
//	myWPrintf(L"some first out%put", mymain);
//	status = (ULONG)getSomeAddress();
//	NtTerminateProcess(NtCurrentProcess(), status);
//}
