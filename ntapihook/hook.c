/*++


{description}
Copyright(C) { year } {fullname}


This program is free software; you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.


You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110 - 1301 USA.


++*/

#include "global.h"
#include "dispatch.h"

#define SYSCALL_STUB_MAGIC 0xB8D18B4CUL
static BYTE sg_pFullImageHdr[PAGE_SIZE];

NTSTATUS getRtSectionAddress(PULONG_PTR pRtSection, PSIZE_T pSectionSize) {
	MEMORY_BASIC_INFORMATION freeMemInfo;
	MEMORY_BASIC_VLM_INFORMATION imageOrMappingInfo;
	PIMAGE_SECTION_HEADER pCurrSecHdr;
	//USHORT lineNum = 0;
	ULONG oldProt;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pCurrAddress = NULL;
	PIMAGE_NT_HEADERS64 pPeHdr64 = NULL;
	ULONGLONG resultLen = 0;
	BOOLEAN queryFreeMem = FALSE;
	ULONGLONG fullImageHdrSize = PAGE_SIZE;

	PIMAGE_SECTION_HEADER pFirstSecHdr = NULL;

	do {
		if (!pRtSection || !pSectionSize) {
			status = STATUS_ACCESS_VIOLATION;
			break;
		}

		*pRtSection = 0x0;
		*pSectionSize = 0;

		RtlZeroMemory(&freeMemInfo, sizeof(MEMORY_BASIC_INFORMATION));
		RtlZeroMemory(&imageOrMappingInfo, sizeof(MEMORY_BASIC_VLM_INFORMATION));

		for (;;) {
			if (queryFreeMem)
				status = NtQueryVirtualMemory(NtCurrentProcess(), pCurrAddress, MemoryBasicInformation, &freeMemInfo, sizeof(MEMORY_BASIC_INFORMATION), &resultLen);
			else
				status = NtQueryVirtualMemory(NtCurrentProcess(), pCurrAddress, MemoryBasicVlmInformation, &imageOrMappingInfo, sizeof(MEMORY_BASIC_VLM_INFORMATION), &resultLen);
			if (STATUS_INVALID_ADDRESS == status) {
				queryFreeMem = TRUE;
				continue;
			}

			if (status)
				break;

			if (queryFreeMem) {
				pCurrAddress = (PUCHAR)pCurrAddress + freeMemInfo.RegionSize;
				queryFreeMem = FALSE;
				continue;
			}

			else {
				pCurrAddress = (PUCHAR)pCurrAddress + imageOrMappingInfo.SizeOfImage;
				queryFreeMem = FALSE;
			}

			if (MEM_IMAGE != imageOrMappingInfo.Type)
				continue;

			myWPrintf(L"Memory Basic Vlm Info | Found an Image!");
			myWPrintf(L"memVlmInfo.Type: %llX", imageOrMappingInfo.Type);
			myWPrintf(L"memVlmInfo.Protection: %llX", imageOrMappingInfo.Protection);
			myWPrintf(L"memVlmInfo.ImageBase: %p", imageOrMappingInfo.ImageBase);
			myWPrintf(L"memVlmInfo.SizeOfImage: %llX", imageOrMappingInfo.SizeOfImage);
			myWPrintf(L"memVlmInfo.Unknown: %llX", imageOrMappingInfo.Unknown);

			status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&imageOrMappingInfo.ImageBase, &fullImageHdrSize, PAGE_READONLY, &oldProt);
			if (status)
				continue;

			//myWPrintf(L"memVlmInfo.ImageBase: %p", imageOrMappingInfo.ImageBase);
			status = NtReadVirtualMemory(NtCurrentProcess(), (PVOID)imageOrMappingInfo.ImageBase, sg_pFullImageHdr, sizeof(sg_pFullImageHdr), &fullImageHdrSize);
			if (status)
				continue;

			pPeHdr64 = (PIMAGE_NT_HEADERS64)(sg_pFullImageHdr + ((PIMAGE_DOS_HEADER)sg_pFullImageHdr)->e_lfanew);
			if (IMAGE_NT_SIGNATURE != pPeHdr64->Signature)
				continue;

			pFirstSecHdr = IMAGE_FIRST_SECTION(pPeHdr64);
			for (ULONG i = 0; i < pPeHdr64->FileHeader.NumberOfSections; i++) {
				pCurrSecHdr = &pFirstSecHdr[i];
				myWPrintf(L"%lX", pCurrSecHdr->Characteristics);
				if ((pCurrSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrSecHdr->Characteristics & IMAGE_SCN_MEM_READ)) {
					myWPrintf(L"Executable section starts @ %p with size %llX", (imageOrMappingInfo.ImageBase + PAGE_ROUND_DOWN(pCurrSecHdr->VirtualAddress)), pCurrSecHdr->Misc.VirtualSize);
					if(0x3C0 >= pCurrSecHdr->SizeOfRawData % PAGE_SIZE){
						myWPrintf(L"Code cave @ %p found. Likely RT section.", (imageOrMappingInfo.ImageBase + PAGE_ROUND_DOWN(pCurrSecHdr->VirtualAddress)));
						*pRtSection = imageOrMappingInfo.ImageBase + PAGE_ROUND_DOWN(pCurrSecHdr->VirtualAddress) + PAGE_ROUND_DOWN(pCurrSecHdr->Misc.VirtualSize) + 0x3C0;
						*pSectionSize = PAGE_SIZE - 0x3C0;
						break;
					}
					//if (pPeHdr64->FileHeader.NumberOfSections < i) {
					//	
					//}
					//if(0xC20 > pCurrAddres)
					//if (0x3E0 > pCurrSecHdr->SizeOfRawData) {
					//	myWPrintf(L"Code cave @ %p found. Likely RT section.", (imageOrMappingInfo.ImageBase + PAGE_ROUND_DOWN(pCurrSecHdr->VirtualAddress)));
					//	*pRtSection = (imageOrMappingInfo.ImageBase + PAGE_ROUND_DOWN(pCurrSecHdr->VirtualAddress));
					//	*pSectionSize = PAGE_SIZE - 0x3E0;
					//	break;
					//}
				}
			}

			if (*pRtSection) {
				status = STATUS_SUCCESS;
				break;
			}


		}
		if (status)
			break;

	} while (status);

	return status;
}


//NTSTATUS createNtapiLookupTable(PVOID pRawNtdllBase, ULONG_PTR address, ULONG_PTR* pAddressOfFuncRva) {
//	PIMAGE_NT_HEADERS64 pNtdllPeHeader = NULL;
//	ULONG rvaNtdllExportDirectory = 0x0;
//	PIMAGE_EXPORT_DIRECTORY pNtdllExportDirectory = NULL;
//	PULONG pNameRvaArray = NULL;
//	PUSHORT pNameOrdinalArray = NULL;
//	PULONG pFunctionRvaArray = NULL;
//	char* pCurrName = NULL;
//	ULONG rvaCurrentFunction = 0x0;
//	PVOID pDesiredFunctionAddress;
//	SIZE_T currStringLen = 0;
//	char* pCurrPos = NULL;
//	ULONG rva1 = (ULONG)(address - (ULONG_PTR)pRawNtdllBase);
//
//	pNtdllPeHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)pRawNtdllBase + ((PIMAGE_DOS_HEADER)pRawNtdllBase)->e_lfanew);
//	if ((pNtdllPeHeader->Signature != IMAGE_NT_SIGNATURE) ||
//		(pNtdllPeHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
//		(pNtdllPeHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64))
//		return STATUS_INVALID_IMAGE_WIN_64;
//
//	if (!pNtdllPeHeader->OptionalHeader.NumberOfRvaAndSizes)
//		return STATUS_RESOURCE_DATA_NOT_FOUND;
//
//	rvaNtdllExportDirectory = pNtdllPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//	pNtdllExportDirectory = (PIMAGE_EXPORT_DIRECTORY)rvaToFileOffset(rvaNtdllExportDirectory, pRawNtdllBase);
//	if (!pNtdllExportDirectory)
//		return STATUS_NOT_EXPORT_FORMAT;
//
//	pNameRvaArray = (PULONG)rvaToFileOffset(pNtdllExportDirectory->AddressOfNames, pRawNtdllBase);
//	pNameOrdinalArray = (PUSHORT)rvaToFileOffset(pNtdllExportDirectory->AddressOfNameOrdinals, pRawNtdllBase);
//	pFunctionRvaArray = (PULONG)rvaToFileOffset(pNtdllExportDirectory->AddressOfFunctions, pRawNtdllBase);
//	if (!pNameRvaArray || !pNameOrdinalArray || !pFunctionRvaArray)
//		return STATUS_INVALID_IMAGE_FORMAT;
//
//	*pAddressOfFuncRva = 0x0;
//	for (ULONG i = 0; i < pNtdllExportDirectory->NumberOfNames; i++) {
//		if (rva1 == pFunctionRvaArray[pNameOrdinalArray[i]]) {
//			*pAddressOfFuncRva = (ULONG_PTR)&pFunctionRvaArray[pNameOrdinalArray[i]];
//			break;
//		}
//
//	}
//
//
//	return STATUS_SUCCESS;
//}

//NTSTATUS getRtSectionAddress(PULONG_PTR pRtSection) {
//	NTSTATUS status = STATUS_SUCCESS;
//	ULONG_PTR ntdllBase = 0x0;
//	PIMAGE_NT_HEADERS64 pNtdllPeHeader = NULL;
//	ULONG rvaNtdllExportDirectory = 0x0;
//	PIMAGE_EXPORT_DIRECTORY pNtdllExportDirectory = NULL;
//	PULONG pNameRvaArray = NULL;
//	PUSHORT pNameOrdinalArray = NULL;
//	PULONG pFunctionRvaArray = NULL;
//	char* pCurrName = NULL;
//	ULONG rvaCurrentFunction = 0x0;
//	PVOID pDesiredFunctionAddress;
//	SIZE_T currStringLen = 0;
//	char* pCurrPos = NULL;
//	ULONG rva1 = (ULONG)(address - (ULONG_PTR)pRawNtdllBase);
//
//	pNtdllPeHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)pRawNtdllBase + ((PIMAGE_DOS_HEADER)pRawNtdllBase)->e_lfanew);
//	if ((pNtdllPeHeader->Signature != IMAGE_NT_SIGNATURE) ||
//		(pNtdllPeHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
//		(pNtdllPeHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64))
//		return STATUS_INVALID_IMAGE_WIN_64;
//
//	if (!pNtdllPeHeader->OptionalHeader.NumberOfRvaAndSizes)
//		return STATUS_RESOURCE_DATA_NOT_FOUND;
//
//	rvaNtdllExportDirectory = pNtdllPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//	pNtdllExportDirectory = (PIMAGE_EXPORT_DIRECTORY)rvaToFileOffset(rvaNtdllExportDirectory, pRawNtdllBase);
//	if (!pNtdllExportDirectory)
//		return STATUS_NOT_EXPORT_FORMAT;
//
//	pNameRvaArray = (PULONG)rvaToFileOffset(pNtdllExportDirectory->AddressOfNames, pRawNtdllBase);
//	pNameOrdinalArray = (PUSHORT)rvaToFileOffset(pNtdllExportDirectory->AddressOfNameOrdinals, pRawNtdllBase);
//	pFunctionRvaArray = (PULONG)rvaToFileOffset(pNtdllExportDirectory->AddressOfFunctions, pRawNtdllBase);
//	if (!pNameRvaArray || !pNameOrdinalArray || !pFunctionRvaArray)
//		return STATUS_INVALID_IMAGE_FORMAT;
//
//	*pAddressOfFuncRva = 0x0;
//	for (ULONG i = 0; i < pNtdllExportDirectory->NumberOfNames; i++) {
//		if (rva1 == pFunctionRvaArray[pNameOrdinalArray[i]]) {
//			*pAddressOfFuncRva = (ULONG_PTR)&pFunctionRvaArray[pNameOrdinalArray[i]];
//			break;
//		}
//
//	}
//
//
//	return STATUS_SUCCESS;
//
//	do {
//		if (!pRtSection) {
//			status = STATUS_ACCESS_VIOLATION;
//			break;
//		}
//
//		ntdllBase = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)((PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink)->InLoadOrderLinks.Flink)->DllBase;
//
//		//RtlImageNtHeader()
//	} while (status);
//	return status;
//}


NTSTATUS copyDispatchCode(HANDLE hProcess, PULONG_PTR pDestAddress) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR rtSectAddr = 0x0;
	SIZE_T rtSectSize = 0;
	SIZE_T protSize = 0;
	ULONG oldprot = 0x0;
	SIZE_T byteswritten = 0;
	PVOID pProtectBase = NULL;
	SIZE_T sizeOfDispatch = getDispatchEnd() - getDispatchBegin();
	//myWPrintf(L"getDispatchEnd: %p", getDispatchEnd());
	//myWPrintf(L"getDispatchBegin: %p", getDispatchBegin());
	do {
		if (!hProcess) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = getRtSectionAddress(&rtSectAddr, &rtSectSize);
		if (status) {
			rtSectAddr = 0x0;
			myWPrintf(L"getRtSectionAddress failed: %lX", status);
			break;
		}


		myWPrintf(L"code cave start: %p", rtSectAddr);
		pProtectBase = (PVOID)rtSectAddr;
		protSize = rtSectSize;
		NtProtectVirtualMemory(hProcess, &pProtectBase, &protSize, PAGE_EXECUTE_READWRITE, &oldprot);
		NtWriteVirtualMemory(hProcess, (PVOID)rtSectAddr, (PVOID)(getDispatchBegin()), sizeOfDispatch, &byteswritten);
		NtProtectVirtualMemory(hProcess, &pProtectBase, &protSize, oldprot, &oldprot);


	} while (status);

	if (pDestAddress)
		*pDestAddress = rtSectAddr;
	//status = (NTSTATUS)sizeOfDispatch;
	myWPrintf(L"sizeOfDispatch: %lld", sizeOfDispatch);
	//dispStatus(NULL, NULL, status);
	return status;
}


/*++

Routine Description:

This function is used to detour the execution of any NtXxx routine (including graphical system calls)
to a caller-supplied dispatch routine. The caller may then intercept and completely block the call, or it may modify the
pre-op as well as the post-op parameters of the hooked function before returning.
Due to function principle, the original function must start with "0x4C, 0x8B, 0xD1, 0xB8, 0x??, 0x??, 0x00, 0x00"
otherwise detouring will fail with the STATUS_INVALID_SYSTEM_SERVICE error.
It is the caller's responsibility to retrieve the function address of the non-exported graphical system services.

Arguments:

hProcess - Supplies a handle to the process which to place the hook into. The caller
must have PROCESS_VM_OPERATION, PROCESS_VM_WRITE, and PROCESS_VM_READ access to the process.

originalNtFunc - Supplies the address of the pristine NtXxx routine to hook.

newNtFunc - Supplies the address of the new dispatch function the execution should be detoured to.

Return Value:

Returns an NT Status code indicating success or failure of the API

--*/

NTSTATUS setNtHook(HANDLE hProcess, ULONG_PTR originalNtFunc, ULONG_PTR newNtFunc) {
	NTSTATUS status = STATUS_SUCCESS;
	//status = (NTSTATUS)(ULONG_PTR)hProcess * (ULONG)(ULONG_PTR)newNtFunc - (ULONG)(ULONG_PTR)&originalNtFunc;
	static BOOLEAN s_dispatchCodeCopied = FALSE;
	//__debugbreak();
	myWPrintf(L"zuucczuzozvi");
	myWPrintf(L"ui");
	myWPrintf(L"i");
	do {
		if (!hProcess || !originalNtFunc || !newNtFunc) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (SYSCALL_STUB_MAGIC != *(PULONG)originalNtFunc) {
			status = STATUS_INVALID_SYSTEM_SERVICE;
			break;
		}

		if (!s_dispatchCodeCopied) {
			status = copyDispatchCode(hProcess, NULL);
			if (status)
				break;
		}
	} while (status);
	
	//dispStatus(NULL, NULL, status);
	return status;
}

//__declspec(noinline) ULONG_PTR getSomeAddress(void) {
//	myWPrintf(L"someNextOut%put", myWPrintf);
//	return (ULONG_PTR)&getSomeAddress;
//}