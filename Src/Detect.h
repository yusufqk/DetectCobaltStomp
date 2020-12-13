#pragma once

#include <Windows.h>

// Library function prototypes
// ------------------------------------------------------------------------

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength 
	);

// Detect module stomping as implemented by Cobalt Strike
// ------------------------------------------------------------------------

void detect_cobalt_stomp(DWORD pid) {
	// Dynamically resolve a function from Ntdll
	HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(Ntdll, "NtQueryInformationProcess");

	// Init some important stuff
	HANDLE processHandle = NULL;
	PROCESS_BASIC_INFORMATION processBasicInfo = { 0 };
	PPEB pPeb = NULL;
	PEB peb = { 0 };
	NTSTATUS status;
	SIZE_T bytesRead = 0;
	PPEB_LDR_DATA pPebLdrData = NULL;
	PEB_LDR_DATA pebLdrData = { 0 };
	PLIST_ENTRY pListEntry = NULL;
	PLIST_ENTRY pListEntryFirstElement = NULL;
	LDR_DATA_TABLE_ENTRY ldrDataTableEntry = { 0 };
	PWCHAR moduleNameW = NULL;
	int length;
	LPSTR moduleNameA = NULL;
	LPSTR stompedModuleName = NULL;
	LPVOID stompedModuleBaseAddress = NULL;

	// Get handle to target process
	processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (processHandle == NULL) {
		printf("[-] OpenProcess error: %d\n", GetLastError());
		goto cleanup;
	}

	// Get PROCESS_BASIC_INFORMATION of target process
	status = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &processBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), 0);
	if (status != STATUS_SUCCESS) {
		printf("[-] NtQueryInformationProcess error: %X\n", status);
		goto cleanup;
	}

	// Get pointer to PEB
	pPeb = processBasicInfo.PebBaseAddress;

	// Get PEB of target process
	ReadProcessMemory(processHandle, pPeb, &peb, sizeof(PEB), &bytesRead);
	if (bytesRead != sizeof(PEB)) {
		printf("[-] ReadProcessMemory1 error: %d\n", GetLastError());
		goto cleanup;
	}

	// Get pointer to PEB_LDR_DATA
	ReadProcessMemory(processHandle, ((LPBYTE)pPeb + 0x18), &pPebLdrData, sizeof(PPEB_LDR_DATA), &bytesRead);
	if (bytesRead != sizeof(PPEB_LDR_DATA)) {
		printf("[-] ReadProcessMemory2 error: %d\n", GetLastError());
		goto cleanup;
	}

	// Get PEB_LDR_DATA of target process
	ReadProcessMemory(processHandle, pPebLdrData, &pebLdrData, sizeof(PEB_LDR_DATA), &bytesRead);
	if (bytesRead != sizeof(PEB_LDR_DATA)) {
		printf("[-] ReadProcessMemory3 error: %d\n", GetLastError());
		goto cleanup;
	}

	// Get pointer to doubly-linked list containing loaded modules
	pListEntry = (PLIST_ENTRY)((PBYTE)pebLdrData.InMemoryOrderModuleList.Flink - 0x10);

	// Get pointer to first element of list
	pListEntryFirstElement = pListEntry;

	// Loop through all the list entries/loaded modules
	do {
		// Get LDR_DATA_TABLE_ENTRY of target process
		ReadProcessMemory(processHandle, pListEntry, &ldrDataTableEntry, sizeof(LDR_DATA_TABLE_ENTRY), &bytesRead);
		if (bytesRead != sizeof(LDR_DATA_TABLE_ENTRY)) {
			printf("[-] ReadProcessMemory4 error: %d\n", GetLastError());
			goto cleanup;
		}

		// If valid image base address
		if (ldrDataTableEntry.DllBase) {
			// Get name of module
			moduleNameW = (PWCHAR)calloc(ldrDataTableEntry.BaseDllName.MaximumLength, sizeof(wchar_t));
			ReadProcessMemory(processHandle, ldrDataTableEntry.BaseDllName.Buffer, moduleNameW, ldrDataTableEntry.BaseDllName.MaximumLength, NULL);

			// Get length of unicode string
			length = WideCharToMultiByte(CP_UTF8, 0, moduleNameW, -1, NULL, 0, NULL, NULL);
			
			// Allocate memory for ASCII string
			moduleNameA = (LPSTR)calloc(length, sizeof(char));

			// Convert image name from UTF-16 to UTF-8 string
			WideCharToMultiByte(CP_UTF8, 0, moduleNameW, -1, moduleNameA, length, NULL, FALSE);

			// [DEBUG]
			//printf("[+] Module Name: %s\n", moduleNameA);

			// Check if image is marked as EXE in LDR_DATA_TABLE_ENTRY
			if (ldrDataTableEntry.EntryPoint == NULL && ldrDataTableEntry.ImageDll == FALSE) {
				// Reduce a false positive
				if (strcmp(moduleNameA, "ntoskrnl.exe")) {
					stompedModuleName = strdup(moduleNameA);
					stompedModuleBaseAddress = ldrDataTableEntry.DllBase;

					break;
				}
			}

			// Cleanup
			free(moduleNameW);
			free(moduleNameA);
		}

		// Get next module
		pListEntry = (PLIST_ENTRY)((PBYTE)ldrDataTableEntry.InMemoryOrderLinks.Flink - 0x10);

	} while (pListEntry != pListEntryFirstElement);

	// Print the message to console
	if (stompedModuleName) {
		printf("\n\t[+] Traces of Cobalt Strike Module Stomping were found!\n");
		printf("\t[+] Module name: %s\n", stompedModuleName);
		printf("\t[+] Image base address: 0x%p\n\n", stompedModuleBaseAddress);

		// Cleanup
		free(moduleNameA);
		free(moduleNameW);
		free(stompedModuleName);
	}
	else
		printf("\n\t[-] No traces of Cobalt Strike module stomping was found!\n\n");

	// Cleanup
cleanup:
	if (processHandle)
		CloseHandle(processHandle);

	return;
}