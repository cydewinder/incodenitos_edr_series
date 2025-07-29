#include "driver.h"

PVOID pLoadLibraryExA = { 0 };

PVOID ApcKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* SystemArgument1, PVOID* SystemArgument2, PVOID* Context) {
	UNREFERENCED_PARAMETER(Apc);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Context);

	ExFreePool(Apc);
	return;
}

NTSTATUS DllInject(HANDLE ProcessId, PEPROCESS PeProcess, PETHREAD PeThread, BOOLEAN Alert) {
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(PeProcess);
	UNREFERENCED_PARAMETER(PeThread);
	UNREFERENCED_PARAMETER(Alert);

	NTSTATUS status;
	CHAR ProcessName[256] = { 0 };
	KdPrint(("[Dll inject] Starting DLL Injection for Process id: %p\n", ProcessId));

	HANDLE hProcess;
	OBJECT_ATTRIBUTES objectAttributes = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID clientId;

	InitializeObjectAttributes(&objectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL, );

	clientId.UniqueProcess = PsGetProcessId(PeProcess); ProcessId;
	clientId.UniqueThread = (HANDLE)0;

	KdPrint(("[Dll inject] Attempting to open process: %p\n", ProcessId));

	status = ZwOpenProcess(&hProcess,
		PROCESS_ALL_ACCESS,
		&objectAttributes,
		&clientId);

	if (!NT_SUCCESS(status)) {
		KdPrint(("[Dll inject] Error opening process: %p\n", ProcessId));
		return STATUS_NO_MEMORY;
	}

	KdPrint(("[Dll inject] Successfully opened process: %p\n", ProcessId));
	CHAR DllFormatPath[] = "C:\\EDR_Test\\vhook.dll";
	SIZE_T Size = strlen(DllFormatPath) + 1;
	PVOID pvMemory = NULL;
	KdPrint(("[Dll inject] Allocating memory in target process: %p\n", ProcessId));

	status = ZwAllocateVirtualMemory(hProcess, &pvMemory, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!(NT_SUCCESS(status))) {
		KdPrint(("[Dll inject] Error allocating memory at: %p\n", pvMemory));
		ZwClose(hProcess);
		return STATUS_NO_MEMORY;
	}
	KdPrint(("[Dll inject] Successfully allocated memory at: %p\n", pvMemory));

	KAPC_STATE KasState;
	PKAPC Apc;

	KeStackAttachProcess(PeProcess, &KasState);
	strcpy(pvMemory, DllFormatPath);
	KdPrint(("[Dll inject] DLL path copied to allocted memory\n"));
	KdPrint(("[Dll inject] Deteaching from process\n"));
	KeUnstackDetachProcess(&KasState);
	Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
	if (Apc) {
		KdPrint(("[Dll inject] APC allocated, Initializing\n"));

		KeInitializeApc(Apc,
			PeThread,
			0,
			(PKKERNEL_ROUTINE)ApcKernelRoutine,
			0,
			(PKNORMAL_ROUTINE)pLoadLibraryExA,
			UserMode,
			pvMemory);

		KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
		KdPrint(("[Dll inject] APC successfully queued.\n"));
		return STATUS_SUCCESS;
	}
	KdPrint(("[Dll inject] Failed to queue APC.\n"));
	return STATUS_NO_MEMORY;
}

VOID WorkerRoutine(PVOID Context) {
	UNREFERENCED_PARAMETER(Context);
	DllInject(&((P_INJECTION_DATA)Context)->ProcessId, ((P_INJECTION_DATA)Context)->Process, ((P_INJECTION_DATA)Context)->Ethread, FALSE);
	KdPrint(("[Dll inject] DLL injection complete, setting event.\n"));

	KeSetEvent(&((P_INJECTION_DATA)Context)->Event, (KPRIORITY)0, FALSE);
	return;
}

VOID NTAPI ApcInjectorRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* SystemArgument1, PVOID* SystemArgument2, PVOID* Context) {
	UNREFERENCED_PARAMETER(Apc);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Context);

	KdPrint(("[Apc injector routine] Starting APC Injection routine\n"));

	INJECTION_DATA Id;

	RtlSecureZeroMemory(&Id, sizeof(INJECTION_DATA));
	ExFreePool(Apc);

	Id.Ethread = KeGetCurrentThread();
	Id.Process = IoGetCurrentProcess();

	KdPrint(("[Apc injector routine] EThread: %p, Process %p, Process ID: %p\n", Id.Ethread, Id.Process, Id.ProcessId));

	KeInitializeEvent(&Id.Event, NotificationEvent, FALSE);
	ExInitializeWorkItem(&Id.WorkItem, (PWORKER_THREAD_ROUTINE)WorkerRoutine, &Id);

	KdPrint(("[Apc injector routine] Queeing Work Item\n"));

	ExQueueWorkItem(&Id.WorkItem, DelayedWorkQueue);
	KeWaitForSingleObject(&Id.Event, Executive, KernelMode, TRUE, 0);

	KdPrint(("[Apc injector routine] Work Item Completed\n"));
	return;
}

PVOID CustomGetProcAddress(PVOID pModuleBase, UNICODE_STRING functionName) {
	UNREFERENCED_PARAMETER(functionName);
	// Check PE header for magic bytes
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	// Check PE header for signature
	PIMAGE_NT_HEADERS ImageNtHeaders = ((PIMAGE_NT_HEADERS)(RtlOffsetToPointer(pModuleBase, ImageDosHeader->e_lfanew)));
	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	// Check Optional Headers
	if (!(ImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress &&
		0 < ImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes)) {
		return NULL;
	}
	// Get address of Export directory
	PIMAGE_EXPORT_DIRECTORY ImageExport = (((PIMAGE_EXPORT_DIRECTORY)(PUCHAR)RtlOffsetToPointer(pModuleBase, ImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress)));
	// Check for export directory
	if (!(ImageExport))
	{
		return NULL;
	}
	PULONG AddressOfNames = ((PULONG)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfNames));
	for (ULONG n = 0; n < ImageExport->NumberOfNames; ++n)
	{
		LPSTR FunctionName = ((LPSTR)RtlOffsetToPointer(pModuleBase, AddressOfNames[n]));
		if (strcmp("LoadLibraryExA", FunctionName) == 0) {
			PULONG AddressOfFunctions = ((PULONG)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfFunctions));
			PUSHORT AddressOfOrdinals = ((PUSHORT)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfNameOrdinals));

			PVOID pFnLoadLibraryExA = ((PVOID)RtlOffsetToPointer(pModuleBase, AddressOfFunctions[AddressOfOrdinals[n]]));

			KdPrint(("[CustomGetProcAddress] Found Function %s @ %p\n", FunctionName, pFnLoadLibraryExA));

			return pFnLoadLibraryExA;
		}
	}
	return NULL;
}


void LoadImageNotifyRoutine(IN PUNICODE_STRING ImageName, IN HANDLE ProcessId, IN PIMAGE_INFO pImageInfo) {
	UNREFERENCED_PARAMETER(ImageName);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(pImageInfo);

	if (ImageName == NULL) {
		return;
	}

	UNICODE_STRING exeExtension;
	RtlInitUnicodeString(&exeExtension, L".exe");
	if (RtlSuffixUnicodeString(&exeExtension, ImageName, TRUE)) {
		KdPrint(("[LoadImageNotifyRoutine] Full image name detected: %wZ for process ID %p\n", ImageName, ProcessId));
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageInfo->ImageBase;
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pImageInfo->ImageBase + dosHeader->e_lfanew);
		if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
			if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
				KdPrint(("[Loadimagenotifyroutine] x86 image detected: %wZ\n", ImageName));
				return;
			}
		}
	}

	WCHAR kernel32mask[] = L"*\\KERNEL32.DLL";
	UNICODE_STRING kernel32unicodeString;
	RtlInitUnicodeString(&kernel32unicodeString, kernel32mask);
	if (!(FsRtlIsNameInExpression(&kernel32unicodeString, ImageName, TRUE, NULL))) {
		return;
	}
	KdPrint(("[LoadImageNotifyRoutine] kernel32.dll loaded into process\n"));
	KdPrint(("[LoadImageNotifyRoutine] Atempting to resolve LoadLibraryExA\n"));

	pLoadLibraryExA = CustomGetProcAddress((PVOID)pImageInfo->ImageBase, kernel32unicodeString);

	KdPrint(("[LoadImageNotifyRoutine] LoadLibraryExA resolved: %p\n", pLoadLibraryExA));
	KdPrint(("[LoadImageNotifyRoutine] Image path available, proceeding to inject dll\n"));

	PKAPC Apc;
	Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
	if (!Apc) {
		KdPrint(("[LoadImageNotifyRoutine] Failed to allocate APC\n"));
		return;
	}
	KdPrint(("[LoadImageNotifyRoutine] Allocating and Initializing APC for dll injection\n"));

	KeInitializeApc(Apc, KeGetCurrentThread(), OriginalApcEnvironment, (PKKERNEL_ROUTINE)ApcInjectorRoutine, 0, 0, KernelMode, 0);
	if (KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT)) {
		KdPrint(("[LoadImageNotifyRoutine] APC successfully queued for dll injection\n"));
	}
	else {
		KdPrint(("[LoadImageNotifyRoutine] Failed to queue apc for dll injection\n"));
	}
}


void NTAPI DriverUnload(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);

	PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
	KdPrint(("Driver successfully unloaded\n"));
}


NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	KdPrint(("Driver Loaded\n"));

	NTSTATUS status;
	status = STATUS_SUCCESS;

	KdPrint(("Registering LoadImageNotifyRoutine\n"));
	PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);

	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;

	return status;

}