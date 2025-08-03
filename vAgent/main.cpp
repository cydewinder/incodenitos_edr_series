#include <stdio.h>
#include <Windows.h>
#include <thread>
#include <iostream>
#include <filesystem>

bool LoadService(const std::string& szServiceName, const std::string& szServiceDisplayName, const std::string& szServiceFile) {
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hSCManager) {
		printf("OpenSCManager Failed, Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		return false;
	}

	hService = CreateServiceA(hSCManager, szServiceName.c_str(), szServiceDisplayName.c_str(), SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szServiceFile.c_str(), NULL, NULL, NULL, NULL, NULL);
	if (!hService) {
		printf("CreateServiceA Failed, Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		CloseServiceHandle(hService);
		return false;
	}
	return true;
}

bool StartKernelService(const std::string& szServiceName) {
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager) {
		printf("OpenSCManager Failed, Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		return false;
	}

	hService = OpenServiceA(hSCManager, szServiceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
	if (!hService) {
		printf("OpenServiceA Failed, Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		CloseServiceHandle(hService);
		return false;
	}
	if (StartServiceA(hService, 0, NULL) == FALSE) {
		printf("StartServiceA Failed, Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		CloseServiceHandle(hService);
		return false;
	}
	return true;
}

void HandleClientConnection(HANDLE hPipe) {
	char buffer[1024];
	DWORD bytesRead;

	while (true) {
		BOOL result = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
		if (!result || bytesRead == 0) {
			break;
		}
		buffer[bytesRead] = '\0';
		std::cout << "Received from DLL: " << buffer << std::endl;
	}
}

void StartNamedPipeServer() {
	while (true) {
		SECURITY_ATTRIBUTES sa;
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = (PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
		sa.bInheritHandle = TRUE;

		if (!InitializeSecurityDescriptor(sa.lpSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION)) {
			printf("Failed to initialize security descriptor\n");
			return;
		}

		if (!SetSecurityDescriptorDacl(sa.lpSecurityDescriptor, TRUE, (PACL)NULL, FALSE)) {
			printf("Failed to set security descriptor acl\n");
			return;
		}

		HANDLE hPipe = CreateNamedPipe(
			TEXT("\\\\.\\pipe\\HookPipe"),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			1024,
			1024,
			0,
			&sa
		);

		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("Failed to create named pipe\n");
			return;
		}

		printf("Waiting for client connection\n");
		BOOL isConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		if (isConnected) {
			printf("Client connected. Spanwing handler thread\n");
			std::thread clientThread(HandleClientConnection, hPipe);
			clientThread.detach();
		}
		else {
			CloseHandle(hPipe);
		}
	}
}

bool StartETWConsumer() {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Path to your ETW consumer executable
	const char* exePath = "C:\\Users\\setup\\source\\repos\\EDR_Test\\x64\\Debug\\etw_test.exe";

	// Create the process
	if (CreateProcessA(
		exePath,           // Application name
		NULL,              // Command line arguments
		NULL,              // Process security attributes
		NULL,              // Thread security attributes
		FALSE,             // Inherit handles
		0,                 // Creation flags
		NULL,              // Environment
		NULL,              // Current directory
		&si,               // Startup info
		&pi                // Process info
	)) {
		std::cout << "ETW Consumer started successfully!" << std::endl;
		std::cout << "Process ID: " << pi.dwProcessId << std::endl;

		// Close handles (process continues running)
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return true;
	}
	else {
		DWORD error = GetLastError();
		std::cout << "Failed to start ETW Consumer. Error: " << error << std::endl;
		return false;
	}
}

int main(int argc, char* argv[]) {
	BOOL bKernel = FALSE; //this logic can be activated if we want to differentiate turn off the apc injection being done by the kernel.
	if (argc == 2 && std::string(argv[1]) == "kernel") {
		bKernel = TRUE;
	}
	else {
		bKernel = FALSE;
	}
	if (bKernel) {
		std::string szServiceFile = "C:\\EDR_Test\\vDriver.sys";
		std::string szServiceName = "VEDR Kernel";

		if (!std::filesystem::exists(szServiceFile)) {
			printf("!!!Driver File does not exist!\n", szServiceFile.c_str());
			return 0;
		} //checking to see if our driver file exists.

		printf("Driver: %s\n", szServiceFile.c_str());
		printf("Service Name: %s\n", szServiceName.c_str());
		printf("Attempting to start vedr kernel service: %s\n", szServiceName.c_str());
		if (LoadService(szServiceName, szServiceName, szServiceFile) == FALSE) {
			printf("Error occured loading kernel service\n");
		}

		if (StartKernelService(szServiceName) == FALSE) {
			printf("An error occured starting the kernel service\n");
		}

		printf("VEDR driver loaded and running\n");

	}
	printf("Starting Named Pipe Server\n");

	//testing etw_consumer3 load (not working!!!)
	//HMODULE hDll = LoadLibrary(L"C:\\Users\\setup\\source\\repos\\EDR_Test\\x64\\Debug\\etw_consumer3.dll");
	//if (!hDll) {
	//	std::cerr << "Failed to load DLL\n";
	//	return 1;
	//}
	//end testing etw_consumer3 load

	//testing starting etw_test.exe

	//end testing starting etw_test.exe
	StartETWConsumer();
	//start named pipe server

	StartNamedPipeServer();


	return 0;
}