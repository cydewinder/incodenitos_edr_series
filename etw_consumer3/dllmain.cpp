#include "pch.h"
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <vhook/logger.hpp>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// AMSI ETW Provider GUID: {2A576B87-09A7-520E-C21A-4942F0271D67}
static const GUID AMSI_PROVIDER_GUID =
{ 0x2A576B87, 0x09A7, 0x520E, { 0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67 } };

class AMSIEventConsumer {
private:
    TRACEHANDLE sessionHandle;
    EVENT_TRACE_LOGFILE trace;
    std::wstring sessionName;
    bool isRunning;

public:
    AMSIEventConsumer() : sessionHandle(0), isRunning(false) {
        sessionName = L"AMSIConsumerSession";
        ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
    }

    ~AMSIEventConsumer() {
        Stop();
    }

    // Check if content appears to be PowerShell (Unicode version)
    static bool IsPowerShellContent(const std::wstring& content) {
        if (content.empty()) return false;

        return (content.find(L"$") != std::wstring::npos ||
            content.find(L"Get-") != std::wstring::npos ||
            content.find(L"Set-") != std::wstring::npos ||
            content.find(L"New-") != std::wstring::npos ||
            content.find(L"Invoke-") != std::wstring::npos ||
            content.find(L"powershell") != std::wstring::npos ||
            content.find(L"pwsh") != std::wstring::npos ||
            content.find(L"-Command") != std::wstring::npos ||
            content.find(L"-EncodedCommand") != std::wstring::npos ||
            content.find(L"[System.") != std::wstring::npos ||
            content.find(L"Add-Type") != std::wstring::npos ||
            content.find(L"Write-Host") != std::wstring::npos ||
            content.find(L"Write-Output") != std::wstring::npos ||
            content.find(L"Import-Module") != std::wstring::npos ||
            content.find(L"Export-") != std::wstring::npos ||
            content.find(L"Select-") != std::wstring::npos ||
            content.find(L"Where-") != std::wstring::npos ||
            content.find(L"ForEach-") != std::wstring::npos ||
            content.find(L"Out-") != std::wstring::npos ||
            content.find(L"ConvertTo-") != std::wstring::npos ||
            content.find(L"ConvertFrom-") != std::wstring::npos);
    }

    // Check if content appears to be PowerShell (ANSI version)
    static bool IsPowerShellContent(const std::string& content) {
        if (content.empty()) return false;

        return (content.find("$") != std::string::npos ||
            content.find("Get-") != std::string::npos ||
            content.find("Set-") != std::string::npos ||
            content.find("New-") != std::string::npos ||
            content.find("Invoke-") != std::string::npos ||
            content.find("powershell") != std::string::npos ||
            content.find("pwsh") != std::string::npos ||
            content.find("-Command") != std::string::npos ||
            content.find("-EncodedCommand") != std::string::npos ||
            content.find("[System.") != std::string::npos ||
            content.find("Add-Type") != std::string::npos ||
            content.find("Write-Host") != std::string::npos ||
            content.find("Write-Output") != std::string::npos ||
            content.find("Import-Module") != std::string::npos ||
            content.find("Export-") != std::string::npos ||
            content.find("Select-") != std::string::npos ||
            content.find("Where-") != std::string::npos ||
            content.find("ForEach-") != std::string::npos ||
            content.find("Out-") != std::string::npos ||
            content.find("ConvertTo-") != std::string::npos ||
            content.find("ConvertFrom-") != std::string::npos);
    }

    // Enhanced binary parsing function
    static void ParseBinaryForStrings(PBYTE data, DWORD size, LPCWSTR propertyName) {
        // Method 1: Look for null-terminated Unicode strings
        for (DWORD i = 0; i < size - 3; i += 2) {
            if (i + 1 < size) {
                PWCHAR wstr = (PWCHAR)(data + i);
                DWORD len = 0;

                // Find length of potential Unicode string
                while (i + (len * 2) + 1 < size && wstr[len] != 0 &&
                    wstr[len] >= 32 && wstr[len] < 65536) {
                    len++;
                    if (len > 1000) break; // Reasonable limit
                }

                if (len >= 4) { // Minimum meaningful string length
                    std::wstring candidate(wstr, len);
                    if (IsPowerShellContent(candidate)) {
                        std::wcout << L"*** POWERSHELL IN BINARY (Unicode) ***" << std::endl;
                        std::wcout << L"Property: " << propertyName << std::endl;
                        std::wcout << L"Offset: " << i << L" Length: " << len << std::endl;
                        std::wcout << L"Content: " << candidate << std::endl;
                        std::wcout << L"*** END BINARY POWERSHELL ***\n" << std::endl;
                    }
                    i += (len * 2); // Skip past this string
                }
            }
        }

        // Method 2: Look for null-terminated ANSI strings
        for (DWORD i = 0; i < size - 1; i++) {
            if (data[i] >= 32 && data[i] < 127) {
                DWORD len = 0;
                while (i + len < size && data[i + len] != 0 &&
                    data[i + len] >= 32 && data[i + len] < 127) {
                    len++;
                    if (len > 1000) break; // Reasonable limit
                }

                if (len >= 4) {
                    std::string candidate((char*)(data + i), len);
                    if (IsPowerShellContent(candidate)) {
                        std::wcout << L"*** POWERSHELL IN BINARY (ANSI) ***" << std::endl;
                        std::wcout << L"Property: " << propertyName << std::endl;
                        std::wcout << L"Offset: " << i << L" Length: " << len << std::endl;
                        std::wcout << L"Content: ";
                        std::cout << candidate << std::endl;
                        std::wcout << L"*** END BINARY POWERSHELL ***\n" << std::endl;
                    }
                    i += len; // Skip past this string
                }
            }
        }

        // Method 3: Look for UTF-8 encoded strings
        for (DWORD i = 0; i < size - 3; i++) {
            if (data[i] >= 32 && data[i] < 127) {
                DWORD len = 0;
                bool validUtf8 = true;

                // Simple UTF-8 validation and length calculation
                while (i + len < size && data[i + len] != 0 && validUtf8) {
                    BYTE c = data[i + len];
                    if (c < 128) {
                        len++;
                    }
                    else if ((c & 0xE0) == 0xC0) {
                        if (i + len + 1 < size && (data[i + len + 1] & 0xC0) == 0x80) {
                            len += 2;
                        }
                        else {
                            validUtf8 = false;
                        }
                    }
                    else if ((c & 0xF0) == 0xE0) {
                        if (i + len + 2 < size &&
                            (data[i + len + 1] & 0xC0) == 0x80 &&
                            (data[i + len + 2] & 0xC0) == 0x80) {
                            len += 3;
                        }
                        else {
                            validUtf8 = false;
                        }
                    }
                    else {
                        validUtf8 = false;
                    }

                    if (len > 1000) break; // Reasonable limit
                }

                if (len >= 4 && validUtf8) {
                    std::string candidate((char*)(data + i), len);
                    if (IsPowerShellContent(candidate)) {
                        std::wcout << L"*** POWERSHELL IN BINARY (UTF-8) ***" << std::endl;
                        std::wcout << L"Property: " << propertyName << std::endl;
                        std::wcout << L"Offset: " << i << L" Length: " << len << std::endl;
                        std::wcout << L"Content: ";
                        std::cout << candidate << std::endl;
                        std::wcout << L"*** END BINARY POWERSHELL ***\n" << std::endl;
                    }
                    i += len; // Skip past this string
                }
            }
        }
    }

    // Enhanced PowerShell command extraction with better binary parsing
    static void ExtractPowerShellContent(PEVENT_RECORD eventRecord) {
        DWORD bufferSize = 0;
        PTRACE_EVENT_INFO eventInfo = nullptr;

        // Get required buffer size
        DWORD status = TdhGetEventInformation(eventRecord, 0, nullptr, eventInfo, &bufferSize);
        if (status != ERROR_INSUFFICIENT_BUFFER) return;

        // Allocate buffer and get event information
        eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (eventInfo == nullptr) return;

        status = TdhGetEventInformation(eventRecord, 0, nullptr, eventInfo, &bufferSize);
        if (status != ERROR_SUCCESS) {
            free(eventInfo);
            return;
        }

        bool foundPowerShellContent = false;

        // Look for PowerShell-related content in ALL properties
        for (DWORD i = 0; i < eventInfo->TopLevelPropertyCount; i++) {
            EVENT_PROPERTY_INFO& propertyInfo = eventInfo->EventPropertyInfoArray[i];
            LPWSTR propertyName = (LPWSTR)((PBYTE)eventInfo + propertyInfo.NameOffset);

            PROPERTY_DATA_DESCRIPTOR dataDescriptor;
            dataDescriptor.PropertyName = (ULONGLONG)propertyName;
            dataDescriptor.ArrayIndex = ULONG_MAX;
            dataDescriptor.Reserved = 0;

            DWORD propertySize = 0;
            status = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &dataDescriptor, &propertySize);
            if (status != ERROR_SUCCESS) continue;

            std::vector<BYTE> propertyBuffer(propertySize);
            status = TdhGetProperty(eventRecord, 0, nullptr, 1, &dataDescriptor, propertySize, propertyBuffer.data());
            if (status != ERROR_SUCCESS) continue;

            // Check different property types for PowerShell content
            if (propertyInfo.nonStructType.InType == TDH_INTYPE_UNICODESTRING && propertySize >= sizeof(WCHAR)) {
                std::wstring content = (LPCWSTR)propertyBuffer.data();
                if (IsPowerShellContent(content)) {
                    std::wcout << L"\n*** POWERSHELL CONTENT DETECTED ***" << std::endl;
                    std::wcout << L"Property: " << propertyName << std::endl;
                    std::wcout << L"Type: Unicode String" << std::endl;
                    std::wcout << L"Content Length: " << content.length() << L" characters" << std::endl;
                    std::wcout << L"Content:" << std::endl;
                    std::wcout << L"----------------------------------------" << std::endl;
                    std::wcout << content << std::endl;
                    std::wcout << L"----------------------------------------" << std::endl;
                    std::wcout << L"*** END POWERSHELL CONTENT ***\n" << std::endl;
                    foundPowerShellContent = true;
                }
            }
            else if (propertyInfo.nonStructType.InType == TDH_INTYPE_ANSISTRING && propertySize > 0) {
                std::string content = (LPCSTR)propertyBuffer.data();
                if (IsPowerShellContent(content)) {
                    std::wcout << L"\n*** POWERSHELL CONTENT DETECTED ***" << std::endl;
                    std::wcout << L"Property: " << propertyName << std::endl;
                    std::wcout << L"Type: ANSI String" << std::endl;
                    std::wcout << L"Content Length: " << content.length() << L" characters" << std::endl;
                    std::wcout << L"Content:" << std::endl;
                    std::wcout << L"----------------------------------------" << std::endl;
                    std::cout << content << std::endl;
                    std::wcout << L"----------------------------------------" << std::endl;
                    std::wcout << L"*** END POWERSHELL CONTENT ***\n" << std::endl;
                    foundPowerShellContent = true;
                }
            }
            else if (propertyInfo.nonStructType.InType == TDH_INTYPE_BINARY && propertySize > 4) {
                // Deep parsing of binary data for embedded strings
                std::wcout << L"\n=== ANALYZING BINARY PROPERTY: " << propertyName << L" ===" << std::endl;
                std::wcout << L"Binary Size: " << propertySize << L" bytes" << std::endl;

                // Try to parse as different encodings
                ParseBinaryForStrings(propertyBuffer.data(), propertySize, propertyName);
            }
        }

        free(eventInfo);
    }

    // Event record callback function
    static VOID WINAPI EventRecordCallback(PEVENT_RECORD eventRecord) {
        if (eventRecord == nullptr) return;

        std::wcout << L"Event received:" << std::endl;
        std::wcout << L"  Provider: " << std::hex << eventRecord->EventHeader.ProviderId.Data1 << std::endl;
        std::wcout << L"  Event ID: " << eventRecord->EventHeader.EventDescriptor.Id << std::endl;
        std::wcout << L"  Process ID: " << eventRecord->EventHeader.ProcessId << std::endl;
        std::wcout << L"  Thread ID: " << eventRecord->EventHeader.ThreadId << std::endl;
        std::wcout << L"  Timestamp: " << eventRecord->EventHeader.TimeStamp.QuadPart << std::endl;

        // Parse event data if present
        if (eventRecord->UserDataLength > 0) {
            ParseEventData(eventRecord);
            // Also try to extract PowerShell content
            ExtractPowerShellContent(eventRecord);
        }
        std::wcout << L"-------------------" << std::endl;
    }

    // Parse event data using TDH (Trace Data Helper)
    static void ParseEventData(PEVENT_RECORD eventRecord) {
        DWORD bufferSize = 0;
        PTRACE_EVENT_INFO eventInfo = nullptr;

        // Get required buffer size
        DWORD status = TdhGetEventInformation(eventRecord, 0, nullptr, eventInfo, &bufferSize);
        if (status != ERROR_INSUFFICIENT_BUFFER) {
            std::wcout << L"  Failed to get event info buffer size: " << status << std::endl;
            return;
        }

        // Allocate buffer and get event information
        eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (eventInfo == nullptr) {
            std::wcout << L"  Failed to allocate memory for event info" << std::endl;
            return;
        }

        status = TdhGetEventInformation(eventRecord, 0, nullptr, eventInfo, &bufferSize);
        if (status != ERROR_SUCCESS) {
            std::wcout << L"  Failed to get event information: " << status << std::endl;
            free(eventInfo);
            return;
        }

        // Print event name if available
        if (eventInfo->EventNameOffset > 0) {
            std::wcout << L"  Event Name: " << (LPWSTR)((PBYTE)eventInfo + eventInfo->EventNameOffset) << std::endl;
        }

        // Print event properties
        std::wcout << L"  Properties (" << eventInfo->TopLevelPropertyCount << L"):" << std::endl;
        for (DWORD i = 0; i < eventInfo->TopLevelPropertyCount; i++) {
            PrintProperty(eventRecord, eventInfo, i);
        }

        free(eventInfo);
    }

    // Print individual property
    static void PrintProperty(PEVENT_RECORD eventRecord, PTRACE_EVENT_INFO eventInfo, DWORD propertyIndex) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        DWORD propertySize = 0;
        DWORD status;

        if (propertyIndex >= eventInfo->TopLevelPropertyCount) return;

        EVENT_PROPERTY_INFO& propertyInfo = eventInfo->EventPropertyInfoArray[propertyIndex];

        // Get property name
        LPWSTR propertyName = (LPWSTR)((PBYTE)eventInfo + propertyInfo.NameOffset);
        std::wcout << L"    " << propertyName << L": ";

        // Set up property data descriptor
        dataDescriptor.PropertyName = (ULONGLONG)propertyName;
        dataDescriptor.ArrayIndex = ULONG_MAX;
        dataDescriptor.Reserved = 0;

        // Get property size
        status = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &dataDescriptor, &propertySize);
        if (status != ERROR_SUCCESS) {
            std::wcout << L"<Failed to get property size>" << std::endl;
            return;
        }

        // Allocate buffer for property data
        std::vector<BYTE> propertyBuffer(propertySize);
        status = TdhGetProperty(eventRecord, 0, nullptr, 1, &dataDescriptor, propertySize, propertyBuffer.data());
        if (status != ERROR_SUCCESS) {
            std::wcout << L"<Failed to get property data>" << std::endl;
            return;
        }

        // Print property value based on type
        PrintPropertyValue(propertyInfo, propertyBuffer.data(), propertySize);
        std::wcout << std::endl;
    }

    // Print property value based on its type
    static void PrintPropertyValue(const EVENT_PROPERTY_INFO& propertyInfo, PBYTE data, DWORD size) {
        switch (propertyInfo.nonStructType.InType) {
        case TDH_INTYPE_UNICODESTRING:
            if (size >= sizeof(WCHAR)) {
                std::wcout << (LPCWSTR)data;
            }
            break;
        case TDH_INTYPE_ANSISTRING:
            if (size > 0) {
                std::cout << (LPCSTR)data;
            }
            break;
        case TDH_INTYPE_UINT32:
            if (size >= sizeof(UINT32)) {
                std::wcout << *(PUINT32)data;
            }
            break;
        case TDH_INTYPE_UINT64:
            if (size >= sizeof(UINT64)) {
                std::wcout << *(PUINT64)data;
            }
            break;
        case TDH_INTYPE_BINARY:
            std::wcout << L"<Binary data, " << size << L" bytes>";
            break;
        default:
            std::wcout << L"<Unknown type " << propertyInfo.nonStructType.InType << L">";
            break;
        }
    }

    // Start the ETW consumer session
    bool Start() {
        if (isRunning) {
            std::wcout << L"Consumer is already running" << std::endl;
            return false;
        }

        // Stop any existing session with the same name
        Stop();

        // Calculate required buffer size for session properties
        DWORD sessionPropertiesSize = sizeof(EVENT_TRACE_PROPERTIES) +
            (sessionName.length() + 1) * sizeof(WCHAR) +
            sizeof(WCHAR); // For log file name (empty)

        // Allocate and initialize session properties
        std::vector<BYTE> buffer(sessionPropertiesSize);
        PEVENT_TRACE_PROPERTIES sessionProperties = (PEVENT_TRACE_PROPERTIES)buffer.data();

        ZeroMemory(sessionProperties, sessionPropertiesSize);
        sessionProperties->Wnode.BufferSize = sessionPropertiesSize;
        sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        sessionProperties->Wnode.ClientContext = 1; // Use system time
        sessionProperties->Wnode.Guid = AMSI_PROVIDER_GUID;
        sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        sessionProperties->LogFileNameOffset = 0; // No log file

        // Copy session name
        wcscpy_s((LPWSTR)((PBYTE)sessionProperties + sessionProperties->LoggerNameOffset),
            sessionName.length() + 1, sessionName.c_str());

        // Start trace session
        DWORD result = StartTrace(&sessionHandle, sessionName.c_str(), sessionProperties);
        if (result != ERROR_SUCCESS) {
            std::wcout << L"Failed to start trace session: " << result << std::endl;
            return false;
        }

        // Enable the AMSI provider
        result = EnableTraceEx2(sessionHandle, &AMSI_PROVIDER_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
        if (result != ERROR_SUCCESS) {
            std::wcout << L"Failed to enable AMSI provider: " << result << std::endl;
            ControlTrace(sessionHandle, nullptr, sessionProperties, EVENT_TRACE_CONTROL_STOP);
            return false;
        }

        // Set up trace for processing
        trace.LoggerName = const_cast<LPWSTR>(sessionName.c_str());
        trace.LogFileName = nullptr;
        trace.EventRecordCallback = EventRecordCallback;
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

        isRunning = true;
        std::wcout << L"AMSI ETW consumer started successfully" << std::endl;
        return true;
    }

    // Process events (blocking call)
    void ProcessEvents() {
        if (!isRunning) {
            std::wcout << L"Consumer is not running" << std::endl;
            return;
        }

        // Open trace for processing
        TRACEHANDLE traceHandle = OpenTrace(&trace);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
            std::wcout << L"Failed to open trace: " << GetLastError() << std::endl;
            return;
        }

        std::wcout << L"Processing events... Press Ctrl+C to stop" << std::endl;

        // Process trace (this blocks until stopped)
        DWORD result = ProcessTrace(&traceHandle, 1, nullptr, nullptr);
        if (result != ERROR_SUCCESS && result != ERROR_CANCELLED) {
            std::wcout << L"ProcessTrace failed: " << result << std::endl;
        }

        CloseTrace(traceHandle);
    }

    // Stop the consumer session
    void Stop() {
        if (sessionHandle != 0) {
            // Calculate buffer size for stopping
            DWORD sessionPropertiesSize = sizeof(EVENT_TRACE_PROPERTIES) +
                (sessionName.length() + 1) * sizeof(WCHAR) +
                sizeof(WCHAR);

            std::vector<BYTE> buffer(sessionPropertiesSize);
            PEVENT_TRACE_PROPERTIES sessionProperties = (PEVENT_TRACE_PROPERTIES)buffer.data();
            ZeroMemory(sessionProperties, sessionPropertiesSize);
            sessionProperties->Wnode.BufferSize = sessionPropertiesSize;
            sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

            ControlTrace(sessionHandle, sessionName.c_str(), sessionProperties, EVENT_TRACE_CONTROL_STOP);
            sessionHandle = 0;
        }
        isRunning = false;
    }
};

// Console control handler for graceful shutdown
AMSIEventConsumer* g_consumer = nullptr;

BOOL WINAPI ConsoleHandler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        std::wcout << L"\nShutting down..." << std::endl;
        if (g_consumer) {
            g_consumer->Stop();
        }
        return TRUE;
    default:
        return FALSE;
    }
}

//testing worker
int worker() {
    Logger::LogMessage("AMSI ETW Event Consumer\n");
    std::wcout << L"AMSI ETW Event Consumer" << std::endl;
    std::wcout << L"=======================" << std::endl;

    // Check if running as administrator
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        std::wcout << L"Warning: This program should be run as Administrator for best results." << std::endl;
        std::wcout << L"Some events may not be captured without elevated privileges." << std::endl << std::endl;
    }

    AMSIEventConsumer consumer;
    g_consumer = &consumer;

    // Set up console handler for graceful shutdown
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Start the consumer
    if (!consumer.Start()) {
        std::wcout << L"Failed to start AMSI consumer" << std::endl;
        return 1;
    }

    // Process events (this will block)
    consumer.ProcessEvents();

    std::wcout << L"Consumer stopped" << std::endl;
    return 0;
}
//end testing worker

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Sleep(5000);
        Logger::LogMessage("=====TEST FROM ETW Process====\n");
        //MessageBox(NULL, L"Process attach called!", L"DllMain", MB_OK);
        worker();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

