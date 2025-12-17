//===============================================================================================//
// This is a stub for the actual functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "Loader.h"

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE: // TODO: remove? not needed anymore or ever?
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		MessageBoxA(NULL, "LoaderDll.c:: Hello from DllMain!", "Reflective Dll Injection", MB_OK);
		// NOTE: we use CreateRemoteThread() so we can unload the host.dll when we're done?  
		// or maybe we're not at this point yet
		//CreateRemoteThread(); for loadAxe(); (specifically for the engine.axe)
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startEngine, NULL, 0, NULL);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}