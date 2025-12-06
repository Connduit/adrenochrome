/* Loader.c */
/*
1. Locate the PE headers
2. allocate memory for the image
3. map sections into the new memory
4. apply relocations
5. resolve imports
6. fix protections
7. run TLS callbacks
8. call the module's entry point (DllMain)
*/

// TODO: this file should be a "bootstrapper" .dll that loads the rawbytes that exist in its .data section. These rawbytes should be the payload.dll


/*
ReflectiveLoader() function that external stager calls
DWORD WINAPI ReflectiveLoader(LPVOID param);
*/

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
/*

TODO: load data that exists 
LoadEngineThread();
    - locates the engine dll bytes inside host.dll's memory storeage

MapModuleFromMemory();

EngineEntry() optional export inide engine dllpoint 


*/
