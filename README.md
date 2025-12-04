# ReflectiveLoader-TODO-Rename-
Multipurpose Loader:
Reflective Loader for DLLs, Stripped DLLs, and Position Independent Code

# Order Flow
- stager
  - locates the reflective loader function offset inside host.dll
  - allocates rwx memory
  - copies raw bytes of host.dll into that newly allocated memory
  - jumps into host.dll's exported ReflectiveLoader()
- host.dll
  - find current module's (host.dll) own in-memory base address
  - parses its own PE headers
  - maps itself into a new memory region
    - copy headers
    - copy sections (.text, .data, .rdata)
  - fixes relocations
  - resolve imports
  - sets memory protections
  - calls its own DllMain(DLL_PROCESS_ATTACH)
- host.dll::DllMain(DLL_PROCESS_ATTACH)
  - setup globals
  - initalize hap or scratch buffers
  - start a new worker thread
  - 
- host.dll::HostEntryPoint() (the real host.dll main function)
  - inialize cyryptography
  - - intialize ipc/state
  - initilaize comms / server connections (if not offline)
  - decrypt and decode payload.dll/engine.dll from .data section or whatever section it is stored in
  - Call ManualMapEngine
 - host.dll::ManualMapEngine()
   - allocates memory for payload.dll/engine.dll
   - applies relocations
   - resolve imports
   - handle tls callbacks
   - calls payload.dll/engine.dll's DllMain(DLL_PROCESS_ATTACH)
- payload.dll/engine.dll
    - does whatever logic is defined in payload.dll/engine.dll
