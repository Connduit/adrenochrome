# Notes
- host.dll equivalent that is referenced in Athena documentation
- contains a manully mapper
- is able to load dlls and .axe files 
    - an .axe file is just a pe-less DLL that has no headers, import table, or section table
    - maybe i make my own custom file type that is just a pe-less dll that also reorganizes a normal pe file's structure
    - .axe files are reconstructed into fully functional in-memory DLLs. it acts exactly like a loaded DLL but only in memory (its DLL format doesn't exist on disk because it lives as .axe file on disk)
    - imports are resolved by hashing

# Features
- custom pe loader that understands the .axe format
- is engine aware meaning it knows where engine.axe is embedded in host.dll (if it is in fact embedded and not living in package.bin or something)
- it can register engine.axe (meaning it can load engine.axe into memory like a normal dll) so other .axe modules (sent from the server or also embedded) can "link" to it or "use" the (exported) functions defined in engine.axe
- exports all of the original functions (this is assuming the installer.dll changes registry of a service to point to our host.dll instead of what it normally should be). and then forward those exports to the real DLL that the installer.dll overwrote with the host.dll
    - Create fake stub functions to avoid heuristic detection of forwarding behavior
- when the host.dll is loaded
    - On a specific exported function call (often DllMain or a custom one (the custom one being the ReflectiveLoader that is called by the installer)), it triggers loading the engine
    - it allocates rwx memory (via VirtualAlloc) to load engine.axe into to be manually mapped
    - spawns a thread into the loader (the loading of engine.axe not host.dll itself) by calling CreateThread, _beginthreadex, or RtlCreateUserThread for engine.axe so it can run independtly of host.dll because we eventually want to unload host.dll 

# TODO
- make another version that doesn't use the "ReflectiveLoader" function and just assumes we will have a loader stub like here: [https://github.com/monoxgas/sRDI/tree/master/ShellcodeRDI](https://github.com/monoxgas/sRDI/tree/master)
- maybe eventually turn host.dll into host.axe? and just write a custom ReflectiveLoader function that knows how to manually map .axe files
