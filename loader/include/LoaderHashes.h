#ifndef ADRENOCHROME_LOADER_HASHES_H
#define ADRENOCHROME_LOADER_HASHES_H

// TODO: rename file to be something like func/module hashes and move to common/ ?

// TODO: ideally these would be computed "on the fly" in c++
// by using a constexpr function
#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534C0AB8

///////////////////////////////////////////////////
#define HASH_KEY						13
//===============================================================================================//


#endif