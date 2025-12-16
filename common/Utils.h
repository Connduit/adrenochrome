#ifndef ADRENOCHROME_UTILS_H
#define ADRENOCHROME_UTILS_H

// #include "LoaderHashes.h" // TODO: fix, won't be able to find this file

#define WIN32_LEAN_AND_MEAN
#include <windows.h> // NOTE: needed for __forceinline

#define DEREF( name  )*(UINT_PTR *)(name)
#define DEREF_64( name  )*(DWORD64 *)(name)
#define DEREF_32( name  )*(DWORD *)(name)
#define DEREF_16( name  )*(WORD *)(name)
#define DEREF_8( name  )*(BYTE *)(name)


#define HASH_KEY 13 // TODO: hacky solution

#pragma intrinsic( _rotr )

__forceinline DWORD ror(DWORD d)
{
    return _rotr(d, HASH_KEY);
}

__forceinline DWORD hash(char* c)
{
    register DWORD h = 0;
    do
    {
        h = ror(h);
        h += *c;
    } while (*++c);

    return h;
}

#endif