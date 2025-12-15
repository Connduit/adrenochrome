#ifndef ADRENOCHROME_UTILS_H
#define ADRENOCHROME_UTILS_H

#define DEREF( name  )*(UINT_PTR *)(name)
#define DEREF_64( name  )*(DWORD64 *)(name)
#define DEREF_32( name  )*(DWORD *)(name)
#define DEREF_16( name  )*(WORD *)(name)
#define DEREF_8( name  )*(BYTE *)(name)

#endif