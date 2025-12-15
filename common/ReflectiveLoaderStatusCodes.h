#ifndef REFLECTIVE_LOADER_STATUS_CODES_H
#define REFLECTIVE_LOADER_STATUS_CODES_H

#define RDI_ERR_BASE 0xE0000000
#define RDI_SUCCESS (0x00000001)
#define RDI_ERR_FIND_IMAGE_BASE (RDI_ERR_BASE | 0x1000)
#define RDI_ERR_RESOLVE_DEPS (RDI_ERR_BASE | 0x2000) // Generic dependency failure
#define RDI_ERR_ALLOC_MEM (RDI_ERR_BASE | 0x3000)
// Granular codes for dependency resolution:
#define RDI_ERR_NO_KERNEL32 (RDI_ERR_BASE | 0x2100)		 // Failed to find kernel32.dll by hash
#define RDI_ERR_NO_NTDLL (RDI_ERR_BASE | 0x2200)		 // Failed to find ntdll.dll by hash
#define RDI_ERR_NO_EXPORTS (RDI_ERR_BASE | 0x2300)		 // Found kernel32, but couldn't find required exports
#define RDI_ERR_GETSYSCALLS_FAIL (RDI_ERR_BASE | 0x2400) // getSyscalls() failed
// My Custom Codes
#define RDI_ERR_MY_CUSTOM_ERROR (RDI_ERR_BASE | 0x4000) // 
#define RDI_ERR_GET_MODULE_FAILS (RDI_ERR_BASE | 0x5000) // 
#define RDI_ERR_FAKE_SUCCESS (RDI_ERR_BASE | 0x9000) // TODO: remove...
///////////////////////////////////////////////////

#define RDI_ERROR(status) (((status) & 0xF0000000) == 0xE0000000)


#endif
