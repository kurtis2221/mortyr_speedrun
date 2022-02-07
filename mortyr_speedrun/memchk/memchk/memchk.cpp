// memchk.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

MEMCHK_API int checkaccess(int address)
{
	MEMORY_BASIC_INFORMATION lpBuffer;
	unsigned int *addr = (unsigned int*)address;
	int res = VirtualQuery(addr, &lpBuffer, 0x100);
	return res != 0 && lpBuffer.State != MEM_FREE &&
	(
		lpBuffer.Protect == PAGE_EXECUTE_READWRITE ||
		lpBuffer.Protect == PAGE_READWRITE
	);
}