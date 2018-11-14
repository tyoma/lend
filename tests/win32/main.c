#include "../../ld32.h"

#include <stdio.h>
#include <Windows.h>
#include <DbgHelp.h>

unsigned read_size(unsigned char *buffer, unsigned buffer_length)
{
	unsigned char *buffer0 = buffer;
	unsigned l = 0;

	for (; buffer_length; buffer += l, buffer_length -= l)
	{
		l = length_disasm(buffer);
		if (l > buffer_length)
			break;
	}
	return buffer - buffer0;
}

static BOOL CALLBACK on_symbol(SYMBOL_INFO *symbol, ULONG size, PVOID ctx)
{
	if (symbol->Tag == 5 /*function*/)
	{
		unsigned l;

		l = read_size((unsigned char *)symbol->Address, symbol->Size);
		if (l != symbol->Size)
			printf("Lengths differ (%s): symbol - %d, disassembled - %d\n", symbol->Name, symbol->Size, l);
	}
	return TRUE;
}

int main(int argc, const char *argv[])
{
	BYTE buffer[1000];

	HANDLE self = NULL, lib = NULL;
	if (argc != 2)
		return -1;

	lib = LoadLibrary(argv[1]);

	self = GetModuleHandle(NULL);
	if (SymInitialize(self, NULL, FALSE))
	{
		DWORD64 base;
		
		base = SymLoadModuleEx(self, NULL, argv[1], NULL, (DWORD64)lib, 0, NULL, 0);
		if (base)
			SymEnumSymbols(self, base, NULL, &on_symbol, 0);
		SymCleanup(self);
	}
	FreeLibrary(lib);
	return 0;
}
