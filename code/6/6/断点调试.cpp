#include <windows.h>
#include<stdio.h>
//Èí¼þ¶Ïµã

BOOL CheckDebug()
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD dwBaseImage = (DWORD)GetModuleHandle(NULL);
	pDosHeader = (PIMAGE_DOS_HEADER)dwBaseImage;
	pNtHeaders = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(pNtHeaders->Signature) + sizeof(IMAGE_FILE_HEADER) + (WORD)pNtHeaders->FileHeader.SizeOfOptionalHeader);
	DWORD dwAddr = pSectionHeader->VirtualAddress + dwBaseImage;
	DWORD dwCodeSize = pSectionHeader->SizeOfRawData;
	BOOL Found = FALSE;
	__asm
	{
		cld
		mov edi, dwAddr
		mov ecx, dwCodeSize
		mov al, 0CCH
		repne scasb
		jnz NotFound
		mov Found, 1
		NotFound:
	}
	return Found;
}
int main()
{
	__asm int 3

	if (CheckDebug())
	{
		printf("a");
	}
	else
	{
		printf("b");
	}
	return 0;
}