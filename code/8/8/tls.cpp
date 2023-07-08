#include <stdio.h>
#include <windows.h>

void NTAPI __stdcall TLS_CALLBACKl(PVOID DllHandle, DWORD dwReason, PVOID Reserved);

#ifdef _M_IX86
#pragma comment(linker,"/INCLUDE:__tls_used")
#pragma comment(linker,"/INCLUDE:__tls_callback")
#else
#pragma comment(linker,"/INCLUDE:_tls_used")
#pragma comment(linker,"/INCLUDE:_tls_callback")
#endif

EXTERN_C

#ifdef _M_IX64
#pragma const_seg(".CRT$XLB")
const
#else
#pragma data_seg(".CRT$XLB")
#endif

PIMAGE_TLS_CALLBACK _tls_callback[] = { TLS_CALLBACKl,0 };
#pragma data_seg ()
#pragma const_seg ()

#include <iostream>

void NTAPI __stdcall TLS_CALLBACKl(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	if (IsDebuggerPresent())
	{
		exit(0);
	}
	else {
		printf("1212");
		MessageBox(NULL,L"aaa", L"bbbb", 0);
	}
}

int main(int argc, char* argv[])
{
	printf("233\n");
	return 0;
}