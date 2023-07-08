#include<windows.h>
#include<stdio.h>
#include<tlhelp32.h>
#include<winternl.h>
#undef   UNICODE 
BOOL CheckDebug()
{
	DWORD ID;
	DWORD ret = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	BOOL bMore = Process32First(hProcessSnap, &pe32);
	while (bMore) {
		if (_wcsicmp(pe32.szExeFile, L"OllyDBG.exe") == 0 || _wcsicmp(pe32.szExeFile, L"OllyICE.exe") == 0 || _wcsicmp(pe32.szExeFile, L"x64_dbg.exe") == 0 || _wcsicmp(pe32.szExeFile, L"windbg.exe") == 0 || _wcsicmp(pe32.szExeFile, L"ImmunityDebugger") == 0)
		{
			return TRUE;
		}
		bMore = Process32Next(hProcessSnap, &pe32);

	}
	CloseHandle(hProcessSnap);
	return FALSE;

}
int main()
{
	if (CheckDebug())
	{
		printf("a");
	}
	else
	{
		printf("b");
	}

}
