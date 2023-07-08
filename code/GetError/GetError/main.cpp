#include<windows.h>
#include<stdio.h>
BOOL CheckDebug() {
	DWORD ret = CloseHandle((HANDLE)0X1234);
	//SetLastError
	if (ret != 0 || GetLastError() != ERROR_INVALID_HANDLE) {
		return TRUE;
	}
	else
	{
		return FALSE;
	}
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
	return 0;
}