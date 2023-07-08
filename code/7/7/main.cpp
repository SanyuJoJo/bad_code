#include<windows.h>
#include<stdio.h>
BOOL CheckDebug()
{

	DWORD time1 = GetTickCount();
	__asm
	{
		mov ecx, 10
		mov edx, 6
		mov ecx, 10
	}
	DWORD time2 = GetTickCount();

	if (time2 - time1 > 0x1A)
	{
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