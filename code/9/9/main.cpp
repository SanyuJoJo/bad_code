#include<windows.h>
#include<stdio.h>
BOOL CheckDebug()
{
	//断点位置，Windows seh几张
	__try
	{
		__asm int 3
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;

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