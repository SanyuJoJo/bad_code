#include<windows.h>
#include<stdio.h>
BOOL CheckDebug()
{
	//�ϵ�λ�ã�Windows seh����
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