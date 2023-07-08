#include<windows.h>
#include<stdio.h>
//远程线程注入
BOOL CheckDebug() {
	BOOL ret;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &ret);
	return ret;
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