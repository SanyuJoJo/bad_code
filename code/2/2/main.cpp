#include<windows.h>
#include<stdio.h>
//Զ���߳�ע��
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