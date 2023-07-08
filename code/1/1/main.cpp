#include<windows.h>
#include<stdio.h>
BOOL CheckDebug() {
	return IsDebuggerPresent();
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