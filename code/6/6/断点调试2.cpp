#include <windows.h>
#include<stdio.h>
BOOL CheckDebug2()
{

	CONTEXT context;
	HANDLE hThread = GetCurrentThread();
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread, &context);
	if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
	{
		return TRUE;
	}
	return FALSE;
}
int main()
{
	if (CheckDebug2())
	{
		printf("a");
	}
	else
	{
		printf("b");
	}
	return 0;
}