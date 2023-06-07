# 反调试基本概念

加壳：能打开看到源代码，但是看不清楚意思
反调试：在打开的过程中或者在调试过程中给调试者阻碍

经典的反调试：
每隔一段时间遍历我当前任务管理器中的进程：
如果存在“ollydbg”；
exit
如果不存在：
继续运行

反调试主要面对的对象：调试器

基本的手段：
识别调试器的特点，如果存在这种特点，那么就退出程序
利用调试器的特点，将这个特点与退出程序相结合



1.几个api
1-1   可以识别visual studio 调试器
``` c++
#include<windows.h>
#include<stdio.h>
BOOL CheckDebug(){
	return IsDebuggerPresent();
}

int main()
{
	if(CheckDebug())
	{
	printf("a");
	}
	else
	{
	printf("b");
	}
	return 0; 
}

```
1-2 远程线程注入（a线程注入b线程，调试b）
``` c++
#include<windows.h>
#include<stdio.h>
BOOL CheckDebug(){
	BOOL ret;
	CheckRemoteDebuggerPresent(GetCurrentProcess(),&ret);
	return ret;
}

int main()
{
	if(CheckDebug())
	{
	printf("a");
	}
	else
	{
	printf("b");
	}
	return 0; 
}


```

上面这两个函数是识别用户态下面的调试器

``` c++
#include<windows.h>
#include<stdio.h>
#include<winternl.h>

typedef NTSTATUS(WINAPI *  NtQueryInfomationProcessPtr)(
HANDLE processHandle,
PROCESSINFOCLASS processInfomationClass,
PVOID processInformation,
ULONG processInformationLength,
PULONG returnLength
);
//_PROCESSINFOCLASS
//进程处于被调试状态时，ProcessDebugPort = 0xffffffff(-1)

bool NtQueryInformationProcessApproach()
{
int debugPort = 0;
HMODULE hModule = LoadLibrary(TEXT("Ntdll.dll"));
NtQueryInfomationProcessPtr NtQueryInfomationProcess = (NtQueryInfomationProcessPtr)GetProcAddress(hModule,"NtQueryInformationProcess");

if(NtQueryInfomationProcess(GetCurrentProcess(),(PROCESSINFOCLASS)7,&debugPort,sizeof(debugPort),NULL))
{
	printf("[ERROR NtQueryInformationProcessApproach] NtQueryInformationProcess failed\n");
}
else
{
	return debugPort ==-1;
}

return false;

}
int main()
{
	if(NtQueryInformationProcessApproach())
	{
	printf("a");
	}
	else
	{
	printf("b");
	}
	return 0; 
}

```

2.GetLastError;如果操作系统

``` c++
#include<windows.h>
#include<stdio.h>
BOOL CheckDebug(){
	DWORD ret = CloseHandle((HANDLE)0X1234);
	//SetLastError
	if(ret !=0 || GetLastError() != ERROR_INVALID_HANDLE){
	return TRUE;
	}
	else
	{
	return FALSE;
	}
}

int main()
{
	if(CheckDebug())
	{
	printf("a");
	}
	else
	{
	printf("b");
	}
	return 0; 
}
```

内核态
利用用户态和内核态的交接点，使得在用户态可以调试
BeingDebugged.cpp
``` c++
#include "kernelmode_antidbg.h"
#include<iostream>
#include "connector.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KUSER_SHARED_VA 0x7FFE0000
#define KUSER_SHARED_SIZE 0x3B8

	inline bool is_kuser_shared_mapped()
	{
		if (IsBadReadPtr((BYTE*)KUSER_SHARED_VA, KUSER_SHARED_SIZE)) {
			std::cerr << "KDB :Failed to retrieve KUSER_SHARED_DATA\n";
			return false;
		}
		return true;
	}
	//from Hidden Bee malware;
	t_kdb_mode is_kernelmode_dbg_enabled() {
		const ULONGLONG KdDebuggerEnable_offset = 0x2d4;
		if (!is_kuser_shared_mapped())
		{
			return KDB_UNKNOWN;
		}
		BYTE* KdDebuggerEnable = (BYTE*)(KUSER_SHARED_VA + KdDebuggerEnable_offset);
		if (*KdDebuggerEnable)
		{
			/*
			this flag is selected if:
			bcdedit /debug on
			*/
			if (*KdDebuggerEnable == 3)
			{
				std::cout << "KDB:Remote enabled! \n";
				return KDB_REMOTE_ENABLED;
			}
			std::cout << "KDB :Local enabled!\n";
			return KDB_LOCAL_ENABLED;
		}
		std::cout << "KDB: Disabled\n";
		return KDB_DISABLED;
	}
#ifdef __cplusplus
}
#endif
```
