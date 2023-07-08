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

## 4内核态
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
//_KUSER_SHARED_DATA

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
				//windbg 双机调试 一台虚拟机作为被调试的对象
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

connector.h
``` c
#ifndef CONNECTOR_H
#define CONNECTOR_H
#ifdef __cplusplus
extern "C"{
#endif
int find();
#ifdef __cplusplus
}
#endif
#endif
```

kernelmode_antidbg.h
```c
#ifdef __cplusplus
extern "C"{
#endif

#include<Windows.h>

typedef enum kdb_mode{
		KDB_UNKNOWN=(-1),
		KDB_DISABLED = 0,
		KDB_LOCAL_ENABLED = 1,
		KDB_REMOTE_ENABLED = 3
} t_kdb_mode;
t_kdb_mode is_kernelmode_dbg_enabled();
#ifdef __cplusplus
}
#endif
```

main.cpp
```c
#include "connector.h"
#include "kernelmode_antidbg.h"
#include<stdio.h>
BOOL anti_dbg();
int main(int argc,char* argv[]){
	if(anti_dbg() == true){
	printf("[MAIN] No dbg was detected running shellcode ... \n");
	//加载shellcode
	}
	else {
	printf("Exiting ... \n");
	exit(0);
	}

return 0;
}


BOOL anti_dbg(){

if(is_kernelmode_dbg_enabled()==KDB_DISABLED)
{
	printf("dbg is diabled\n");
	return true;
}else if(is_kernelmode_dbg_enabled()==KDB_LOCAL_ENABLED){
	printf("local dbg is running...\n");
	return false;
}else if(is_kernelmode_dbg_enabled()==KDB_REMOTE_ENABLED)
{
	printf("remote dbg is running...\n");
	return false;
}
else{
	printf("Unkown state, possibly is_kernelmode_dbg_enabled faild...\n");
	return false;
}
}
```

### 5窗口程序识别
FindWindowA.cpp
``` c
#include<windows.h>
#include<stdio.h>
#include<tlhelp32.h>
#include<winternl.h>
BOOL CheckDebug()
{
	DWORD ID;
	DWORD ret = 0;
	PROCESSENTRY32 pe32;
	pe32 dwSize=sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32SnapSHOT(TH32CS_SNAPPROCESS,0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	BOOL bMore = Process32First(hProcessSnap,&pe32);
	while(bMore){
	if(_stricmp(pe32.szExeFile,"OllyDBG.exe")==0 || _stricmp(pe32.szExeFile,"OllyICE.exe")==0 || _stricmp(pe32.szExeFile,"x64_dbg.exe")==0 || _stricmp(pe32.szExeFile,"windbg.exe")==0 || _stricmp(pe32.szExeFile,"ImmunityDebugger")==0)
	{
	return TRUE;
	}
	bMore = Process32Next(hProcessSnap,&pe32);
	
	}
	CloseHandle(hProcessSnap);
	return FALSE;

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

}

```
在vs2019中,将相关内容替换
``` c
_wcsicmp(pe32.szExeFile,L"OllyDBG.exe")==0 || _wcsicmp(pe32.szExeFile,L"OllyICE.exe")==0 || _wcsicmp(pe32.szExeFile,L"x64_dbg.exe")==0 || _wcsicmp(pe32.szExeFile,L"windbg.exe")==0 || _wcsicmp(pe32.szExeFile,L"ImmunityDebugger")
```
## 6 断点检查
软件断点--断点检查
``` c
#include <windows.h>
#include<stdio.h>
//软件断点

BOOL CheckDebug()
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD dwBaseImage = (DWORD)GetModuleHandle(NULL);
	pDosHeader = (PIMAGE_DOS_HEADER)dwBaseImage;
	pNtHeaders = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(pNtHeaders->Signature) + sizeof(IMAGE_FILE_HEADER) + (WORD)pNtHeaders->FileHeader.SizeOfOptionalHeader);
	DWORD dwAddr = pSectionHeader->VirtualAddress + dwBaseImage;
	DWORD dwCodeSize = pSectionHeader->SizeOfRawData;
	BOOL Found = FALSE;
	__asm
	{
		cld
		mov edi, dwAddr
		mov ecx, dwCodeSize
		mov al, 0CCH
		repne scasb
		jnz NotFound
		mov Found, 1
		NotFound:
	}
	return Found;
}
int main()
{
	__asm int 3

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
```
硬件断点---断点检查2
``` c
#include <windows.h>
#include<stdio.h>
BOOL CheckDebug2()
{

	CONTEXT context;
	HANDLE hThread = GetCurrentThread();
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hTread,&context);
	if(context.Dr0 !=0 || context.DR1 != 0 || contxt.Dr2 !=0|| contxt.Dr3 !=0)
	{
		return TRUE;
	}
	return FALSE;
}
int main()
{
	if(CheckDebug2())
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
伪造断点
``` c
#include<windows.h>
#include<stdio.h>
BOOL CheckDebug()
{
//断点位置，Windows seh机制
	__try
	{
		__asm int 3
	}
	__except(1)
	{
	return FALSE;
	}
	return TRUE;
	
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

## 7
时间差
程序自己运行会很快，
如果被调试，人的观察分析时间就很长
``` c
#include<windows.h>
#include<stdio.h>
BOOL CheckDebug()
{

	DWORD time1 = GetTickCount();
	__asm
	{
	mov ecx,10
	mov edx,6
	mov ecx,10
	}
	DWORD time2 = GetTickCount();

	if(time2-time1 >0x1A)
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
## 8 tls
tls
ida 可以看到函数详情
ctrl+x
``` c

```

## 9 伪造断点

``` c
#include<windows.h>
#include<stdio.h>
BOOL CheckDebug()
{
//断点位置，Windows seh几张
	__try
	{
		__asm int 3
	}
	__except(1)
	{
	return FALSE;
	}
	return TRUE;
	
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

## 10 seh
引导到系统内存上：
``` c
#include "stdio.h"
#include "windows.h"
#include "tchar.h"

void AD_BreakPoint()
{
	printf("SEH : BreakPoint\n");
	__asm {
		// install SEH
		push handler
		push DWORD ptr fs : [0]
		mov DWORD ptr fs : [0] , esp
		//generating exception
		int 3
		// 1）debugging
		// go to terminating code
		mov eax, 0xFFFFFFFF
		jmp eax       //process terminating
		//2） not debugging
		// go to normal code
		handler :
		mov eax, dword ptr ss : [esp + 0xc]
			mov dword ptr ds : [eax + 0xb8] , ebx
			xor eax, eax
			retn
			normal_code :
		//remove SEH
		pop dword ptr fs : [0]
			add esp, 4
	}
	printf("  ==> Not debugging... \n\n");
}

int _tmain(int argc, TCHAR* argv)
{
	AD_BreakPoint();
	return 0;
}
```