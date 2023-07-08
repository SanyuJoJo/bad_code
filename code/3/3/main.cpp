#include<windows.h>
#include<stdio.h>
#include<winternl.h>

typedef NTSTATUS(WINAPI* NtQueryInfomationProcessPtr)(
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
	NtQueryInfomationProcessPtr NtQueryInfomationProcess = (NtQueryInfomationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");

	if (NtQueryInfomationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), NULL))
	{
		printf("[ERROR NtQueryInformationProcessApproach] NtQueryInformationProcess failed\n");
	}
	else
	{
		return debugPort == -1;
	}

	return false;

}
int main()
{
	if (NtQueryInformationProcessApproach())
	{
		printf("a");
	}
	else
	{
		printf("b");
	}
	return 0;
}
