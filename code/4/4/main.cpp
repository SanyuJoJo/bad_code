#include "connector.h"
#include "kernelmode_antidbg.h"
#include<stdio.h>
BOOL anti_dbg();
int main(int argc, char* argv[]) {
	if (anti_dbg() == true) {
		printf("[MAIN] No dbg was detected running shellcode ... \n");
		//º”‘ÿshellcode
	}
	else {
		printf("Exiting ... \n");
		exit(0);
	}

	return 0;
}


BOOL anti_dbg() {

	if (is_kernelmode_dbg_enabled() == KDB_DISABLED)
	{
		printf("dbg is diabled\n");
		return true;
	}
	else if (is_kernelmode_dbg_enabled() == KDB_LOCAL_ENABLED) {
		printf("local dbg is running...\n");
		return false;
	}
	else if (is_kernelmode_dbg_enabled() == KDB_REMOTE_ENABLED)
	{
		printf("remote dbg is running...\n");
		return false;
	}
	else {
		printf("Unkown state, possibly is_kernelmode_dbg_enabled faild...\n");
		return false;
	}
}