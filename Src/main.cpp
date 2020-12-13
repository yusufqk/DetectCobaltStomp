#include <stdio.h>
#include "Structs.h"
#include "Detect.h"

int main(int argc, char const *argv[]) {
	if (argc < 2) {
		printf("\n[!] Usage:\n\n\tDetectCobaltStomp.exe <PID>\n");
		return 0;
	}

	DWORD pid = atoi(argv[1]);
	detect_cobalt_stomp(pid);

	return 0;
}