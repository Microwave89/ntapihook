#include "global.h"

ULONG_PTR getDispatchBegin(void) {
	return (ULONG_PTR)&getDispatchBegin;
}

ULONG_PTR newNtUserGetUpdateRect(ULONG_PTR param1, ULONG_PTR param2, ULONG_PTR param3, ULONG_PTR param4,
	ULONG_PTR param5, ULONG_PTR param6, ULONG_PTR param7, ULONG_PTR param8,
	ULONG_PTR param9, ULONG_PTR param10, ULONG_PTR param11, ULONG_PTR param12,
	ULONG_PTR param13, ULONG_PTR param14, ULONG_PTR param15, ULONG_PTR param16) {
	NTSTATUS status = STATUS_SUCCESS;

	status = syscallStub(0x1056, param1, param2, param3, param4,
		param5, param6, param7, param8,
		param9, param10, param11, param12,
		param13, param14, param15, param16);

	return status;
}

ULONG_PTR getDispatchEnd(void) {
	return 8 + (ULONG_PTR)&getDispatchEnd;
}
