#include "test_common.h"

typedef struct _LP_FIB_THREAD_CONTEXT
{
	int                                 Index;
	unsigned long                       Result;
} LP_FIB_THREAD_CONTEXT, * PLP_FIB_THREAD_CONTEXT;

STATUS
(__cdecl _MultiThreadFibonacci)(
	IN_OPT PVOID Context
	);