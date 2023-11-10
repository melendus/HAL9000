#include "test_common.h"
#include "test_thread.h"
#include "test_priority_donation.h"
#include "mutex.h"
#include "thread_internal.h"
#include "pit.h"
#include "checkin_queue.h"
#include "test_lp.h"

STATUS
(__cdecl _MultiThreadFibonacci) (
	IN_OPT	PVOID	Context
	)
{
	STATUS status;
	PLP_FIB_THREAD_CONTEXT context = (PLP_FIB_THREAD_CONTEXT)Context;
	if (context->Index == 0 || context->Index == 1) {
		context->Result = 1;
		return STATUS_SUCCESS;
	}

	LP_FIB_THREAD_CONTEXT context1 = { context->Index - 1, 0};
	LP_FIB_THREAD_CONTEXT context2 = { context->Index - 2, 0};

	PTHREAD thread1 = NULL;
	PTHREAD thread2 = NULL;
	char thName[MAX_PATH];

	__try
	{
		snprintf(thName, MAX_PATH, "Fib-%d", context->Index);
		 status = ThreadCreate(thName,
			ThreadPriorityDefault,
			_MultiThreadFibonacci,
			&context1,
			&thread1);

		 if (!SUCCEEDED(status)) {
			 LOG_FUNC_ERROR(" ThreadCreate ", status);
			 __leave;
		}
		 snprintf(thName, MAX_PATH, "Fib -%d", context->Index);
		 status = ThreadCreate(thName,
			 ThreadPriorityDefault,
			 _MultiThreadFibonacci,
			 &context2,
			 &thread2
		 );
		 if (!SUCCEEDED(status))
		 {
			 LOG_FUNC_ERROR(" ThreadCreate ", status);
			 __leave;
		 }

		// added code
		// this simply checks if the 2 created threads finished their
		// execution , and the finish status is SUCCEEDED
		 ThreadWaitForTermination(thread1, &status);
		 ASSERT(SUCCEEDED(status));
		 ThreadWaitForTermination(thread2, &status);
		 ASSERT(SUCCEEDED(status));

		// if so , we can safely say that we have the correct
		// results in each context
		 context->Result = context1.Result + context2.Result;

		 LOG("RESULT and INDEX: %d %d\n", context->Result, context->Index);
	}
	__finally
	{
		if (thread1)
		{
			ThreadCloseHandle(thread1);
		}
		if (thread2)
		{
			ThreadCloseHandle(thread2);
		}
	}

	return status;
}