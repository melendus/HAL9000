#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread_internal.h"
#include "cpumu.h"
#include "smp.h"
#include "vmm.h"
#include "mutex.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

static BOOLEAN areSyscallsDisabled = FALSE;

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
        case SyscallIdFileWrite:
            status = SyscallFileWrite(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]);
            break;
        case SyscallIdThreadGetTid:
            status = SyscallThreadGetTid((UM_HANDLE)pSyscallParameters[0], (TID*)pSyscallParameters[1]);
            break;
        case SyscallIdProcessGetName:
            status = SyscallProcessGetName((QWORD)pSyscallParameters[0], (char*)pSyscallParameters[1]);
            break;
        case SyscallIdGetThreadPriority:
            status = SyscallGetThreadPriority((BYTE*)*pSyscallParameters);
            break;
        case SyscallIdSetThreadPriority:
            status = SyscallSetThreadPriority((BYTE)*pSyscallParameters);
            break;
        case SyscallIdGetCurrentCPUID:
            status = SyscallGetCurrentCPUID((BYTE*)*pSyscallParameters);
            break;
        case SyscallIdGetNumberOfThreadsForCurrentProcess:
            status = SyscallGetNumberOfThreadsForCurrentProcess((QWORD*)*pSyscallParameters);
            break;
        case SyscallIdGetCPUUtilization:
            status = SyscallGetCPUUtilization((BYTE*)pSyscallParameters[0], (BYTE*)pSyscallParameters[1]);
            break;
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdMemset:
            status = SyscallMemset((PBYTE)pSyscallParameters[0], (DWORD)pSyscallParameters[1], (BYTE)pSyscallParameters[2]);
            break;
        case SyscallIdDisableSyscalls:
            status = SyscallDisableSyscalls((BOOLEAN)*pSyscallParameters);
            break;
        case SyscallIdSetGlobalVariable:
            status = SyscallSetGlobalVariable((char*)pSyscallParameters[0], (DWORD)pSyscallParameters[1], (QWORD)pSyscallParameters[2]);
            break;
        case SyscallIdGetGlobalVariable:
            status = SyscallGetGlobalVariable((char*)pSyscallParameters[0], (DWORD)pSyscallParameters[1], (QWORD)pSyscallParameters[2]);
            break;
        case SyscallIdMutexInit:
            status = SyscallMutexInit((UM_HANDLE)*pSyscallParameters);
            break;
        case SyscallIdMutexAcquire:
            status = SyscallMutexAcquire((UM_HANDLE)*pSyscallParameters);
            break;
        case SyscallIdMutexRelease:
            status = SyscallMutexRelease((UM_HANDLE)*pSyscallParameters);
            break;
        // STUDENT TODO: implement the rest of the syscalls
        default:
            LOG_ERROR("Unimplemented syscall called from User-space! ID OF SYSCALL: %d\n", sysCallId);
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
//USERPROG exercise 1
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls

STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                           Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{

    STATUS status;
    DWORD bufferLength;

    if (Buffer == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (BytesWritten == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (FileHandle != UM_FILE_HANDLE_STDOUT) {
        return STATUS_UNSUPPORTED;
    }


    //validate access rights
    status = MmuIsBufferValid(Buffer, BytesToWrite, PAGE_RIGHTS_READ, GetCurrentProcess());
    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid(BytesWritten, sizeof(QWORD), PAGE_RIGHTS_WRITE, GetCurrentProcess());
    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    bufferLength = cl_strlen((char*)Buffer);

    if ((QWORD)bufferLength + 1 != BytesToWrite) {
        return STATUS_UNSUCCESSFUL;
    }

    if (FileHandle == UM_FILE_HANDLE_STDOUT)
        LOG("[%s]\n", Buffer);

    *BytesWritten = BytesToWrite;

    return STATUS_SUCCESS;
}

STATUS
SyscallThreadGetTid(
    IN_OPT  UM_HANDLE               ThreadHandle,
    OUT     TID* ThreadId
)
{
    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS status;
    PTHREAD myThread;
    myThread = NULL;

    myThread = GetCurrentThread();

    if (myThread == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (ThreadId == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid(ThreadId, sizeof(TID), PAGE_RIGHTS_WRITE, GetCurrentProcess());

    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (ThreadHandle == UM_INVALID_HANDLE_VALUE) {
        *ThreadId = myThread->Id;
        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;   
}

STATUS
SyscallProcessGetName(
    IN QWORD                        ProcessNameMaxLen,
    OUT char*                       ProcessName
) {

    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS status;
    PPROCESS currentProcess = GetCurrentProcess();
    DWORD processNameLength;
    char processNameToBeReturned[MAX_PATH];

    if (ProcessName == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (currentProcess == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid(ProcessName, ProcessNameMaxLen, PAGE_RIGHTS_WRITE, GetCurrentProcess());
    
    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    processNameLength = cl_strlen(currentProcess->ProcessName);

    if (processNameLength > ProcessNameMaxLen) {
        cl_strncpy(processNameToBeReturned, currentProcess->ProcessName, (DWORD)ProcessNameMaxLen);
        cl_strcpy(ProcessName, processNameToBeReturned);
        return STATUS_TRUNCATED_PROCESS_NAME;
    }
    else {
        cl_strcpy(ProcessName, currentProcess->ProcessName);
        return STATUS_SUCCESS;
    }
}

STATUS
SyscallGetThreadPriority(
    OUT BYTE* ThreadPriority
) {
    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS status;

    if (ThreadPriority == NULL) {
        return STATUS_UNSUCCESSFUL;
    }


    PTHREAD currentThread;
    currentThread = NULL;

    currentThread = GetCurrentThread();

    if (currentThread == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid(ThreadPriority, sizeof(BYTE), PAGE_RIGHTS_WRITE, GetCurrentProcess());

    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    *ThreadPriority = currentThread->Priority;

    return STATUS_SUCCESS;
}

STATUS
SyscallSetThreadPriority(
    IN BYTE ThreadPriority
) {
    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    if (&ThreadPriority == NULL) {
        return STATUS_UNSUCCESSFUL;
    }


    PTHREAD currentThread;
    currentThread = NULL;

    currentThread = GetCurrentThread();

    if (currentThread == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    currentThread->Priority = ThreadPriority;

    return STATUS_SUCCESS;
}

STATUS
SyscallGetCurrentCPUID(
    OUT BYTE* CpuId
) {
    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS status;
    PPCPU pCpu;

    if (CpuId == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    pCpu = GetCurrentPcpu();

    if (pCpu == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid(CpuId, sizeof(BYTE), PAGE_RIGHTS_WRITE, GetCurrentProcess());

    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    *CpuId = pCpu->ApicId;

    return STATUS_SUCCESS;
}

STATUS
SyscallGetNumberOfThreadsForCurrentProcess(
    OUT QWORD* ThreadNo
) {
    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS status;

    if (ThreadNo == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    PPROCESS currentProcess = NULL;
    currentProcess = GetCurrentProcess();

    if (currentProcess == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid(ThreadNo, sizeof(QWORD), PAGE_RIGHTS_WRITE, GetCurrentProcess());

    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    *ThreadNo = currentProcess->NumberOfThreads;

    return STATUS_SUCCESS;
}

STATUS
SyscallGetCPUUtilization(
    IN_OPT BYTE* CpuId,
    OUT BYTE* Utilization
) {
    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    BYTE calculatedUtilization;


    if (Utilization == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    PLIST_ENTRY pCpuListHead;
    PLIST_ENTRY pCurEntry;

    pCpuListHead = NULL;

    SmpGetCpuList(&pCpuListHead);

    if (CpuId == NULL) {
        BYTE totalTicks = 0;
        BYTE totalIdleTicks = 0;
        calculatedUtilization = 0;

        for (pCurEntry = pCpuListHead->Flink;
            pCurEntry != pCpuListHead;
            pCurEntry = pCurEntry->Flink)
        {
            PPCPU pCpu = CONTAINING_RECORD(pCurEntry, PCPU, ListEntry);
            totalTicks += (BYTE)pCpu->ThreadData.KernelTicks;
            totalIdleTicks +=  (BYTE)pCpu->ThreadData.IdleTicks;
        }

        // we can't do division by 0 => we only divide by totalTicks if the tick count is different
           // from 0
        calculatedUtilization = 0 != (totalTicks + totalIdleTicks) ? (totalTicks * 100) / (totalTicks + totalIdleTicks) : 0;
        *Utilization = calculatedUtilization;

        return STATUS_SUCCESS;
    }

    BYTE ticks = 0;
    BYTE idleTicks = 0;

    for (pCurEntry = pCpuListHead->Flink;
        pCurEntry != pCpuListHead;
        pCurEntry = pCurEntry->Flink)
    {
        PPCPU pCpu = CONTAINING_RECORD(pCurEntry, PCPU, ListEntry);
        if (pCpu->ApicId == *CpuId) {
            ticks = (BYTE)pCpu->ThreadData.KernelTicks;
            idleTicks += (BYTE)pCpu->ThreadData.IdleTicks;
            calculatedUtilization = 0 != (ticks + idleTicks) ? (ticks * 100) / (ticks + idleTicks) : 0;
            *Utilization = calculatedUtilization;

            return STATUS_SUCCESS;
        }
       
    }
    return STATUS_UNSUCCESSFUL;
}

//USERPROG exercise 1
STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    GetCurrentProcess()->TerminationStatus = ExitStatus;
    ProcessTerminate(NULL);

    return STATUS_SUCCESS;
}

//USERPROG exercise 1
STATUS
SyscallThreadExit(
    IN  STATUS                      ExitStatus
)
{
    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    ThreadExit(ExitStatus);
    return STATUS_SUCCESS;
}


//USERPROG exercise 4
STATUS
SyscallMemset(
    OUT_WRITES(BytesToWrite)    PBYTE   Address,
    IN                          DWORD   BytesToWrite,
    IN                          BYTE    ValueToWrite
) {
    //USERPROG exercise 6
    if (areSyscallsDisabled) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS status;

    if (BytesToWrite == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (BytesToWrite <= 0) {
        return STATUS_UNSUCCESSFUL;
    }

    if (ValueToWrite == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid(Address, sizeof(PBYTE), PAGE_RIGHTS_WRITE, GetCurrentProcess());


    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    memset(Address, ValueToWrite, BytesToWrite);

    return STATUS_SUCCESS;
}

//USERPROG exercise 6
STATUS
SyscallDisableSyscalls(
    IN      BOOLEAN     Disable
) {
    if (Disable == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    areSyscallsDisabled = Disable;

    return STATUS_SUCCESS;
}

//USERPROG exercise 7
STATUS
SyscallSetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    IN                              QWORD   Value
)
{
    if (VariableName == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (VarLength == NULL && VarLength <= 0) {
        return STATUS_UNSUCCESSFUL;
    }

    if (Value == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    ProcessSetGlobalVariable(VariableName, VarLength, Value);

    return STATUS_SUCCESS;
}

//USERPROG exercise 7

STATUS
SyscallGetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    OUT                             PQWORD  Value
)
{
    STATUS status;

    if (VariableName == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (VarLength == NULL && VarLength <= 0) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid(Value, sizeof(PQWORD), PAGE_RIGHTS_WRITE, GetCurrentProcess());

    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    ProcessGetGlobalVariable(VariableName, VarLength, Value);

    if (Value == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

//USERPROG exercise 8
STATUS
SyscallMutexInit(
    OUT         UM_HANDLE* Mutex
)
{
    if ((PMUTEX)Mutex == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    MutexInit((PMUTEX)Mutex, FALSE);

    return STATUS_SUCCESS;
}

//USERPROG exercise 8
STATUS
SyscallMutexAcquire(
    IN       UM_HANDLE          Mutex
)
{
    STATUS status;

    if ((PMUTEX)Mutex == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid((PMUTEX)Mutex, sizeof(MUTEX), PAGE_RIGHTS_ALL, GetCurrentProcess());
    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    MutexAcquire((PMUTEX)Mutex);

    return STATUS_SUCCESS;
}

//USERPROG exercise 8
STATUS
SyscallMutexRelease(
    IN       UM_HANDLE          Mutex
)
{
    STATUS status;

    if ((PMUTEX)Mutex == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid((PMUTEX)Mutex, sizeof(MUTEX), PAGE_RIGHTS_ALL, GetCurrentProcess());
    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    MutexRelease((PMUTEX)Mutex);

    return STATUS_SUCCESS;
}

//CODE FOR VIRTUAL MEMORY ASSIGNMENT
//STATUS
//SyscallVirtualAlloc(
//    IN_OPT      PVOID                   BaseAddress,
//    IN          QWORD                   Size,
//    IN          VMM_ALLOC_TYPE          AllocType,
//    IN          PAGE_RIGHTS             PageRights,
//    IN_OPT      UM_HANDLE               FileHandle,
//    IN_OPT      QWORD                   Key,
//    OUT         PVOID* AllocatedAddress
//) {
//    DWORD invalidParameters = 0;
//
//    if (BaseAddress != NULL) {
//        invalidParameters++;
//    }
//
//    if (FileHandle != UM_INVALID_HANDLE_VALUE) {
//        invalidParameters++;
//    }
//
//    if (Key != 0) {
//        invalidParameters++;
//    }
//
//    if (invalidParameters == 1) {
//        return STATUS_INVALID_PARAMETER1;
//    }
//
//    if (invalidParameters == 2) {
//        return STATUS_INVALID_PARAMETER2;
//    }
//
//    if (invalidParameters == 3) {
//        return STATUS_INVALID_PARAMETER3;
//    }
//
//    STATUS status;
//
//    status = MmuIsBufferValid(AllocatedAddress, sizeof(PVOID), PAGE_RIGHTS_WRITE, GetCurrentProcess());
//
//    if (!SUCCEEDED(status))
//    {
//        LOG_FUNC_ERROR("AllocatedAddress for SyscallVirualAloc", status);
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    *AllocatedAddress = VmmAllocRegion(BaseAddress, Size, AllocType, PageRights);
//
//    return STATUS_SUCCESS;
//}
//
//STATUS
//SyscallVirtualFree(
//    IN          PVOID                   Address,
//    _When_(VMM_FREE_TYPE_RELEASE == FreeType, _Reserved_)
//    _When_(VMM_FREE_TYPE_RELEASE != FreeType, IN)
//    QWORD                   Size,
//    IN          VMM_FREE_TYPE           FreeType
//) {
//    VmmFreeRegion(Address, Size, FreeType);
//    return STATUS_SUCCESS;
//}
//
//
//STATUS
//SyscallGetPageFaultNo(
//    IN PVOID AllocatedVirtAddr, 
//    OUT QWORD* PageFaultNo
//) {
//    if (AllocatedVirtAddr == NULL) {
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    PPROCESS currentProcess = GetCurrentProcess();
//
//    if (currentProcess == NULL) {
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    STATUS status;
//    status = MmuIsBufferValid(PageFaultNo, sizeof(QWORD), PAGE_RIGHTS_WRITE, currentProcess);
//
//    PagesFaultEntry* curEntry;
//    LIST_ENTRY head;
//
//    for (PLIST_ENTRY pEntry = currentProcess->PagesWithPageFault.Flink;
//        pEntry != &currentProcess->PagesWithPageFault;
//        pEntry = pEntry->Flink
//        )
//    {
//        curEntry = CONTAINING_RECORD(pEntry, PagesFaultEntry, PagesWithPageFault);
//        if (curEntry->VirtualAddress == AllocatedVirtAddr) {
//            *PageFaultNo = curEntry->NumberOfPF;
//            break;
//        }
//    }
//}
//
//STATUS
//SyscallGetPagePhysAddr(
//    IN PVOID AllocatedVirtAddr,
//    OUT PVOID* AllocatedPhysAddr
//) {
//    if (AllocatedVirtAddr == NULL) {
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    STATUS status;
//    status = MmuIsBufferValid(AllocatedPhysAddr, sizeof(PVOID), PAGE_RIGHTS_WRITE, GetCurrentProcess());
//
//    if (!SUCCEEDED(status))
//    {
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    PML4 cr3;
//
//    cr3.Raw = (QWORD)__readcr3();
//
//    PHYSICAL_ADDRESS pAddr = VmmGetPhysicalAddress(cr3, AllocatedVirtAddr);
//
//    *AllocatedPhysAddr = pAddr;
//}
//
//STATUS
//SyscallGetPageInternalFragmentation(
//    IN PVOID AllocatedVirtAddr,
//    OUT QWORD* IntFragSize
//) {
//    if (AllocatedVirtAddr == NULL) {
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    STATUS status;
//    PPROCESS currentProcess = GetCurrentProcess();
//    status = MmuIsBufferValid(IntFragSize, sizeof(QWORD), PAGE_RIGHTS_WRITE, currentProcess);
//
//    PPROCESS currentProcess = GetCurrentProcess();
//    PagesFragEntry* curEntry;
//    LIST_ENTRY head;
//
//    for (PLIST_ENTRY pEntry = currentProcess->PagesWithPageFault.Flink;
//        pEntry != &currentProcess->PagesWithPageFault;
//        pEntry = pEntry->Flink
//        )
//    {
//        curEntry = CONTAINING_RECORD(pEntry, PagesFragEntry, PagesFragmentationSize);
//        if (curEntry->VirtualAddress == AllocatedVirtAddr) {
//            *IntFragSize = curEntry->FragmentationSize;
//            break;
//        }
//    }
//}