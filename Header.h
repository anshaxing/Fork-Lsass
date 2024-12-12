#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#endif
#define STATUS_SUCCESS 0x00000000
#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#endif
typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} T_CLIENT_ID;

typedef struct
{
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    T_CLIENT_ID ReflectionClientId;
} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI* RtlCreateProcessReflectionFunc) (
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID StartRoutine,
    PVOID StartContext,
    HANDLE EventHandle,
    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation
    );