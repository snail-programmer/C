// hook.cpp : ���� DLL Ӧ�ó���ĵ���������
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
//���干�����ݶ�
#pragma data_seg("MyData")
DWORD ishideor(0);        //�ж��Ƿ����ؽ���
DWORD protect_pid(0);
DWORD term_pid(0);
PROC user32(0);
PROC isview(0);
PROC antdll(0);
PROC* proc_user32(0);
PROC* proc_isview(0);
PROC* proc_query(0);
HWND Hwnd_prot(0);
HMODULE module(0);    //dllģ����
#pragma data_seg()
#pragma comment(linker,"/SECTION:MyData,RWS")
//�������ݶζ������
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

ZWQUERYSYSTEMINFORMATION zwquerysysteminformation;    //ʵ������������
//=================================��������ʵ��
NTSTATUS WINAPI MyZwQuerySystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
)
{
	zwquerysysteminformation = (ZWQUERYSYSTEMINFORMATION)antdll;    //����ԭʼ������ַ����������
	NTSTATUS ntStatus;
	PSYSTEM_PROCESSES pSystemProcesses = NULL, Prev;
	Sleep(1);
	ntStatus = (zwquerysysteminformation)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);  //����ԭ����
	if (NT_SUCCESS(ntStatus) && SystemInformationClass == SystemProcessesAndThreadsInformation)
	{
		pSystemProcesses = (PSYSTEM_PROCESSES)SystemInformation;   //��ȡ��ַΪ�ṹ������
		if (pSystemProcesses->ProcessId == protect_pid)
		{
			return ntStatus;
		}
		while (TRUE)
		{
			if (pSystemProcesses->ProcessId == protect_pid) //�����������Ҫ���ص�PID�ͽ��������޸�
			{
				if (pSystemProcesses->NextEntryDelta)
				{
					//��������Ҫ���صĽ��̺��滹�н���ʱ
					//Խ�������Լ�������NextEntryDeltaֱ��ָ����һ�����ݿ�
					DWORD dwOldProtect;
					//�ĳɶ�д��ִ��״̬
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
					//�����ǽ��̴������һ��������ô���ǾͰ���һ�����ݽṹ��NextEntryDelta��0
					//��ʱϵͳ�ڱ������ǽ���ʱ�Ͳ��ᷢ����
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
//=============================================����Ϊ���ؽ��̴���
BOOL WINAPI MyIsWindowVisible(
	_In_ HWND hWnd
)
{
	return FALSE;    //�ܾ������������ʾ�����б�
	 
}
 
  HANDLE WINAPI myopenprocess(DWORD DWSIZE, BOOL jc, DWORD PID)
{
	  term_pid = PID;
     CString stop_lanjie(_T("")), stop_term(_T(""));
	 stop_lanjie.Format(_T("%x"), protect_pid);
	 stop_term.Format(_T("%x"), term_pid);
	 if (stop_lanjie == stop_term)
	 {
 	 return((ter)(FARPROC)user32)(DWSIZE, jc, 4); //������߷���ϵͳ�ں˵�PID
	 }
	 else
	  return((ter)(FARPROC)user32)(DWSIZE, jc, PID); //����	  
}
 

void inject(DWORD ds)
{
	DWORD protect = 0;
	HMODULE hmodule = ::LoadLibrary(_T("Kernel32.dll"));
	HMODULE hview = ::LoadLibrary(_T("user32.dll"));
	HMODULE hntdll = ::LoadLibrary(_T("ntdll.dll"));
	user32 = GetProcAddress(hmodule, "OpenProcess"); //��ȡϵͳ������ַ
	isview = GetProcAddress(hview, "IsWindowVisible");
	antdll = ::GetProcAddress(hntdll, "ZwQuerySystemInformation");
 	lanjie = (PROC)myopenprocess;    //PID���˺�����ַ
	lanjie2 = (PROC)MyIsWindowVisible;
	lanjie3 = (PROC)MyZwQuerySystemInformation;
	ULONG size;
	HMODULE he = GetModuleHandle(NULL);  //��ģ��

	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(he, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);//��ȡ����IAT��
	for (; import->Name; import++)   //ѭ�����������ڼ��صĶ�̬���ӿ�����(dll)
	{
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)he + import->FirstThunk);  //�ýṹ��洢����η��������Ϣ
		for (; thunk->u1.Function; thunk++)   //��������η���
		{
			ppfn = (PROC*)&thunk->u1.Function;  //��ȡ���ŵ�ַ
			//��������������������б���ֹ�䷢�����ٴ�����Ϣ
			if (*ppfn == isview)
			{
				  proc_isview = ppfn;    //����ԭ������ַ
				VirtualProtect(ppfn, sizeof(lanjie2), PAGE_WRITECOPY, &protect);               //ȥ��д��������
				WriteProcessMemory(GetCurrentProcess(), ppfn, &lanjie2, sizeof(lanjie2), NULL);
				VirtualProtect(ppfn, sizeof(lanjie2), protect, &protect);
			}
			//==========================if else ѡ����̱������������ػ�������,��ishideor��ֵ����
			if (*ppfn == user32 && !ishideor)
			{
				if (*ppfn == user32)
				{
					proc_user32= ppfn;                                                           //�������غ�����ַ
					VirtualProtect(ppfn, sizeof(lanjie), PAGE_WRITECOPY, &protect);               //ȥ��д��������
					WriteProcessMemory(GetCurrentProcess(), ppfn, &lanjie, sizeof(lanjie), NULL); //��дָ��OpenProcess�����ĵ�ַ
					VirtualProtect(ppfn, sizeof(lanjie), protect, &protect);                      //�ָ�д��������
				}
			} 
			else if (*ppfn == antdll && ishideor)               //���أ�����ZwQuerySystemInformation����
			{
				proc_query = ppfn;
				VirtualProtect(ppfn, sizeof(lanjie3), PAGE_WRITECOPY, &protect);               //ȥ��д��������
				WriteProcessMemory(GetCurrentProcess(), ppfn, &lanjie3, sizeof(lanjie3), NULL);
				VirtualProtect(ppfn, sizeof(lanjie3), protect, &protect);                      //�ָ�д��������
			}
			 
		}//^forѭ������������η��ŵ�ַ
	}
}
LRESULT CALLBACK proc(int code, WPARAM wm, LPARAM lm)
{
	inject(protect_pid); //ע�����غ���
	return false;
}
void out(DWORD DD,DWORD p_pid,DWORD hideor)
{
	ishideor = hideor;                    //�Ƿ�ָ������
	protect_pid = p_pid;
 	 module = GetModuleHandle(_T("hook.dll")); //��ȡdllģ����
	if (!module)
		MessageBox(NULL, _T("�޷���ȡdllģ����Ϣ"), NULL, NULL);
	hook = SetWindowsHookEx(WH_GETMESSAGE, proc, module, 0);  //����ϵͳȫ�ֹ��ӣ���proc�������óɹ�����Ϣ������
	if (!hook)
		MessageBox(NULL, _T("HOOKģ�����ʧ��"), NULL, NULL);
}
void unhook()
{
	DWORD dwnew = 0;
	VirtualProtect(proc_isview, sizeof(isview), PAGE_WRITECOPY, &dwnew);
	WriteProcessMemory(GetCurrentProcess(), proc_isview, &isview, sizeof(isview), NULL);      //�ָ�IsWindowVisible������ַ
	VirtualProtect(proc_isview, sizeof(isview), dwnew, &dwnew);
	if (ishideor)
	{
		VirtualProtect(proc_query, sizeof(antdll), PAGE_WRITECOPY, &dwnew);
		WriteProcessMemory(GetCurrentProcess(), proc_query, &antdll, sizeof(antdll), NULL);   //�ָ�ZwQuerySystemInformation������ַ
		VirtualProtect(proc_query, sizeof(antdll), dwnew, &dwnew);
	}
	else
	{
		VirtualProtect(proc_user32, sizeof(user32), PAGE_WRITECOPY, &dwnew);
		WriteProcessMemory(GetCurrentProcess(), proc_user32, &user32, sizeof(user32), NULL);  //�ָ�OpenProcess������ַ
		VirtualProtect(proc_user32, sizeof(user32), dwnew, &dwnew); 
	}
	UnhookWindowsHookEx(hook); //ж��ȫ�ֹ���
	FreeLibrary(module);   //ж��dll
}
CWinApp theApp;
int main()
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(nullptr);

	if (hModule != nullptr)
	{
		// ��ʼ�� MFC ����ʧ��ʱ��ʾ����
		if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
		{
			// TODO: ���Ĵ�������Է���������Ҫ
			wprintf(L"����: MFC ��ʼ��ʧ��\n");
			nRetCode = 1;
		}
		else
		{
			// TODO: �ڴ˴�ΪӦ�ó������Ϊ��д���롣
		}
	}
	else
	{
		// TODO: ���Ĵ�������Է���������Ҫ
		wprintf(L"����: GetModuleHandle ʧ��\n");
		nRetCode = 1;
	}

	return nRetCode;
}

