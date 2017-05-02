#include <ntddk.h>
//=======================================================================//
//***************************SSDT hook 代码******************************//
ULONG oldserivce;                      //保存系统原函数地址
long protect_pid;                   //保存要保护的进程PID
#define Msg CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)  //定义IO控制码
#define device_name L"\\Device\\RECEIVE_DATA"  //设备名称
#define device_link L"\\??\\RECEIVE_INK"       //设备符号名称
#pragma code_seg("PAGE")
NTSTATUS status;          //状态
UNICODE_STRING DeviceName;//设备名
UNICODE_STRING SymbolicLinksName;//设备符号链接名
UNICODE_STRING  lnkname;  //驱动卸载时保存设备名和设备符号名
PDEVICE_OBJECT  devnamed;
PDEVICE_OBJECT pDeviceObject;//设备对象
ULONG Data_Control;               //IRP控制码
UCHAR *Information;               //以字符形式读取缓冲区
int  *info;                       //以整形格式读取缓冲区
//=================================函数定义
typedef NTSTATUS(*NtOpen)(PHANDLE pout, ACCESS_MASK des, POBJECT_ATTRIBUTES attr, PCLIENT_ID id);
NTSTATUS IRP_CREATE(PDEVICE_OBJECT irp_deviceobj, PIRP irp_irp);
NTSTATUS MyNtOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesireAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientID);
NTSTATUS MessageProcRoutine(IN PDEVICE_OBJECT pDevobj, IN PIRP pIrp);
////*********************************/////
typedef struct ServiceDescriptorEntry{ 
 unsigned int *ServiceTableBase;          //指向系统服务程序的地址(SSDT)  
 unsigned int *ServiceCounterTableBase;   //指向另一个索引表，该表包含了每个服务表项被调用的次数；不过这个值只在Checkd Build的内核中有效，在Free Build的内核中，这个值总为NULL  
 unsigned int NumberOfServices;           //表示当前系统所支持的服务个数  
 unsigned char *ParamTableBase;           //指向SSPT中的参数地址，它们都包含了NumberOfService这么多个数组单元  
} ServiceDescriptorTableEntry , *PServiceDescriptorTableEntry;
extern PServiceDescriptorTableEntry KeServiceDescriptorTable;//KeServiceDescriptorTable为导出函数  
 NtOpen  realaddr; 
 //拦截函数
 NTSTATUS MyNtOpenProcess(  
             PHANDLE ProcessHandle,  
             ACCESS_MASK DesireAccess,  
             POBJECT_ATTRIBUTES ObjectAttributes,  
             PCLIENT_ID ClientID)  
			{
				if((long)ClientID->UniqueProcess==protect_pid)
				{
				    return STATUS_ACCESS_DENIED;
				}
			    else
					return (realaddr(ProcessHandle,DesireAccess,ObjectAttributes,ClientID));
			}


//=========================================================================处理来自应用层的控制信息
NTSTATUS IRP_CREATE(PDEVICE_OBJECT irp_deviceobj, PIRP irp_irp)
{
	return STATUS_SUCCESS;
}
NTSTATUS MessageProcRoutine(IN PDEVICE_OBJECT pDevobj, IN PIRP pIrp)
{
	PIO_STACK_LOCATION stack; 
	stack = IoGetCurrentIrpStackLocation(pIrp); //获取IRP堆栈
    Data_Control = (ULONG)stack->Parameters.DeviceIoControl.IoControlCode;
	DbgPrint("IO控制码:%x", Data_Control);
    info = (int*)pIrp->AssociatedIrp.SystemBuffer;    //缓冲区读写

		DbgPrint("Infomation=======:%d", info[0]);
        protect_pid=info[0];          //读取缓存区数据(要保护的进程PID)
		
		//=========================HOOK保护//===========================================//
		oldserivce =(ULONG)KeServiceDescriptorTable->ServiceTableBase[122];     //获取NtOpenProcess函数SSDT地址
        realaddr=(NtOpen)oldserivce;                                            //获取NtOpenProcess函数地址
        KeServiceDescriptorTable->ServiceTableBase[122] =(ULONG)MyNtOpenProcess;//替换NtOpenProcess内核函数
		//××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××//
		
	switch (Data_Control)
	{
	case Msg:
	{
		break;
	}
	default:
		break;
	}
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
//×××××××××××××××××××××××××××××××驱动卸载恢复被HOOK的函数地址
 DbgPrint("Unhooker unload!"); 
 KeServiceDescriptorTable->ServiceTableBase[122]=oldserivce;
 DbgPrint("%s,%x","已恢复SSDT函数地址:",oldserivce);
 __asm {  //打开内存页面写保护
	 mov eax, cr0
	 or eax, 10000h
	 mov cr0, eax
	 sti
 }
 //==============================驱动卸载删除设备符号和设备

	RtlInitUnicodeString(&lnkname, device_link);
	IoDeleteSymbolicLink(&lnkname);         //删除设备符号
	devnamed = pDriverObject->DeviceObject;
	IoDeleteDevice(devnamed);              //删除设备
	DbgPrint("驱动程序已卸载!");
	return STATUS_SUCCESS;
}
//********************************************************************************//
//#pragma code_seg("INIT") //表示代码只在加载时运行完毕即从内存卸载
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegsiterPath)
{
pDriverObject->DriverUnload = DriverUnload;//=====================//驱动卸载入口
//=========================================================================//
//                  SSDT hook初始化                                       //
//×××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××//
 DbgPrint("Unhooker load"); 
     __asm{//去掉内存保护  
  cli 
   mov eax,cr0 
   and eax,not 10000h 
   mov cr0,eax 
 }  

//-------------------------------------------------------------------------//
//                       初始化驱动通信，创建设备和设备符号     	      //
//×××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××//


	//=====================================================//初始化设备和设备符号
	RtlInitUnicodeString(&DeviceName, &device_name);
	RtlInitUnicodeString(&SymbolicLinksName, &device_link);

	//======================================================//创建设备
	status = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("创建设备失败!");
		return status;
	}
	//================================================================//根据创建好的设备创建一个设备符号链接名
	pDeviceObject->Flags |= DO_BUFFERED_IO;                           //驱动通信读写方式为缓冲区读写方式
	status = IoCreateSymbolicLink(&SymbolicLinksName, &DeviceName);   //创建设备符号标识
	if (!NT_SUCCESS(status))
	{
		//如果失败则删除创建好的设备
		IoDeleteDevice(pDeviceObject);
		KdPrint(("设备符号链接名创建失败！"));
		return status;
	}
	pDriverObject->DeviceObject = pDeviceObject;
    //================================================================//指定处理驱动通信的函数
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_CREATE;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MessageProcRoutine;  

	return STATUS_SUCCESS;
}