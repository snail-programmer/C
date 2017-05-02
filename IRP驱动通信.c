#include <ntddk.h>
//=======================================================================//
//***************************SSDT hook ����******************************//
ULONG oldserivce;                      //����ϵͳԭ������ַ
long protect_pid;                   //����Ҫ�����Ľ���PID
#define Msg CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)  //����IO������
#define device_name L"\\Device\\RECEIVE_DATA"  //�豸����
#define device_link L"\\??\\RECEIVE_INK"       //�豸��������
#pragma code_seg("PAGE")
NTSTATUS status;          //״̬
UNICODE_STRING DeviceName;//�豸��
UNICODE_STRING SymbolicLinksName;//�豸����������
UNICODE_STRING  lnkname;  //����ж��ʱ�����豸�����豸������
PDEVICE_OBJECT  devnamed;
PDEVICE_OBJECT pDeviceObject;//�豸����
ULONG Data_Control;               //IRP������
UCHAR *Information;               //���ַ���ʽ��ȡ������
int  *info;                       //�����θ�ʽ��ȡ������
//=================================��������
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
 unsigned int *ServiceTableBase;          //ָ��ϵͳ�������ĵ�ַ(SSDT)  
 unsigned int *ServiceCounterTableBase;   //ָ����һ���������ñ������ÿ�����������õĴ������������ֵֻ��Checkd Build���ں�����Ч����Free Build���ں��У����ֵ��ΪNULL  
 unsigned int NumberOfServices;           //��ʾ��ǰϵͳ��֧�ֵķ������  
 unsigned char *ParamTableBase;           //ָ��SSPT�еĲ�����ַ�����Ƕ�������NumberOfService��ô������鵥Ԫ  
} ServiceDescriptorTableEntry , *PServiceDescriptorTableEntry;
extern PServiceDescriptorTableEntry KeServiceDescriptorTable;//KeServiceDescriptorTableΪ��������  
 NtOpen  realaddr; 
 //���غ���
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


//=========================================================================��������Ӧ�ò�Ŀ�����Ϣ
NTSTATUS IRP_CREATE(PDEVICE_OBJECT irp_deviceobj, PIRP irp_irp)
{
	return STATUS_SUCCESS;
}
NTSTATUS MessageProcRoutine(IN PDEVICE_OBJECT pDevobj, IN PIRP pIrp)
{
	PIO_STACK_LOCATION stack; 
	stack = IoGetCurrentIrpStackLocation(pIrp); //��ȡIRP��ջ
    Data_Control = (ULONG)stack->Parameters.DeviceIoControl.IoControlCode;
	DbgPrint("IO������:%x", Data_Control);
    info = (int*)pIrp->AssociatedIrp.SystemBuffer;    //��������д

		DbgPrint("Infomation=======:%d", info[0]);
        protect_pid=info[0];          //��ȡ����������(Ҫ�����Ľ���PID)
		
		//=========================HOOK����//===========================================//
		oldserivce =(ULONG)KeServiceDescriptorTable->ServiceTableBase[122];     //��ȡNtOpenProcess����SSDT��ַ
        realaddr=(NtOpen)oldserivce;                                            //��ȡNtOpenProcess������ַ
        KeServiceDescriptorTable->ServiceTableBase[122] =(ULONG)MyNtOpenProcess;//�滻NtOpenProcess�ں˺���
		//������������������������������������������������������������������������������������������������������������������������������������������������������������//
		
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
//������������������������������������������������������������������ж�ػָ���HOOK�ĺ�����ַ
 DbgPrint("Unhooker unload!"); 
 KeServiceDescriptorTable->ServiceTableBase[122]=oldserivce;
 DbgPrint("%s,%x","�ѻָ�SSDT������ַ:",oldserivce);
 __asm {  //���ڴ�ҳ��д����
	 mov eax, cr0
	 or eax, 10000h
	 mov cr0, eax
	 sti
 }
 //==============================����ж��ɾ���豸���ź��豸

	RtlInitUnicodeString(&lnkname, device_link);
	IoDeleteSymbolicLink(&lnkname);         //ɾ���豸����
	devnamed = pDriverObject->DeviceObject;
	IoDeleteDevice(devnamed);              //ɾ���豸
	DbgPrint("����������ж��!");
	return STATUS_SUCCESS;
}
//********************************************************************************//
//#pragma code_seg("INIT") //��ʾ����ֻ�ڼ���ʱ������ϼ����ڴ�ж��
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegsiterPath)
{
pDriverObject->DriverUnload = DriverUnload;//=====================//����ж�����
//=========================================================================//
//                  SSDT hook��ʼ��                                       //
//����������������������������������������������������������������������������������������������������������������������������������������������//
 DbgPrint("Unhooker load"); 
     __asm{//ȥ���ڴ汣��  
  cli 
   mov eax,cr0 
   and eax,not 10000h 
   mov cr0,eax 
 }  

//-------------------------------------------------------------------------//
//                       ��ʼ������ͨ�ţ������豸���豸����     	      //
//����������������������������������������������������������������������������������������������������������������������������������������������//


	//=====================================================//��ʼ���豸���豸����
	RtlInitUnicodeString(&DeviceName, &device_name);
	RtlInitUnicodeString(&SymbolicLinksName, &device_link);

	//======================================================//�����豸
	status = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("�����豸ʧ��!");
		return status;
	}
	//================================================================//���ݴ����õ��豸����һ���豸����������
	pDeviceObject->Flags |= DO_BUFFERED_IO;                           //����ͨ�Ŷ�д��ʽΪ��������д��ʽ
	status = IoCreateSymbolicLink(&SymbolicLinksName, &DeviceName);   //�����豸���ű�ʶ
	if (!NT_SUCCESS(status))
	{
		//���ʧ����ɾ�������õ��豸
		IoDeleteDevice(pDeviceObject);
		KdPrint(("�豸��������������ʧ�ܣ�"));
		return status;
	}
	pDriverObject->DeviceObject = pDeviceObject;
    //================================================================//ָ����������ͨ�ŵĺ���
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_CREATE;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MessageProcRoutine;  

	return STATUS_SUCCESS;
}