
// listenDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "listen.h"
#include "listenDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// ClistenDlg �Ի���



ClistenDlg::ClistenDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_LISTEN_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void ClistenDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(ClistenDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    
	ON_WM_TIMER()
 
 
END_MESSAGE_MAP()

PROCESSENTRY32 pe32;
HANDLE handle;
DWORD dpid;
BOOL find = FALSE;
CString cmd;
CString cmdname;
CString major_cmd = _T("runhook.exe");
BOOL p_boot = TRUE;     //��س����Ƿ�����
BOOL major_proc = TRUE;  //�����������
CString control_cmd;    //��ȡ���ƽ���״ָ̬ʾ
CString isstop(_T("CONTROLSTOP")); //��������ָֹͣ��
char *buffer = "";
CString upper_sys, upper_proc;  //��Сдת���Ƚ�
// ClistenDlg ��Ϣ�������

BOOL ClistenDlg::OnInitDialog()
{
 
 	 SetWindowPos(&CWnd::wndTopMost, 0, 0, 0, 0, SWP_HIDEWINDOW);
 	 ModifyStyleEx(WS_EX_APPWINDOW, WS_EX_TOOLWINDOW);
	CDialogEx::OnInitDialog();

	FILE *file;
	fopen_s(&file, "process.ini", "r");
	buffer = new char[100];
	fgets(buffer, 50, file);
	fclose(file);
	cmd = (CString)buffer;

  	//=================================================
	SetTimer(1, 2000, NULL);   //��ʼ�������ʱ�������
	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void ClistenDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void ClistenDlg::OnPaint()
{
	
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR ClistenDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



 


void ClistenDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (!PathFileExists(_T("startlisten.ini")))
	{
			MessageBox(_T("�����ļ�startlisten.ini��ʧ,���½�һ��"));
			ExitProcess(0);
	}
	else if(!PathFileExists(_T("process.ini")))
	{
		MessageBox(_T("�����ļ�process.ini��ʧ,���½�һ��"));
		ExitProcess(0);
	}
//	::GetPrivateProfileString(_T("LISTEN"), _T("CONTROL"), _T("�����ļ�����"), control_cmd.GetBuffer(MAX_PATH), MAX_PATH, _T("startlisten.ini"));
 	CStdioFile stdio(_T("startlisten.ini"),CStdioFile::modeRead);
	stdio.ReadString(control_cmd);
	stdio.Close();
	if (control_cmd == isstop)
	{
		MessageBox(_T("�����̷�����ֹͣ����"), _T("����˳�"),MB_SYSTEMMODAL);
		KillTimer(1);     //ֹͣ���
		ExitProcess(0);   //�����˳�
	}
	else
	{         

		pe32.dwSize = { sizeof(pe32) };
		handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		find = ::Process32First(handle, &pe32);
		while (find)
		{
            //��Ҫ���д�Сд�ַ�ת��bug==========bug===========bug===========������ģ�fucked
			upper_sys = pe32.szExeFile;
			upper_sys=upper_sys.MakeUpper();
			upper_proc = cmd.MakeUpper();
			if (pe32.szExeFile == major_cmd)
			{
				major_proc = FALSE;
			}
 			if (upper_proc.Find(upper_sys)!=-1 || upper_sys==_T("WORDPAD.EXE"))
			{

				//���ֽ���
				p_boot = FALSE;   //FALSE״̬��ʾ���������˳���
			}
			find = ::Process32Next(handle, &pe32);
		}
		if (major_proc)
		{
			//����������̱��ر�
			STARTUPINFO info = { sizeof(STARTUPINFO) };
			PROCESS_INFORMATION pi;
			TCHAR runhook[] = _T("runhook.exe");
			if (!CreateProcess(NULL, runhook, NULL, NULL, NULL, NULL, NULL, NULL, &info, &pi))
			{

				MessageBox(_T("�������ĳ���ʧ"), _T("����"), MB_ICONWARNING);
				ExitProcess(0);
			}
		}
		else
			major_proc = TRUE;
		if (p_boot)
		{
			//������ܱ������򱻹ر�
			 
			if(!WinExec(buffer, SW_SHOW))
			{
				MessageBox(_T("���򲻴���"), _T("����"), NULL);
				KillTimer(1);   //�������
			}
	 
		}
		else
			p_boot = TRUE;    //��֤�رպ��������������ش���
	}
	CDialogEx::OnTimer(nIDEvent);
}

 
