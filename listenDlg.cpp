
// listenDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "listen.h"
#include "listenDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// ClistenDlg 对话框



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
BOOL p_boot = TRUE;     //监控程序是否启动
BOOL major_proc = TRUE;  //监控主调进程
CString control_cmd;    //读取控制进程状态指示
CString isstop(_T("CONTROLSTOP")); //控制中心停止指令
char *buffer = "";
CString upper_sys, upper_proc;  //大小写转换比较
// ClistenDlg 消息处理程序

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
	SetTimer(1, 2000, NULL);   //初始化程序的时候开启监控
	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void ClistenDlg::OnPaint()
{
	
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR ClistenDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



 


void ClistenDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (!PathFileExists(_T("startlisten.ini")))
	{
			MessageBox(_T("配置文件startlisten.ini丢失,请新建一个"));
			ExitProcess(0);
	}
	else if(!PathFileExists(_T("process.ini")))
	{
		MessageBox(_T("配置文件process.ini丢失,请新建一个"));
		ExitProcess(0);
	}
//	::GetPrivateProfileString(_T("LISTEN"), _T("CONTROL"), _T("配置文件错误"), control_cmd.GetBuffer(MAX_PATH), MAX_PATH, _T("startlisten.ini"));
 	CStdioFile stdio(_T("startlisten.ini"),CStdioFile::modeRead);
	stdio.ReadString(control_cmd);
	stdio.Close();
	if (control_cmd == isstop)
	{
		MessageBox(_T("主进程发出了停止命令"), _T("监控退出"),MB_SYSTEMMODAL);
		KillTimer(1);     //停止监控
		ExitProcess(0);   //程序退出
	}
	else
	{         

		pe32.dwSize = { sizeof(pe32) };
		handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		find = ::Process32First(handle, &pe32);
		while (find)
		{
            //需要进行大小写字符转换bug==========bug===========bug===========操他妈的，fucked
			upper_sys = pe32.szExeFile;
			upper_sys=upper_sys.MakeUpper();
			upper_proc = cmd.MakeUpper();
			if (pe32.szExeFile == major_cmd)
			{
				major_proc = FALSE;
			}
 			if (upper_proc.Find(upper_sys)!=-1 || upper_sys==_T("WORDPAD.EXE"))
			{

				//发现进程
				p_boot = FALSE;   //FALSE状态表示不用启动此程序
			}
			find = ::Process32Next(handle, &pe32);
		}
		if (major_proc)
		{
			//如果主调进程被关闭
			STARTUPINFO info = { sizeof(STARTUPINFO) };
			PROCESS_INFORMATION pi;
			TCHAR runhook[] = _T("runhook.exe");
			if (!CreateProcess(NULL, runhook, NULL, NULL, NULL, NULL, NULL, NULL, &info, &pi))
			{

				MessageBox(_T("控制中心程序丢失"), _T("警告"), MB_ICONWARNING);
				ExitProcess(0);
			}
		}
		else
			major_proc = TRUE;
		if (p_boot)
		{
			//如果用受保护程序被关闭
			 
			if(!WinExec(buffer, SW_SHOW))
			{
				MessageBox(_T("程序不存在"), _T("警告"), NULL);
				KillTimer(1);   //结束监控
			}
	 
		}
		else
			p_boot = TRUE;    //保证关闭后可以重新启动监控代码
	}
	CDialogEx::OnTimer(nIDEvent);
}

 
