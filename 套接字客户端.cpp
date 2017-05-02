
// UDPclientDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "UDPclient.h"
#include "UDPclientDlg.h"
#include "afxdialogex.h"
#include <WinSock2.h>
#pragma comment(lib,"ws2_32.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CUDPclientDlg 对话框



CUDPclientDlg::CUDPclientDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_UDPCLIENT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUDPclientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT2, medit);
}

BEGIN_MESSAGE_MAP(CUDPclientDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CUDPclientDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CUDPclientDlg 消息处理程序

BOOL CUDPclientDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CUDPclientDlg::OnPaint()
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
HCURSOR CUDPclientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


int status_online = TRUE;
WSADATA data;
sockaddr_in client_addr;
SOCKET c_socket;
void CUDPclientDlg::OnBnClickedOk()
{
	CString msg(_T(""));
	medit.GetWindowTextW(msg);
	if (msg!=_T(""))
	{
		if (status_online)
		{
			status_online = FALSE;
			WSAStartup(MAKEWORD(2, 2), &data);
			c_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);   //创建TCP套接字

			memset((void*)&client_addr, 0, sizeof(client_addr));

			client_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
			client_addr.sin_family = AF_INET;
			client_addr.sin_port = htons(8080);

			//连接服务器套接字
			connect(c_socket, (sockaddr*)&client_addr, sizeof(SOCKADDR));
		}
		while (true)
		{

			char *cmsg = new char(msg.GetLength() * 2 + 1);
     		//	WideCharToMultiByte(CP_ACP, 0, msg,-1, cmsg, msg.GetLength()*2+1, NULL, NULL);
			strcpy(cmsg, (char*)msg.GetBuffer());
			MessageBoxA(NULL, cmsg,"test", NULL);
			send(c_socket, cmsg, msg.GetLength()*2+1, 0);
			char Buffer[MAX_PATH] = { 0 };
			int lens = MAX_PATH;
			recv(c_socket, Buffer, lens, 0);
			MessageBoxA(NULL, Buffer, NULL, NULL);
			memset((void*)Buffer, 0, MAX_PATH);
			if (msg == _T("exit"))
			{
				closesocket(c_socket);
				WSACleanup();
				MessageBox(_T("over"));
				break;
			}
			break;
		}
 

	}
	else
		MessageBox(_T("请输入有效信息!"));
}
