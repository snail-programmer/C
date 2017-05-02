
// UDPServerDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "UDPServer.h"
#include "UDPServerDlg.h"
#include "afxdialogex.h"
#include "resource.h"
#include <WinSock2.h>
#pragma  comment(lib,"Ws2_32.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CUDPServerDlg 对话框



CUDPServerDlg::CUDPServerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_UDPSERVER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUDPServerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
 
}

BEGIN_MESSAGE_MAP(CUDPServerDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CUDPServerDlg::OnBnClickedOk)
 
	ON_BN_CLICKED(IDCANCEL, &CUDPServerDlg::OnBnClickedCancel)
END_MESSAGE_MAP()


// CUDPServerDlg 消息处理程序

BOOL CUDPServerDlg::OnInitDialog()
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

void CUDPServerDlg::OnPaint()
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
HCURSOR CUDPServerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
//线程
DWORD _stdcall thread(LPVOID lpvoid)
{
	//WinSocket首先调用动态链接库，并使用WSAStartup函数初始化，以及在该函数中指明版本号
	WSADATA wsa;                          //WSA
	WSAStartup(MAKEWORD(2, 2), &wsa);     //初始化{MAKEWORD(2,2)>主版本号为2,副版本号为2}
	sockaddr_in server_addr;
	memset((void*)&server_addr, 0, sizeof(server_addr));         //填充
	SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);   //创建tcp套接字

	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");  //指定IP地址
	server_addr.sin_family = AF_INET;                           //使用IPV4
	server_addr.sin_port = htons(8080);                       //指定端口
	bind(server, (sockaddr*)&server_addr, sizeof(server_addr)); //绑定套接字

	listen(server, 20);                                          //监听

	SOCKADDR client_addr;
	int len = sizeof(SOCKADDR);
	SOCKET conne = accept(server, &client_addr, &len);        //接收请求并创建可靠连接(TCP)

	while (true)
	{
		char buffer[MAX_PATH] = { 0 };                          //初始化缓冲区
		int buffer_length = MAX_PATH;                           //设定大小
		if (recv(conne, buffer, buffer_length, 0)!=-1)
		{
			if (!conne)
			{
				MessageBox(NULL,_T("连接中断"), NULL, NULL);
				ExitThread(0);
				break;
			}
			MessageBoxA(NULL, buffer, "来自客户端的信息", NULL);
			int exitd = 0;
			if (buffer == "exit")
			{
				exitd = 1;
				break;
			}
			else
				send(conne, "Hello,I'm Server", 30, 0);                               //发送信息
			if (exitd == 1)
			{
				closesocket(conne);
				closesocket(server);
				WSACleanup();
				ExitThread(0);
				break;
			}
		}
	}
	return true;
}
void CUDPServerDlg::OnBnClickedOk()
{ 
	HANDLE hthread = ::CreateThread(0, 0, thread, NULL, NULL, NULL);   //创建一个线程
}


void CUDPServerDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CUDPServerDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnCancel();
}
