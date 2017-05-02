
// UDPclientDlg.cpp : ʵ���ļ�
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


// CUDPclientDlg �Ի���



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


// CUDPclientDlg ��Ϣ�������

BOOL CUDPclientDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CUDPclientDlg::OnPaint()
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
			c_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);   //����TCP�׽���

			memset((void*)&client_addr, 0, sizeof(client_addr));

			client_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
			client_addr.sin_family = AF_INET;
			client_addr.sin_port = htons(8080);

			//���ӷ������׽���
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
		MessageBox(_T("��������Ч��Ϣ!"));
}
