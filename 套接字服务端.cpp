
// UDPServerDlg.cpp : ʵ���ļ�
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


// CUDPServerDlg �Ի���



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


// CUDPServerDlg ��Ϣ�������

BOOL CUDPServerDlg::OnInitDialog()
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

void CUDPServerDlg::OnPaint()
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
HCURSOR CUDPServerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
//�߳�
DWORD _stdcall thread(LPVOID lpvoid)
{
	//WinSocket���ȵ��ö�̬���ӿ⣬��ʹ��WSAStartup������ʼ�����Լ��ڸú�����ָ���汾��
	WSADATA wsa;                          //WSA
	WSAStartup(MAKEWORD(2, 2), &wsa);     //��ʼ��{MAKEWORD(2,2)>���汾��Ϊ2,���汾��Ϊ2}
	sockaddr_in server_addr;
	memset((void*)&server_addr, 0, sizeof(server_addr));         //���
	SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);   //����tcp�׽���

	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");  //ָ��IP��ַ
	server_addr.sin_family = AF_INET;                           //ʹ��IPV4
	server_addr.sin_port = htons(8080);                       //ָ���˿�
	bind(server, (sockaddr*)&server_addr, sizeof(server_addr)); //���׽���

	listen(server, 20);                                          //����

	SOCKADDR client_addr;
	int len = sizeof(SOCKADDR);
	SOCKET conne = accept(server, &client_addr, &len);        //�������󲢴����ɿ�����(TCP)

	while (true)
	{
		char buffer[MAX_PATH] = { 0 };                          //��ʼ��������
		int buffer_length = MAX_PATH;                           //�趨��С
		if (recv(conne, buffer, buffer_length, 0)!=-1)
		{
			if (!conne)
			{
				MessageBox(NULL,_T("�����ж�"), NULL, NULL);
				ExitThread(0);
				break;
			}
			MessageBoxA(NULL, buffer, "���Կͻ��˵���Ϣ", NULL);
			int exitd = 0;
			if (buffer == "exit")
			{
				exitd = 1;
				break;
			}
			else
				send(conne, "Hello,I'm Server", 30, 0);                               //������Ϣ
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
	HANDLE hthread = ::CreateThread(0, 0, thread, NULL, NULL, NULL);   //����һ���߳�
}


void CUDPServerDlg::OnBnClickedButton1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}


void CUDPServerDlg::OnBnClickedCancel()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CDialogEx::OnCancel();
}
