#include <bits/stdc++.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "protocolHeader.h"
#pragma comment(lib, "ws2_32.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

const BYTE ICMP_ECHO_REQUEST=8;   //请求回显报文
const BYTE ICMP_ECHO_REPLY=0;     //回显应答报文
const BYTE ICMP_TIMEOUT=11;       //传输超时报文

Socket::Socket(char *ipAddress) {
    WSADATA pWSAdata;
    if(WSAStartup(MAKEWORD(2,2), &pWSAdata) != 0) {
        printf("初始化winsock库失败，程序将退出!\n");
        std::cout << WSAGetLastError() << std::endl;
        exit(0);
    }
    pSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(pSocket == INVALID_SOCKET) {
        printf("初始化socket失败，程序将退出!\n");
        std::cout << WSAGetLastError() << std::endl;
        exit(0);
    }
    u_long ulDestIP = inet_addr(ipAddress);
    /*根据域名获取IP地址*/
    if(ulDestIP == INADDR_NONE) {
        pHostIP = gethostbyname(ipAddress);
        if(pHostIP)
            ulDestIP = (*(in_addr *)(pHostIP->h_addr_list[0])).S_un.S_addr;
        else
            ulDestIP = NULL;
    }
    if(ulDestIP == NULL) {
        printf("无效的域名或地址，程序将退出!\n");
        exit(0);
    }
    pDestAddress.sin_family = AF_INET;
    pDestAddress.sin_addr.S_un.S_addr = ulDestIP;
    /*接收限时*/
    int ret = setsockopt(pSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&DEF_ICMP_TIMEOUT, sizeof(DEF_ICMP_TIMEOUT));
    if(ret) {
        printf("设定接收限时失败，程序将退出!\n");
        std::cout << WSAGetLastError() << std::endl;
        exit(0);
    }
    /*发送限时*/
    ret = setsockopt(pSocket, SOL_SOCKET, SO_SNDTIMEO, (char *)&DEF_ICMP_TIMEOUT, sizeof(DEF_ICMP_TIMEOUT));
    if(ret) {
        printf("设定发送限时失败，程序将退出!\n");
        std::cout << WSAGetLastError() << std::endl;
        exit(0);
    }
}

Socket::~Socket() {
    closesocket(pSocket);
    WSACleanup();
}

u_short Socket::calChecksum(u_short *buffer, int tSize) {
    u_long checksum = 0;
    while(tSize > 1) {
        checksum += *buffer++;
        tSize -= sizeof(u_short);
    }
    if(tSize) {
        /*处理奇数个16bits段*/
        checksum += *(u_short *)buffer;
    }
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    return (u_short)(~checksum);
}

bool Socket::decode(char *pBuffer, int pBufferSize, decodeRet &ret) {  
    IPHeader *ipheader = (IPHeader *)pBuffer;
    int ipheaderLen = (ipheader->headLength & 0xf) * 4;
    if((int)(ipheaderLen + sizeof(ICMPHeader)) > pBufferSize)
        return false;
    u_short pId, pSeq;
    ICMPHeader *icmpheader = (ICMPHeader *)(pBuffer + ipheaderLen);
    if(icmpheader->type == ICMP_ECHO_REPLY) {
        pId = icmpheader->id;
        pSeq = icmpheader->seq; 
    } else if(icmpheader->type == ICMP_TIMEOUT) {
        IPHeader *innerIpheader = (IPHeader *)(pBuffer + ipheaderLen + sizeof(ICMPHeader));
        int innerIpheaderLen = (innerIpheader->headLength & 0xf) * 4;
        ICMPHeader *pinnerIcmpheader = (ICMPHeader *)(pBuffer + ipheaderLen + sizeof(ICMPHeader) + innerIpheaderLen);
        pId = pinnerIcmpheader->id;
        pSeq = pinnerIcmpheader->seq;
    } else {
        return false;
    }
    if(pId != (u_short)GetCurrentProcessId() || pSeq != ret.seq) {
        return false;
    }
    ret.IP = ipheader->soruceAddress;
    ret.timeseq = GetTickCount() - ret.timeseq;
    return true;
}

void Socket::sendToGroup(BYTE TTL, u_short seq) {
    BYTE pTTL = TTL;
    int ret = setsockopt(pSocket, IPPROTO_IP, IP_TTL, (char *)&pTTL, sizeof(pTTL));
    if(ret == -1) {
        std::cout << "设置第" <<seq << "个分组的TTL时失败，程序将退出!" << std::endl;
        std::cout << WSAGetLastError() << std::endl;
        exit(0);
    }
    memset(pICMPSendBuffer, 0, sizeof(pICMPSendBuffer));
    ICMPHeader *picmpheader = (ICMPHeader *)pICMPSendBuffer;
    picmpheader->type = ICMP_ECHO_REQUEST;
    picmpheader->code = 0;
    picmpheader->id = (u_short)GetCurrentProcessId();
    memset(pICMPSendBuffer + sizeof(ICMPHeader), 'E', DEF_ICMP_DATA_SIZE);
    picmpheader->checksum = 0;
    picmpheader->seq = seq;
    picmpheader->checksum = Socket::calChecksum((u_short *)pICMPSendBuffer, sizeof(ICMPHeader) + DEF_ICMP_DATA_SIZE);
    ret = sendto(pSocket, pICMPSendBuffer, sizeof(pICMPSendBuffer), 0, (sockaddr *)&pDestAddress, sizeof(pDestAddress));
    if(ret == -1) {
        std::cout << "发送第" <<seq << "个分组时失败，程序将退出!" << std::endl;
        std::cout << WSAGetLastError() << std::endl;
        exit(0);
    }
}

bool Socket::receiveGroup(decodeRet &ret) {
    while(true) {
        sockaddr from;
        int fromAddressLen = sizeof(from), pRecvDataLen;
        pRecvDataLen = recvfrom(pSocket, pICMPRecBuffer, MAX_ICMP_PACKET_SIZE, 0, (sockaddr *)&from, (int *)&fromAddressLen);
        if(pRecvDataLen > 0) {
            if(Socket::decode(pICMPRecBuffer, pRecvDataLen , ret)){
                return true;
            }
        } else if(WSAGetLastError() == WSAETIMEDOUT) {
            return false;
        }
    }
}

u_long Socket::getDestIP() {
    return pDestAddress.sin_addr.S_un.S_addr;
}