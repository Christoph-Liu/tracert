#pragma once

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

const int DEF_ICMP_DATA_SIZE=32;        /*ICMP报文默认数据字段长度*/
const int MAX_ICMP_PACKET_SIZE=1024;    /*ICMP报文最大长度（包括报头）*/
const DWORD DEF_ICMP_TIMEOUT=4000;      /*回显应答超时时间*/

typedef struct {
    union {
        unsigned char version;      /*版本*/
        unsigned char headLength;   /*首部长度*/
    };        
    unsigned char serviceType;      /*服务类型*/
    unsigned short totalLength;     /*总长度*/
    unsigned short label;           /*标识*/
    union {
        unsigned char tag;          /*标志*/
        unsigned short offset;      /*片偏移*/
    }; 
    unsigned char aliveTime;        /*生存时间*/
    unsigned char protocol;         /*协议类型*/
    unsigned short checksum;        /*首部校验和*/
    unsigned long soruceAddress;    /*源地址*/
    unsigned long targetAddress;    /*目的地址*/
}IPHeader;

typedef struct {
    BYTE type;                      /*类型*/
    unsigned char code;             /*代码*/
    unsigned short checksum;        /*校验和*/
    unsigned short id;              /*标识符*/
    unsigned short seq;             /*序列号*/
}ICMPHeader;

/*输出信息的定义*/
typedef struct {
    unsigned short seq;             /*序列号*/
    DWORD timeseq;                  /*返回时间*/
    u_long IP;                      /*返回报文的IP地址*/
}decodeRet; 

class Socket {
    public:
        Socket(char *ipAddress);
        ~Socket();
        void sendToGroup(BYTE TTL, u_short seq);
        bool receiveGroup(decodeRet &ret);
        bool decode(char *pBuffer, int pBufferSize, decodeRet &ret);
        u_short calChecksum(u_short *buffer, int tSize);
        u_long getDestIP();
    private:
        SOCKET pSocket;
        hostent *pHostIP;
        sockaddr_in pSourceAddress;
        sockaddr_in pDestAddress;
        /*发送缓冲区*/
        char pICMPSendBuffer[sizeof(ICMPHeader) + DEF_ICMP_DATA_SIZE];
        /*接收缓冲区*/
        char pICMPRecBuffer[MAX_ICMP_PACKET_SIZE];
};