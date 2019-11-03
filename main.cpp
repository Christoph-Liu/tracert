#include <bits/stdc++.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "protocolHeader.h"
#include "trace.cpp"

#pragma comment(lib, "ws2_32.lib")

char ipAddress[255];

int main(int argc, char *argv[]) {
    SetConsoleOutputCP(65001);
    if(argc > 1) {
        strcpy(ipAddress, argv[1]);
    } else {
        strcpy(ipAddress, "www.baidu.com");
    }
    std::cout<<"Tracing route to "<<ipAddress<<" with a maximum of 30 hops."<<std::endl;
    Socket pSocket = Socket(ipAddress);
    u_short seq = 0;
    BYTE TTL = 1, MAXhops = 30;
    decodeRet ret;
    while(MAXhops--) { 
        pSocket.sendToGroup(TTL, seq);
        ret.seq = seq; 
        ret.timeseq = GetTickCount();
        if(pSocket.receiveGroup(ret)) {
            std::cout << std::setiosflags(std::ios::left) << std::setw(15) << seq <<std::resetiosflags(std::ios::left)
                << std::setiosflags(std::ios::right) << std::setw(15) << ret.timeseq << "ms" <<std::resetiosflags(std::ios::right)
                    << std::setiosflags(std::ios::right) << std::setw(30) << (inet_ntoa)(*(in_addr*)&ret.IP) <<std::resetiosflags(std::ios::right) << std::endl;
        } else {
            std::cout << std::setiosflags(std::ios::left) << std::setw(15) << seq <<std::resetiosflags(std::ios::left)
                << std::setiosflags(std::ios::right) << std::setw(15) << "*" <<std::resetiosflags(std::ios::right)
                    << std::setiosflags(std::ios::right) << std::setw(32) << "request timeout" <<std::resetiosflags(std::ios::right) << std::endl;
        }
        if(ret.IP == pSocket.getDestIP())
            break;
        seq++; TTL++;
    }
    std::cout << "finished." <<std::endl;
    return 0;
}