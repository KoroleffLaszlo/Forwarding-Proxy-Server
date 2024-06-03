#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <tchar.h>

#pragma commment(lib, "Ws2_32.lib")

#define ADDRESS "127.0.0.1"
#define PORT_NUM 80

int main(const int argc, const char *argv[]){

    // init WINSOCK
    WSADATA wsaData;
    int wsaStart = WSAStartup(MAKEWORD(2,2), &wsaData);

    if (wsaStart){ //not zero -> ERROR
        std::cout << "WSAStartup failed" << wsaStart << std::endl;
        ExitProcess(EXIT_FAILURE);
    }
    
    //creating socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    
    if(serverSocket == INVALID_SOCKET){
        std::cout << "Socket initialization failed" << serverSocket << std::endl;
        WSACleanup();
        ExitProcess(EXIT_FAILURE);
    }

    //binding socket to address
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT_NUM);
    if(InetPton(AF_INET, _T(ADDRESS), &address.sin_addr.s_addr) == SOCKET_ERROR){ // converting IP into bits
        std::cout << "IP to bit conversion failed" << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        ExitProcess(EXIT_FAILURE);
    }

    if(bind(serverSocket, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR){
        std::cout << "Bind failed" << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        ExitProcess(EXIT_FAILURE);
    }



    ExitProcess(EXIT_SUCCESS);
}