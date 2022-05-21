#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <thread>
#include <experimental/filesystem>
#include <sstream>
#include <iterator>
#include <fstream>
#include <sys/types.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "packet.h"

using namespace std;

void sendSYN(int connectSocket, string filename,  struct sockaddr_in servAddr);
pkt recvSYNACK(int connectSocket, struct sockaddr_in fromAddr);
void sendACK(int connectSocket, struct sockaddr_in servAddr, int ackno);
void StopAndWait(string filename, int connectSocket, struct sockaddr_in servAddr);
void GBN (string filename, int connectSocket, struct sockaddr_in servAddr, int expectedseqno);
pkt recvData (int connectSocket, struct sockaddr_in servAddr);
void sendFINACK(int connectSocket, struct sockaddr_in servAddr, int seqno, int ackno);

int main(int argc, char * argv[]){

    if (argc > 2){
        printf("Invalid Client\n");
        exit(-1);//terminate
    }

    int connectSocket; //socket to be able to connect to the server socket
    string connectIP; //address of the server to connect to
    int size;
    int port; //specified port or use the default
    string filename; //file that the client requesting from the server to send
    ifstream input("client.in"); //read client parameters
    if (!input){
        printf("File doesn't exist");
        exit(-1);
    }
    input >> connectIP; //server ip
    input >> port; //server known port no
    input >> filename; //name of requested file

    if(argc == 2){
        port = atoi(argv[2]); //custom port number
    }

    connectSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//Create datagram UDP socket
    if (connectSocket < 0) {//error
        printf("Failed to create a client socket\n");
        exit(-1);//terminate
    }
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));

    // Filling server information
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(connectIP.c_str());
    servAddr.sin_port = htons(port);

    sendSYN(connectSocket, filename, servAddr); //step 1 sends a datagram to the server to get a file giving its filename.

    pkt packet = recvSYNACK(connectSocket, servAddr); //receive the ACK sent in step 2
    while (packet.flags == 0){ //time out if ack not received until it is
        sendSYN(connectSocket, filename, servAddr); 
        packet = recvSYNACK(connectSocket, servAddr);
    }

    sendACK(connectSocket, servAddr, (packet.seqno)+(packet.len)); //send ack for 3-way handshake

    //StopAndWait(filename, connectSocket, servAddr); //SnW strategy
    GBN(filename, connectSocket, servAddr, (packet.seqno)+(packet.len)); //GBN strategy

    close(connectSocket); //close the connection
}

void sendSYN(int connectSocket, string filename,  struct sockaddr_in servAddr){ //SYN packet

    if (filename.length() >= CHUNK_SIZE) { 
        printf("File name is too long\n");
        exit(-1);//terminate
    }
    pkt pSYN = crtPkt(strdup(filename.c_str()), filename.size(), rand() % MAX_SEQNUM, 0, pkt::FLAG_SYN);
    // Send the packet to the server
    ssize_t numBytesSent = sendto(connectSocket, &pSYN, sizeof(pSYN), MSG_CONFIRM, (const struct sockaddr*)&servAddr, sizeof(servAddr));
}

pkt recvSYNACK(int connectSocket, struct sockaddr_in servAddr){ //ack for the SYN packet
    clock_t begin = clock();
    int flags = fcntl(connectSocket, F_GETFL);
    fcntl(connectSocket, F_SETFL, flags | O_NONBLOCK); //unblock for timeouts
    pkt pSYNACK;
    socklen_t servAddrLen = sizeof(servAddr);
    while ((clock() - begin) / CLOCKS_PER_SEC < TIMEOUT){ //incase the packet is lost
        ssize_t numBytesRcvd = recvfrom(connectSocket, &pSYNACK, sizeof(pSYNACK), MSG_WAITALL, (struct sockaddr *) &servAddr, &servAddrLen); //receive the response from the server
        if(cmprCksum(pSYNACK) && pSYNACK.flags == (pkt::FLAG_SYN | pkt::FLAG_ACK)){ //not corrupt and correct packet with correct flags
            return pSYNACK;
        }
    }
    string empty = "";
    pSYNACK= crtPkt(&empty[0], 1, 0, 0, 0);
    return pSYNACK;
}

void StopAndWait(string filename, int connectSocket, struct sockaddr_in servAddr){
    FILE *file = fopen(("SnW_"+filename).c_str(), "wa+"); //open the file to write data in
    pkt pData = recvData(connectSocket, servAddr); //recieve first segment
    while (pData.flags != pkt::FLAG_FIN){ //keep receiving until the packet has FIN flag
        sendACK(connectSocket, servAddr, (pData.seqno)+(pData.len)); //send ack for every packet received
        fwrite(pData.payload, sizeof(char), pData.len, file); //write to the file
        pData = recvData(connectSocket, servAddr);
    }
    sendFINACK(connectSocket, servAddr, (pData.ackno)+(pData.len), (pData.seqno)+(pData.len)); //send ACK for the last data packet
    fwrite(pData.payload, sizeof(char), pData.len, file);
    fclose(file); //close the file
}

void GBN (string filename, int connectSocket, struct sockaddr_in servAddr, int seqno){
    FILE *file = fopen(("GBN_"+filename).c_str(), "wa+");//open the file to write data in
    pkt pData = recvData(connectSocket, servAddr);//recieve first segment
    int expectedseqno = seqno % MAX_SEQNUM; 
    while (pData.flags != pkt::FLAG_FIN) {//keep receiving until the packet has FIN flag
        if (pData.seqno == expectedseqno){ //equals the expected
            expectedseqno = (expectedseqno + pData.len) % MAX_SEQNUM;//expected seq which is previous plus length of data
            sendACK(connectSocket, servAddr, expectedseqno);
            fwrite(pData.payload, sizeof(char), pData.len, file);
            pData = recvData(connectSocket, servAddr);
        }
    }
    sendFINACK(connectSocket, servAddr, (pData.ackno)+(pData.len), (pData.seqno)+(pData.len));
    fwrite(pData.payload, sizeof(char), pData.len, file);
    fclose(file);
}

pkt recvData (int connectSocket, struct sockaddr_in servAddr){ //receive packets with datagrams
    pkt pData;
    socklen_t servAddrLen = sizeof(servAddr);
    while (1){
        ssize_t numBytesRcvd = recvfrom(connectSocket, &pData, sizeof(pData), MSG_WAITALL, (struct sockaddr *) &servAddr, &servAddrLen);
        if(cmprCksum(pData) && ((pData.flags == pkt::FLAG_FIN) || (pData.flags == 0))){
            return pData;
        }
    }
}

void sendACK(int connectSocket, struct sockaddr_in servAddr, int ackno){
    string empty = "";
    pkt pACK= crtPkt(&empty[0], 1, 0, ackno % MAX_SEQNUM, pkt::FLAG_ACK);
    ssize_t numBytesSent = sendto(connectSocket, &pACK, sizeof(pACK), MSG_CONFIRM, (const struct sockaddr*)&servAddr, sizeof(servAddr));
}

void sendFINACK(int connectSocket, struct sockaddr_in servAddr, int seqno, int ackno){
    string empty = "";
    pkt pFINACK= crtPkt(&empty[0], 0,0, ackno % MAX_SEQNUM, pkt::FLAG_FIN | pkt::FLAG_ACK);
    ssize_t numBytesSent = sendto(connectSocket, &pFINACK, sizeof(pFINACK), MSG_CONFIRM, (const struct sockaddr*)&servAddr, sizeof(servAddr));
}