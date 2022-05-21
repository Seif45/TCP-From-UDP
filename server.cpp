#include <stdio.h>
#include <string.h>
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
#include <cmath>
#include <set>
#include <fcntl.h>
#include "packet.h"

using namespace std;

pkt recvSYN(int connectSocket, struct sockaddr_in &clntAddr);
void sendSYNACK(int seqno, int ackno, int connectSocket, struct sockaddr_in clntAddr);
void clientHandling(char* filename, int len, int connectSocket, struct sockaddr_in clntAddr, int seed, double proba, int seqno);
void StopAndWait(int connectSocket, struct sockaddr_in clntAddr, FILE *file, int seed, double proba, int fileSize, set<int> lostPktsIndices, int seqno);
void GBN(int connectSocket, struct sockaddr_in clntAddr, FILE *file, int seed, double proba, int fileSize, set<int> lostPktsIndices, int seqno);
bool timeout(clock_t begin);
void sendPKT(int connectSocket, pkt packet, struct sockaddr_in clntAddr);
pkt recvACK(int connectSocket, struct sockaddr_in clntAddr);
char *getChunk(FILE *file, int index, int fileSize);
set<int> getLostPktsIndices(int seed, double proba, int totalPkts);

int main(int argc, char * argv[]){
    if (argc != 1) { // Test for correct number of arguments
        printf("Invalid Server\n");
        exit(-1);//terminate
    }
    int port;
    int seed;
    double proba;
    struct sockaddr_in servAddr;

    ifstream input("server.in"); //file to read server parameters
    if (!input){
        printf("File doesn't exist");
        exit(-1);
    }
    input >> port; //known port no
    input >> seed; // random seed generator
    input >> proba; //PLP

    int connectSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//Create socket for incoming connections
    if (connectSocket == -1) {//error
        printf("Failed to create a server socket\n");
        exit(-1);//terminate
    }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = INADDR_ANY;
    servAddr.sin_port = htons(port);
    // Bind to the local address
    if (bind(connectSocket, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0){
        printf("Server socket bind error\n"); 
        exit(-1);
    }

    struct sockaddr_in  clntAddr; // Client address
    memset(&clntAddr, 0, sizeof(clntAddr));
    pkt packet = recvSYN(connectSocket, clntAddr); //it must has the SYN flag and no errors
    int seqno = rand() % MAX_SEQNUM;
    sendSYNACK(seqno, (packet.seqno)+(packet.len), connectSocket, clntAddr); //server sends an ACK for syn to the client
    clientHandling(packet.payload, packet.len, connectSocket, clntAddr, seed, proba, seqno+1); //handle the client

}

pkt recvSYN(int connectSocket, struct sockaddr_in &clntAddr){ //recieve requests from client with SYN flag
    pkt pSYN ;
    socklen_t clntAddrLen = sizeof(clntAddr);
    while (1){
        ssize_t numBytesRcvd = recvfrom(connectSocket, &pSYN, sizeof(pSYN), MSG_WAITALL, (struct sockaddr *) &clntAddr, &clntAddrLen);
        if(cmprCksum(pSYN) && pSYN.flags == pkt::FLAG_SYN){
            return pSYN;
        }
    }
}

void sendSYNACK(int seqno, int ackno, int connectSocket, struct sockaddr_in clntAddr){ //send ACK for the SYN
    string empty = "";
    pkt pSYNACK = crtPkt(&empty[0], 1, seqno, ackno % MAX_SEQNUM, pkt::FLAG_SYN | pkt::FLAG_ACK);
    ssize_t numBytesSent = sendto(connectSocket, &pSYNACK, sizeof(pSYNACK), MSG_CONFIRM, (struct sockaddr *) &clntAddr, sizeof(clntAddr));
}

void clientHandling(char* filename, int len, int connectSocket, struct sockaddr_in clntAddr, int seed, double proba, int seqno){
    FILE *file = fopen(filename, "rb"); //open the file requested by the client
    if (!file){
        printf("File doesn't exist");
        exit(-1);
    }
    fseek(file, 0, SEEK_END);
    int fileSize = ftell(file); //get the size of the file
    rewind(file);
    int totalPkts = ceil(fileSize * 1.0 / CHUNK_SIZE); //total no of packets
    set<int> lostPktsIndices = getLostPktsIndices(seed, proba, totalPkts); //indices of all lost packets to be simulated
    //StopAndWait(connectSocket, clntAddr, file, seed, proba, fileSize, lostPktsIndices, seqno);
    GBN(connectSocket, clntAddr, file, seed, proba, fileSize, lostPktsIndices, seqno);
    fclose(file);
    close(connectSocket);
}

void StopAndWait(int connectSocket, struct sockaddr_in clntAddr, FILE *file, int seed, double proba, int fileSize, set<int> lostPktsIndices, int seqno){
    int totalPkts = ceil(fileSize * 1.0 / CHUNK_SIZE);
    int nextseqno = seqno;
    pkt ack = recvACK(connectSocket, clntAddr); //ack for the 3-way handshake
    cout << lostPktsIndices.size() << " packets will be lost\n";
    for (int i = 0; i < totalPkts-1; i++){ //all data packets except the last one
        while (1){ //until data is sent
            if (lostPktsIndices.count(i)){ //to be simulated as lost
                cout << "Packet number " << i << " was lost\n";
                ack = recvACK(connectSocket, clntAddr); //received timed out ack
                lostPktsIndices.erase(i); // remove it from lost packets to be re transmitted
                cout << "Resending the packet number " << i << "\n";
            }
            else { //send it
                char *chunk = getChunk(file, i, fileSize);//appropriate size of data to be sent
                pkt packet = crtPkt(chunk, strlen(chunk),nextseqno % MAX_SEQNUM, 0, 0);
                nextseqno += strlen(chunk);
                sendPKT(connectSocket, packet, clntAddr);
                ack = recvACK(connectSocket, clntAddr);
                break;
            }
        }
    }
    while (1){ //last packet of data add FIN flag
        if (lostPktsIndices.count(totalPkts-1)){
            ack = recvACK(connectSocket, clntAddr);
            lostPktsIndices.erase(totalPkts-1);
        }
        else {
            char *chunk = getChunk(file, totalPkts-1, fileSize);
            pkt packet = crtPkt(chunk, strlen(chunk),nextseqno % MAX_SEQNUM, 0, pkt::FLAG_FIN); //with fin flag
            nextseqno += strlen(chunk);
            sendPKT(connectSocket, packet, clntAddr);
            ack = recvACK(connectSocket, clntAddr);
            break;
        }
    }
}

void GBN(int connectSocket, struct sockaddr_in clntAddr, FILE *file, int seed, double proba, int fileSize, set<int> lostPktsIndices, int seqno){
    pkt ack = recvACK(connectSocket, clntAddr); //3-way handshake
    int totalPkts = ceil(fileSize * 1.0 / CHUNK_SIZE);
    pkt packet;
    int base = 0; //base of the window
    bool sent = true;
    int i = 0; //index of lost packets
    int cwnd = 1; //window size
    vector<pkt> sentpkts; //already sent packets but not acked
    sentpkts.resize(fileSize+1);
    int nextseqno = seqno; //sequence numebr of next packet which is previous plus length of data
    int nextbaseno = 0; //number of next base in the window
    ofstream graph ; //graph points for the congestion control graph
    graph.open ("graph.txt");
    int counter = 1;
    graph << counter++ << " " << cwnd << endl;
    while (base != (totalPkts-1)){ //send all but last packet
        if (sent){
            char *chunk = getChunk(file, i, fileSize);
            packet = crtPkt(chunk, strlen(chunk),nextseqno % MAX_SEQNUM, 0, 0);
            nextseqno += strlen(chunk);
            i++;
            if (lostPktsIndices.count(i-1)){ //simulated as lost
                cout << "Packet number " << i-1 << " was lost\n";
                lostPktsIndices.erase(i-1);
                cwnd = 1;
                graph << counter++ << " " << cwnd << endl;
                sent = false;
                cout << "Resending the packet number " << i-1 << "\n";
                continue;
            }
        }
        bool flag = false;
        if ((nextbaseno < base + cwnd)){ //can send more
            sentpkts[nextbaseno] = packet; //store it cuz not acked yet
            sendPKT(connectSocket, packet, clntAddr);
            nextbaseno++;
            flag = true;
            sent = true;
        }
        if (!flag){
            sent = false;
        }
        pkt ack = recvACK(connectSocket, clntAddr); //receive ack if any
        if (ack.flags == pkt::FLAG_ACK){
            base = base + 1;
            if (cwnd <= SSTHRESHOLD/2){
                cwnd *= 2;
                graph << counter++ << " " << cwnd << endl;
            }
            else if (cwnd < totalPkts){
                cwnd += 1;
                graph << counter++ << " " << cwnd << endl;
            }
        }
    }
    while (1){ //last packet with FIN flag
        if (lostPktsIndices.count(totalPkts-1)){
            ack = recvACK(connectSocket, clntAddr);
            lostPktsIndices.erase(totalPkts-1);
        }
        else {
            char *chunk = getChunk(file, totalPkts-1, fileSize);
            pkt packet = crtPkt(chunk, strlen(chunk),nextseqno % MAX_SEQNUM, 0, pkt::FLAG_FIN);
            nextseqno += strlen(chunk);
            sendPKT(connectSocket, packet, clntAddr);
            ack = recvACK(connectSocket, clntAddr);
            break;
        }
    }
    graph.close();
}

void sendPKT(int connectSocket, pkt packet, struct sockaddr_in clntAddr){ //send data packets
    ssize_t numBytesSent = sendto(connectSocket, &packet, sizeof(packet), MSG_CONFIRM, (struct sockaddr *) &clntAddr, sizeof(clntAddr));
}

pkt recvACK(int connectSocket, struct sockaddr_in clntAddr){ //receives acks
    clock_t begin = clock();
    int flags = fcntl(connectSocket, F_GETFL);
    fcntl(connectSocket, F_SETFL, flags | O_NONBLOCK);
    pkt ack;
    socklen_t clntAddrLen = sizeof(clntAddr);
    while (((clock() - begin) / CLOCKS_PER_SEC) < TIMEOUT) { // time out timer
        ssize_t numBytesRcvd = recvfrom(connectSocket, &ack, sizeof(ack), MSG_WAITALL, (struct sockaddr *) &clntAddr, &clntAddrLen);
        if(cmprCksum(ack) && ack.flags == pkt::FLAG_ACK){
            return ack;
        }
    }
    string empty = "";
    ack= crtPkt(&empty[0], 1, 0, 0, 0);
    return ack;
}

char *getChunk(FILE *file, int index, int fileSize){ //get the in order chunk of data
    int chunkSize = min(CHUNK_SIZE, fileSize - (index * CHUNK_SIZE));
    char *chunk = (char*) malloc(chunkSize);
    fseek(file, index * CHUNK_SIZE, SEEK_SET);
    fread (chunk, sizeof(char), chunkSize, file);
    return chunk;
}

set<int>  getLostPktsIndices(int seed, double proba, int totalPkts){ //indices of all lost packets to be simulated
    int totalLostPkts = ceil(proba * totalPkts);
    set<int> indices;
    srand(seed);
    for (int i = 0 ; i < totalLostPkts ; i++){
        int index = rand() % totalPkts;
        if (indices.count(index) == 0){
            indices.insert(index);
        }
        else {
            i--;
        }
    }
    return indices;
}