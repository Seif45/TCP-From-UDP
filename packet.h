#include <iostream>

#define MAX_PKTSIZE 1024
#define MAX_SEQNUM 30720
#define CHUNK_SIZE 500
#define TIMEOUT 2
#define SSTHRESHOLD 8

using namespace std;

struct pkt { //data structure for the packets
    uint16_t cksum; //checksum
    uint16_t len; //data length
    uint32_t seqno;
    uint32_t ackno;
    uint16_t flags;

    enum EFlags //flags as 3 bits power of 2 so the OR between any of them gives new number
	{
		FLAG_SYN   =  0x1,
		FLAG_FIN   =  0x2,
		FLAG_ACK   =  0x4,
	};
    char payload [MAX_PKTSIZE];
};


pkt crtPkt(char *data, int len, int seqno, int ackno, int flags);
uint16_t calcPktCksum(pkt packet);
bool cmprCksum(pkt packet);