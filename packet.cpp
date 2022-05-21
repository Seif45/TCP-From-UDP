#include "packet.h"
#include <string.h>

pkt crtPkt(char* data, int len, int seqno, int ackno, int flags){ //create a new packet with parameters
    pkt packet ;
    for(int i = 0 ;i < len; i++){
        (packet.payload)[i] = data[i];
    }
    packet.seqno = seqno;
    packet.ackno = ackno;
    packet.flags = flags;
    packet.len = len;
    packet.cksum = calcPktCksum(packet);
    return packet;
}

uint16_t calcPktCksum(pkt packet){ //calculate the checksum
    uint32_t sum = 0;
    for(int i = 0; i < strlen(packet.payload); i++){ //add all data
        sum += packet.payload[i];
    }
    sum += packet.len;
    sum += packet.seqno;
    sum += packet.ackno;
    sum += packet.flags;
    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    // Return the one's complement of sum
    return ( (uint16_t)(~sum)  );
}

bool cmprCksum(pkt packet){ //compare
    return packet.cksum == calcPktCksum(packet);
}