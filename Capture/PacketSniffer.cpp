#include "SIPPacketQueue.h"
#include <iostream>
#include <pcap.h>
#include <ace/Unbounded_Queue.h>

bool isSIPPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen < 42) return false; // 14 bytes ethernet header + 20 bytes IP header + 8 bytes UDP header
    const uint8_t* ip_header = packet + 14;
    uint8_t protocol = ip_header[9];
    uint16_t src_port = ip_header[20] << 8 | ip_header[21]; // 2 bytes
    uint16_t dst_port = ip_header[22] << 8 | ip_header[23]; // 2 bytes
    return (protocol == 17 && (src_port == 5060 || dst_port == 5060));
}

void filterSIPPackets(const char* filename){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        std::cerr << "Error: " << errbuf << std::endl;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (pcap_next_ex(pcap, &header, &packet) == 1) {
        if (isSIPPacket(header, packet)) {
            sipPacket pkt;
            pkt.seq_no = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
            pkt.packetData.assign(packet + 14, packet + header->caplen);

            // std::cout << pkt.packetData.size() << " " << header->caplen << std::endl;
            
            // Push directly into the queue
            SIPPacketQueue::getInstance().enqueue(pkt);
        }
    }
    pcap_close(pcap);
}

int main() {
    const char* filename = "../USS_test_Oneway_audio.pcapng";
    filterSIPPackets(filename);

    while(!SIPPacketQueue::getInstance().isEmpty()) {
        sipPacket pkt;
        SIPPacketQueue::getInstance().dequeue(pkt);
        std::cout << pkt.seq_no << ", " << pkt.packetData.size() << " Bytes" << std::endl;
    }
    return 0;
}
