#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <vector>
#include <pcap.h>
#include <cstring>
#include <cstdint>

struct sipPacket {
    uint64_t seq_no; // Timestamp-based sequence number
    std::vector<uint8_t> packetData;
};

bool isSIPPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen <= 42) return false; // 14 (Ethernet) + 20 (IP) + 8 (UDP)

    const uint8_t* ip_header = packet + 14;
    uint8_t protocol = ip_header[9];

    if (protocol != 17) return false; // UDP

    uint16_t src_port = (ip_header[20] << 8) | ip_header[21];
    uint16_t dst_port = (ip_header[22] << 8) | ip_header[23];

    if (src_port != 5060 && dst_port != 5060) return false; // Ensure SIP traffic

    const uint8_t* udp_payload = packet + 14 + 20 + 8; // Skip Ethernet, IP, and UDP headers
    int payload_length = header->caplen - (14 + 20 + 8);

    if (payload_length <= 0) return false; // No data, not a SIP packet

    // Check if the payload starts with a valid SIP message
    const char* sip_methods[] = {
        "INVITE", "REGISTER", "ACK", "BYE", "CANCEL", "OPTIONS", "PRACK",
        "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE",
        "SIP/2.0"
    };

    for (const char* method : sip_methods) {
        if (strncmp((const char*)udp_payload, method, strlen(method)) == 0) {
            return true; // SIP packet detected!
        }
    }

    return false;
}

// Function to serialize sipPacket
std::vector<uint8_t> serializePacket(const sipPacket& pkt) {
    std::vector<uint8_t> buffer(sizeof(pkt.seq_no) + pkt.packetData.size());
    std::memcpy(buffer.data(), &pkt.seq_no, sizeof(pkt.seq_no));
    std::memcpy(buffer.data() + sizeof(pkt.seq_no), pkt.packetData.data(), pkt.packetData.size());

    return buffer;
}

#endif // UTILS_H
