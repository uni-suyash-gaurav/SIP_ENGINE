#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <vector>
#include <pcap.h>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <sstream>

struct sipPacket {
    uint64_t seq_no; // Timestamp-based sequence number
    std::vector<uint8_t> packetData;
    std::string arrival_time;
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

std::vector<uint8_t> serializePacket(const sipPacket& pkt) {
    size_t arrivalTimeLen = pkt.arrival_time.size();
    size_t totalSize = sizeof(pkt.seq_no) + sizeof(size_t) + arrivalTimeLen + pkt.packetData.size();
    
    std::vector<uint8_t> buffer(totalSize);
    uint8_t* ptr = buffer.data();
    
    // Copy seq_no
    std::memcpy(ptr, &pkt.seq_no, sizeof(pkt.seq_no));
    ptr += sizeof(pkt.seq_no);

    // Copy arrival_time length
    std::memcpy(ptr, &arrivalTimeLen, sizeof(size_t));
    ptr += sizeof(size_t);

    // Copy arrival_time string
    std::memcpy(ptr, pkt.arrival_time.data(), arrivalTimeLen);
    ptr += arrivalTimeLen;

    // Copy packetData
    std::memcpy(ptr, pkt.packetData.data(), pkt.packetData.size());

    return buffer;
}


std::string getFormattedTimestamp(const struct timeval& ts) {
    char buffer[64];
    std::tm* timeinfo = std::localtime(&ts.tv_sec);
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    std::ostringstream oss;
    oss << buffer;
    return oss.str();
}

#endif // UTILS_H
