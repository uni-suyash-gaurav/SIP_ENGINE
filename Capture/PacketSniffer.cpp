#include "SIPPacketQueue.h"
#include <iostream>
#include <pcap.h>
#include <ace/Unbounded_Queue.h>
#include <arpa/inet.h> // For ntohs()
#include <cstdint>
#include <cstring>

bool isSIPPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen <= 42) return false; // Minimum valid Ethernet + IP + UDP packet

    const uint8_t* ip_header = packet + 14; // IP header starts after Ethernet header
    uint8_t protocol = ip_header[9];

    if (protocol != 17) return false; // Ensure it's UDP

    // Extract source and destination ports
    uint16_t src_port = (ip_header[20] << 8) | ip_header[21];
    uint16_t dst_port = (ip_header[22] << 8) | ip_header[23];

    if (src_port != 5060 && dst_port != 5060) return false; // Ensure SIP traffic

    // Calculate UDP payload start position
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

    return false; // Not a SIP packet
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
            // pkt.packetData = (char*) packet + 14;
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

        std::cout << pkt.seq_no << ", " << std::endl;

        int protocol = (int)pkt.packetData[9];
        // Extract source & destination IP (IP Header: bytes 12-15 for src, 16-19 for dest)
        char srcIP[16], destIP[16];
        snprintf(srcIP, sizeof(srcIP), "%d.%d.%d.%d",
                pkt.packetData[12], pkt.packetData[13], pkt.packetData[14], pkt.packetData[15]);
        snprintf(destIP, sizeof(destIP), "%d.%d.%d.%d",
                pkt.packetData[16], pkt.packetData[17], pkt.packetData[18], pkt.packetData[19]);

        // Extract source & destination port (Transport Layer: bytes 20-23)
        uint16_t srcPort = (pkt.packetData[20] << 8) | pkt.packetData[21];
        uint16_t destPort = (pkt.packetData[22] << 8) | pkt.packetData[23];

        // Print extracted values
        std::cout << "Protocol: " << (protocol == 17 ? "UDP" : "TCP") << std::endl;
        std::cout << "Source IP: " << srcIP << " | Source Port: " << srcPort << std::endl;
        std::cout << "Destination IP: " << destIP << " | Destination Port: " << destPort << std::endl;

        // Define SIP payload offset (Ethernet + IP + UDP)
        size_t sip_offset = 20 + 8; // Start of SIP message
        std::cout << "SIP Packet Data: " << std::endl;
        // Print SDP payload from SIP message (skip headers)
        std::string sipData = "";
        for (size_t i = sip_offset; i < pkt.packetData.size(); ++i) {
            sipData += (char)pkt.packetData[i]; // Convert byte to char for readability
        }
        std::cout << sipData << std::endl;
    }
    return 0;
}


// #include <iostream>
// #include <vector>
// #include <cstring>
// #include <nats/nats.h>
// #include <pcap.h>

// #define SUBJECT_NAME "sip.packets"

// struct sipPacket {
//     uint64_t seq_no; // Timestamp-based sequence number
//     std::vector<uint8_t> packetData;
// };

// bool isSIPPacket(const struct pcap_pkthdr* header, const u_char* packet) {
//     if (header->caplen < 42) return false; // 14 bytes ethernet header + 20 bytes IP header + 8 bytes UDP header
//     const uint8_t* ip_header = packet + 14;
//     uint8_t protocol = ip_header[9];
//     uint16_t src_port = ip_header[20] << 8 | ip_header[21]; // 2 bytes
//     uint16_t dst_port = ip_header[22] << 8 | ip_header[23]; // 2 bytes
//     return (protocol == 17 && (src_port == 5060 || dst_port == 5060));
// }

// // Function to serialize sipPacket
// std::vector<uint8_t> serializePacket(const sipPacket& pkt) {
//     std::vector<uint8_t> buffer(sizeof(pkt.seq_no) + pkt.packetData.size());

//     // Copy seq_no into buffer
//     std::memcpy(buffer.data(), &pkt.seq_no, sizeof(pkt.seq_no));

//     // Copy packetData into buffer after seq_no
//     std::memcpy(buffer.data() + sizeof(pkt.seq_no), pkt.packetData.data(), pkt.packetData.size());

//     return buffer;
// }

// int main() {
//     natsStatus s;
//     natsConnection* conn = NULL;
//     jsCtx* js = NULL;
//     jsErrCode jerr;

//     // Connect to NATS
//     s = natsConnection_ConnectTo(&conn, "nats://localhost:4222");
//     if (s != NATS_OK) {
//         std::cerr << "NATS Connection Failed: " << natsStatus_GetText(s) << std::endl;
//         return 1;
//     }

//     // Create JetStream context
//     s = natsConnection_JetStream(&js, conn, NULL);
//     if (s != NATS_OK) {
//         std::cerr << "Error creating JetStream context: " << natsStatus_GetText(s) << std::endl;
//         natsConnection_Destroy(conn);
//         return 1;
//     }

//     // Open pcap file
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t* pcap = pcap_open_offline("../USS_test_Oneway_audio.pcapng", errbuf);
//     if (!pcap) {
//         std::cerr << "Failed to open pcap file: " << errbuf << std::endl;
//         return 1;
//     }

//     struct pcap_pkthdr* header;
//     const u_char* packet;
    
//     while (pcap_next_ex(pcap, &header, &packet) == 1) {
//         if (isSIPPacket(header, packet)) { // Assuming you have isSIPPacket function
//             sipPacket pkt;
//             pkt.seq_no = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
//             pkt.packetData.assign(packet + 14, packet + header->caplen);

//             // Serialize packet
//             std::vector<uint8_t> serializedData = serializePacket(pkt);

//             // Publish message
//             jsPubAck* pa = NULL;
//             s = js_Publish(&pa, js, SUBJECT_NAME, serializedData.data(), serializedData.size(), NULL, &jerr);
//             if (s == NATS_OK) {
//                 std::cout << "Published SIP Packet with seq_no: " << pkt.seq_no << std::endl;
//             } else {
//                 std::cerr << "Error publishing message: " << natsStatus_GetText(s) << std::endl;
//             }

//             jsPubAck_Destroy(pa);
//         }
//     }

//     // Cleanup
//     pcap_close(pcap);
//     jsCtx_Destroy(js);
//     natsConnection_Destroy(conn);
//     nats_Close();

//     return 0;
// }
