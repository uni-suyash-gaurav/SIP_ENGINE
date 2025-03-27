#include <iostream>
#include <pcap.h>
#include <nats/nats.h>
#include <arpa/inet.h> // For ntohs()
#include <cstdint>
#include <cstring>
#include <vector>

#define SUBJECT_NAME "sip.packets"
#define STREAM_NAME "sip_packets"

struct sipPacket {
    uint64_t seq_no; // Timestamp-based sequence number
    std::vector<uint8_t> packetData;
};

bool isSIPPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen <= 42) return false; // Minimum valid Ethernet + IP + UDP packet

    const uint8_t* ip_header = packet + 14; // IP header starts after Ethernet header
    uint8_t protocol = ip_header[9];

    if (protocol != 17) return false; // Ensure it's UDP

    // Extract source and destination ports
    uint16_t src_port = (ip_header[20] << 8) | ip_header[21];
    uint16_t dst_port = (ip_header[22] << 8) | ip_header[23];

    if (src_port != 5060 && dst_port != 5060) return false;

    // Calculate UDP payload start position
    const uint8_t* udp_payload = packet + 14 + 20 + 8;
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

// Function to serialize sipPacket
std::vector<uint8_t> serializePacket(const sipPacket& pkt) {
    std::vector<uint8_t> buffer(sizeof(pkt.seq_no) + pkt.packetData.size());

    // Copy seq_no into buffer
    std::memcpy(buffer.data(), &pkt.seq_no, sizeof(pkt.seq_no));

    // Copy packetData into buffer after seq_no
    std::memcpy(buffer.data() + sizeof(pkt.seq_no), pkt.packetData.data(), pkt.packetData.size());

    return buffer;
}

int main() {
    natsStatus s;
    natsConnection *conn = NULL;
    jsCtx *js = NULL;
    jsErrCode jerr;
    jsStreamInfo *si = NULL;

    // Connect to NATS server
    s = natsConnection_ConnectTo(&conn, "nats://localhost:4222");
    if (s != NATS_OK) {
        std::cerr << "Error connecting: " << natsStatus_GetText(s) << std::endl;
        return 1;
    }

    // Create JetStream context
    s = natsConnection_JetStream(&js, conn, NULL);
    if (s != NATS_OK) {
        std::cerr << "Error creating JetStream context: " << natsStatus_GetText(s) << std::endl;
        natsConnection_Destroy(conn);
        return 1;
    }

    // Check if stream already exists
    s = js_GetStreamInfo(&si, js, STREAM_NAME, NULL, &jerr);
    if (s != NATS_OK) {
        std::cout << "Stream does not exist, creating new stream..." << std::endl;

        // Define stream configuration
        jsStreamConfig cfg;
        jsStreamConfig_Init(&cfg);
        cfg.Name = STREAM_NAME;
        const char *subjects[] = {SUBJECT_NAME};
        cfg.Subjects = subjects;
        cfg.SubjectsLen = 1;
        cfg.Storage = js_MemoryStorage;
        cfg.Retention = js_WorkQueuePolicy;  // This ensures messages are removed after being received

        // Add the stream
        s = js_AddStream(&si, js, &cfg, NULL, &jerr);
        if (s != NATS_OK) {
            std::cerr << "Error adding stream: " << natsStatus_GetText(s)
                    << " - JetStream error code: " << jerr << std::endl;
            natsConnection_Destroy(conn);
            return 1;
        }
    } else {
        std::cout << "Stream already exists." << std::endl;
    }

    const char* filename = "../USS_test_Oneway_audio.pcapng";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        std::cerr << "Error: " << errbuf << std::endl;
        return 1;
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
            // Serialize packet
            std::vector<uint8_t> serializedData = serializePacket(pkt);
            
            // Publish a message
            jsPubAck *pa = NULL;
            s = js_Publish(&pa, js, SUBJECT_NAME, serializedData.data(), serializedData.size(), NULL, &jerr);
            if (s != NATS_OK) {
                std::cerr << "Error publishing message: " << natsStatus_GetText(s)
                        << " - JetStream error code: " << jerr << std::endl;
            } else {
                std::cout << "Published message with sequence: " << pa->Sequence << std::endl;
            }
            jsPubAck_Destroy(pa);
        }
    }
    pcap_close(pcap); 

    // Clean up
    jsStreamInfo_Destroy(si);
    jsCtx_Destroy(js);
    natsConnection_Destroy(conn);
    nats_Close();

    return (s == NATS_OK) ? 0 : 1;
}
