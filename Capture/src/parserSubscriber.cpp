#include <iostream>
#include <nats/nats.h>
#include <thread>
#include <chrono>
#include <cstring>
#include <vector>

#define SUBJECT_NAME "sip.packets"
#define STREAM_NAME "sip_packets"
#define CONSUMER_NAME "sip_packet_consumer"

struct sipPacket {
    uint64_t seq_no; // Timestamp-based sequence number
    std::vector<uint8_t> packetData;
    std::string arrival_time;
};

sipPacket deserializePacket(const uint8_t* data, size_t length) {
    sipPacket pkt;
    const uint8_t* ptr = data;

    // Read seq_no
    std::memcpy(&pkt.seq_no, ptr, sizeof(pkt.seq_no));
    ptr += sizeof(pkt.seq_no);

    // Read arrival_time length
    size_t arrivalTimeLen;
    std::memcpy(&arrivalTimeLen, ptr, sizeof(size_t));
    ptr += sizeof(size_t);

    // Read arrival_time string
    pkt.arrival_time.assign(reinterpret_cast<const char*>(ptr), arrivalTimeLen);
    ptr += arrivalTimeLen;

    // Read packetData
    size_t packetDataLen = length - (sizeof(pkt.seq_no) + sizeof(size_t) + arrivalTimeLen);
    pkt.packetData.assign(ptr, ptr + packetDataLen);

    return pkt;
}


int main(){
    natsStatus s;
    natsConnection *conn = NULL;
    jsCtx *js = NULL;
    jsErrCode jerr;
    jsConsumerInfo *ci = NULL;
    natsSubscription *sub = NULL;

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

    // Define consumer configuration
    jsConsumerConfig cfg;
    jsConsumerConfig_Init(&cfg);
    cfg.Durable = CONSUMER_NAME;
    cfg.AckPolicy = js_AckExplicit;
    cfg.DeliverPolicy = js_DeliverAll;
    cfg.FilterSubject = SUBJECT_NAME;
    cfg.MaxDeliver = 1;  // Ensure each message is only delivered once
    cfg.AckWait = 5000000000; // 5 seconds
    cfg.ReplayPolicy = js_ReplayInstant; // Don't replay old messages
    cfg.MaxAckPending = 10; // Maximum number of unacknowledged messages

    // Create or update the durable consumer
    s = js_AddConsumer(&ci, js, STREAM_NAME, &cfg, NULL, &jerr);
    if (s != NATS_OK) {
        std::cerr << "Error adding consumer: " << natsStatus_GetText(s)
                  << " - JetStream error code: " << jerr << std::endl;
        natsConnection_Destroy(conn);
        return 1;
    }

    // Subscribe to the durable consumer
    jsSubOptions subOpts;
    jsSubOptions_Init(&subOpts);

    s = js_PullSubscribe(&sub, js, SUBJECT_NAME, CONSUMER_NAME, NULL, &subOpts, &jerr);
    if (s != NATS_OK) {
        std::cerr << "Error subscribing: " << natsStatus_GetText(s)
                  << " - JetStream error code: " << jerr << std::endl;
        natsConnection_Destroy(conn);
        return 1;
    }

    std::cout << "Parser is listening for messages." << std::endl;

    while (true) {
        // Fetch up to 5 messages, wait up to 1 second
        natsMsgList list;
        natsStatus status = natsSubscription_Fetch(&list,sub, 5, 1000,NULL );
 
        if (status == NATS_OK) {
            for (int i = 0; i < list.Count; i++) {
                const uint8_t* data = (const uint8_t*)natsMsg_GetData(list.Msgs[i]);
                size_t length = natsMsg_GetDataLength(list.Msgs[i]);
                sipPacket pkt = deserializePacket(data, length);


                std::cout << pkt.seq_no << std::endl;
                std::cout << pkt.arrival_time << std::endl;
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


                // Simulate processing delay
                std::this_thread::sleep_for(std::chrono::seconds(1));
 
                // Acknowledge the message
                natsMsg_Ack(list.Msgs[i], NULL);
            }
            natsMsgList_Destroy(&list);
        } else {
            std::cerr << "Waiting for new message..." << std::endl;
        }
    }

    // Cleanup
    natsSubscription_Destroy(sub);
    jsConsumerInfo_Destroy(ci);
    jsCtx_Destroy(js);
    natsConnection_Destroy(conn);
    nats_Close();

    return 0;
}
