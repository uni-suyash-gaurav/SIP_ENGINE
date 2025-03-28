#include "utils.h"
#include <nats/nats.h>
#include <string>

#define SUBJECT_NAME "sip.packets"
#define STREAM_NAME "sip_packets"

natsStatus s;
natsConnection *conn = NULL;
jsCtx *js = NULL;
jsErrCode jerr;
jsStreamInfo *si = NULL;

void NATSInitialize(){
    // Connect to NATS server
    s = natsConnection_ConnectTo(&conn, "nats://localhost:4222");
    if (s != NATS_OK) {
        std::cerr << "Error connecting: " << natsStatus_GetText(s) << std::endl;
        return;
    }

    // Create JetStream context
    s = natsConnection_JetStream(&js, conn, NULL);
    if (s != NATS_OK) {
        std::cerr << "Error creating JetStream context: " << natsStatus_GetText(s) << std::endl;
        natsConnection_Destroy(conn);
        return;
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
            return;
        }
    } else {
        std::cout << "Stream already exists." << std::endl;
    }
}

void publishPacketToNats(std::vector<uint8_t> serializedData) {
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

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (isSIPPacket(header, packet)) {
        sipPacket pkt;
        pkt.seq_no = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
        pkt.packetData.assign(packet + 14, packet + header->caplen);
        pkt.arrival_time = getFormattedTimestamp(header->ts);
        // std::cout << pkt.seq_no << " " << pkt.packetData.size() << " " << header->caplen << std::endl;

        // Serialize packet
        std::vector<uint8_t> serializedData = serializePacket(pkt);

        // Publish to stream
        publishPacketToNats(serializedData);
    }
}

void captureLivePackets(const char* interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open live capture on the specified interface
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Error: " << errbuf << std::endl;
        return;
    }

    // Initialize JetStream NATS
    NATSInitialize();

    // Capture packets indefinitely
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Close the pcap handle
    pcap_close(handle);
}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    // Find all available network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

     // Print available network interfaces
     std::cout << "Available network interfaces:" << std::endl;
     pcap_if_t* d;
     int i = 0;
     for (d = alldevs; d != NULL; d = d->next) {
         std::cout << i++ << ": " << d->name;
         if (d->description)
             std::cout << " (" << d->description << ")";
         std::cout << std::endl;
     }

     if (i == 0) {
        std::cerr << "No interfaces found!" << std::endl;
        return 1;
    }

    // Select the first interface (eth)
    const char* interface = alldevs->name;
    // const char* interface = "any";
    std::cout << "Capturing on interface: " << interface << std::endl;

    // Start live capture
    captureLivePackets(interface);

    return 0;
}
