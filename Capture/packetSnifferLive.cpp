#include <iostream>
#include <pcap.h>
#include <ace/Unbounded_Queue.h>
#include <vector>
#include <mutex>
#include <string>
#include <regex>

struct sipPacket {
    uint64_t seq_no; // Timestamp-based sequence number
    std::vector<uint8_t> packetData;
};

ACE_Unbounded_Queue<sipPacket> sipPacketQueue;
std::mutex mtx;

bool isSIPPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen < 42) return false; // Ethernet (14) + IP (20) + UDP (8)
    const uint8_t* ip_header = packet + 14;
    uint8_t protocol = ip_header[9];
    uint16_t src_port = (ip_header[20] << 8) | ip_header[21];
    uint16_t dst_port = (ip_header[22] << 8) | ip_header[23];

    return (protocol == 17 && (src_port == 5060 || dst_port == 5060));
}

// Function to extract SIP details (extension, IP, and message type)
void extractSIPDetails(const std::string& payload) {
    std::regex sip_regex(R"(From:\s*<sip:(\d+)@([\d\.]+)>)"); // Extract extension and IP
    std::smatch match;

    std::string extension, ip, sipMessageType;

    // Extract extension & IP
    if (std::regex_search(payload, match, sip_regex)) {
        extension = match[1];
        ip = match[2];
    }

    // Extract SIP message type (first line of SIP message)
    std::istringstream stream(payload);
    std::getline(stream, sipMessageType); // Get first line

    // Print extracted information
    std::cout << "SIP Message: " << sipMessageType << "\n";
    if (!extension.empty() && !ip.empty()) {
        std::cout << "Extension: " << extension << ", SIP URI IP: " << ip << std::endl;
    }
    std::cout << "----------------------------------" << std::endl;
}

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (isSIPPacket(header, packet)) {
        sipPacket pkt;
        pkt.seq_no = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
        pkt.packetData.assign(packet + 14, packet + header->caplen);
        // std::cout << pkt.seq_no << " " << pkt.packetData.size() << " " << header->caplen << std::endl;

        // Get UDP payload (SIP message)
        const uint8_t* sip_payload = packet + 42; // Ethernet (14) + IP (20) + UDP (8)
        size_t sip_length = header->caplen - 42;
        // Convert payload to string for regex processing
        std::string payload(reinterpret_cast<const char*>(sip_payload), sip_length);
        // Extract details
        extractSIPDetails(payload);

        std::lock_guard<std::mutex> lock(mtx);
        sipPacketQueue.enqueue_tail(pkt);
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

    // Select the first interface
    const char* interface = alldevs->name;
    // const char* interface = "any";
    std::cout << "Capturing on interface: " << interface << std::endl;

    // Start live capture
    captureLivePackets(interface);

    return 0;
}
