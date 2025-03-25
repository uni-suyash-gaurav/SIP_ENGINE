#ifndef SIP_PACKET_QUEUE_H
#define SIP_PACKET_QUEUE_H

#include <ace/Unbounded_Queue.h>
#include <mutex>
#include <vector>
#include <queue>

struct sipPacket {
    uint64_t seq_no; // Timestamp-based sequence number
    std::vector<uint8_t> packetData;
};

class SIPPacketQueue {
public:
    static SIPPacketQueue& getInstance() {
        static SIPPacketQueue instance;
        return instance;
    }

    // Delete copy constructor and assignment operator
    SIPPacketQueue(SIPPacketQueue const&) = delete;
    SIPPacketQueue& operator=(SIPPacketQueue const&) = delete;
    
    void enqueue(const sipPacket& pkt) {
        std::lock_guard<std::mutex> lock(mtx);
        q.push(pkt);
    }

    void dequeue(sipPacket& pkt) {
        pkt = q.front();
        q.pop();
    }

    bool isEmpty() {
        std::lock_guard<std::mutex> lock(mtx);
        return q.empty();
    }

private:
    std::queue<sipPacket> q;
    std::mutex mtx;

    SIPPacketQueue() {}
    ~SIPPacketQueue() {}
};


#endif // SIP_PACKET_QUEUE_H
