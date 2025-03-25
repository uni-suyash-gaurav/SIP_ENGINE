#ifndef SIP_PACKET_QUEUE_H
#define SIP_PACKET_QUEUE_H

#include <ace/Unbounded_Queue.h>
#include <mutex>
#include <vector>

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
        queue.enqueue_tail(pkt);
    }

    bool dequeue(sipPacket& pkt) {
        std::lock_guard<std::mutex> lock(mtx);
        return queue.dequeue_head(pkt) == 0;
    }

    bool isEmpty() {
        std::lock_guard<std::mutex> lock(mtx);
        return queue.is_empty();
    }

private:
    ACE_Unbounded_Queue<sipPacket> queue;
    std::mutex mtx;

    SIPPacketQueue() {}
    ~SIPPacketQueue() {}
};


#endif // SIP_PACKET_QUEUE_H
