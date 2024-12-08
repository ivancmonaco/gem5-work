#ifndef __BOOTCAMP_SECURE_MEMORY_SECURE_MEMORY_HH__
#define __BOOTCAMP_SECURE_MEMORY_SECURE_MEMORY_HH__

#include <queue>
#include <vector>

#include "base/stats/group.hh"
#include "base/statistics.hh"
#include "mem/packet.hh"
#include "mem/port.hh"
#include "params/SecureMemory.hh"
#include "sim/clocked_object.hh"
#include "sim/eventq.hh"

namespace gem5
{

class SecureMemory : public ClockedObject
{
  private:
    class CPUSidePort: public ResponsePort
    {
      private:
        SecureMemory* owner;
        bool needToSendRetry;
        PacketPtr blockedPacket;

      public:
        CPUSidePort(SecureMemory* owner, const std::string& name):
            ResponsePort(name), owner(owner), needToSendRetry(false), blockedPacket(nullptr)
        {}
        bool needRetry() const { return needToSendRetry; }
        bool blocked() const { return blockedPacket != nullptr; }
        void sendPacket(PacketPtr pkt);

        virtual AddrRangeList getAddrRanges() const override;
        virtual bool recvTimingReq(PacketPtr pkt) override;
        virtual Tick recvAtomic(PacketPtr pkt) override;
        virtual void recvFunctional(PacketPtr pkt) override;
        virtual void recvRespRetry() override;
    };

    class MemSidePort: public RequestPort
    {
      private:
        SecureMemory* owner;
        bool needToSendRetry;
        PacketPtr blockedPacket;

      public:
        MemSidePort(SecureMemory* owner, const std::string& name):
            RequestPort(name), owner(owner), needToSendRetry(false), blockedPacket(nullptr)
        {}
        bool needRetry() const { return needToSendRetry; }
        bool blocked() const { return blockedPacket != nullptr; }
        void sendPacket(PacketPtr pkt);

        virtual bool recvTimingResp(PacketPtr pkt) override;
        virtual void recvReqRetry() override;
    };

    template<typename T>
    class TimedQueue
    {
      private:
        Tick latency;

        std::queue<T> items;
        std::queue<Tick> insertionTimes;

      public:
        TimedQueue(Tick latency): latency(latency) {}

        void push(T item, Tick insertion_time) {
            items.push(item);
            insertionTimes.push(insertion_time);
        }
        void pop() {
            items.pop();
            insertionTimes.pop();
        }

        T& front() { return items.front(); }
        Tick frontTime() { return insertionTimes.front(); }
        bool empty() const { return items.empty(); }
        size_t size() const { return items.size(); }
        bool hasReady(Tick current_time) const {
            if (empty()) {
                return false;
            }
            return (current_time - insertionTimes.front()) >= latency;
        }
        Tick firstReadyTime() { return insertionTimes.front() + latency; }
    };

    struct SequenceNumberTag: public Packet::SenderState
    {
        uint64_t sequenceNumber;
        SequenceNumberTag(uint64_t sequenceNumber):
            SenderState(), sequenceNumber(sequenceNumber)
        {}
    };

    struct SecureMemoryStats: public statistics::Group
    {
        statistics::Scalar totalInspectionBufferLatency;
        statistics::Scalar numRequestsFwded;
        statistics::Scalar totalResponseBufferLatency;
        statistics::Scalar numResponsesFwded;
        statistics::Scalar numReqRespDisplacements;
        SecureMemoryStats(SecureMemory* secure_memory);
    };



    CPUSidePort cpuSidePort;
    MemSidePort memSidePort;

    int inspectionBufferEntries;
    TimedQueue<PacketPtr> inspectionBuffer;

    int inspectionWindow;
    int numInspectionUnits;
    Cycles totalInspectionLatency;
    std::vector<Tick> inspectionUnitAvailableTimes;

    int outputBufferEntries;
    TimedQueue<PacketPtr> outputBuffer;

    int responseBufferEntries;
    TimedQueue<PacketPtr> responseBuffer;

    EventFunctionWrapper nextInspectionEvent;
    void processNextInspectionEvent();
    void scheduleNextInspectionEvent(Tick when);

    EventFunctionWrapper nextReqSendEvent;
    void processNextReqSendEvent();
    void scheduleNextReqSendEvent(Tick when);

    EventFunctionWrapper nextReqRetryEvent;
    void processNextReqRetryEvent();
    void scheduleNextReqRetryEvent(Tick when);

    EventFunctionWrapper nextRespSendEvent;
    void processNextRespSendEvent();
    void scheduleNextRespSendEvent(Tick when);

    EventFunctionWrapper nextRespRetryEvent;
    void processNextRespRetryEvent();
    void scheduleNextRespRetryEvent(Tick when);

    uint64_t nextAvailableSeqNum;
    void inspectRequest(PacketPtr pkt);

    uint64_t nextExpectedSeqNum;
    void inspectResponse(PacketPtr pkt);

    Tick align(Tick when);

    SecureMemoryStats stats;

  public:
    SecureMemory(const SecureMemoryParams& params);

    virtual void init() override;
    virtual Port& getPort(const std::string& if_name, PortID idx=InvalidPortID) override;

    AddrRangeList getAddrRanges() const;
    bool recvTimingReq(PacketPtr pkt);
    Tick recvAtomic(PacketPtr pkt);
    void recvFunctional(PacketPtr pkt);
    void recvReqRetry();

    bool recvTimingResp(PacketPtr pkt);
    void recvRespRetry();
};


} // namespace gem5

#endif // __BOOTCAMP_SECURE_MEMORY_SECURE_MEMORY_HH__
