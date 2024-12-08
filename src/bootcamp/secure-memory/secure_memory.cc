#include "bootcamp/secure-memory/secure_memory.hh"

#include <algorithm>
#include <cmath>

#include "debug/SecureMemoryDebugFlag.hh"

namespace gem5
{

SecureMemory::SecureMemory(const SecureMemoryParams& params):
    ClockedObject(params),
    cpuSidePort(this, name() + ".cpu_side_port"),
    memSidePort(this, name() + ".mem_side_port"),
    inspectionBufferEntries(params.inspection_buffer_entries),
    inspectionBuffer(clockPeriod()),
    inspectionWindow(params.insp_window),
    numInspectionUnits(params.num_insp_units),
    totalInspectionLatency(params.insp_tot_latency),
    inspectionUnitAvailableTimes((size_t) params.num_insp_units, 0),
    outputBufferEntries(params.output_buffer_entries),
    outputBuffer(clockPeriod()),
    responseBufferEntries(params.response_buffer_entries),
    responseBuffer(clockPeriod()),
    nextInspectionEvent([this]() { processNextInspectionEvent(); }, name() + ".nextInspectionEvent"),
    nextReqSendEvent([this](){ processNextReqSendEvent(); }, name() + ".nextReqSendEvent"),
    nextReqRetryEvent([this](){ processNextReqRetryEvent(); }, name() + ".nextReqRetryEvent"),
    nextRespSendEvent([this](){ processNextRespSendEvent(); }, name() + ".nextRespSendEvent"),
    nextRespRetryEvent([this](){ processNextRespRetryEvent(); }, name() + ".nextRespRetryEvent"),
    nextAvailableSeqNum(0), nextExpectedSeqNum(0),
    stats(this)
{}

void
SecureMemory::init()
{
    cpuSidePort.sendRangeChange();
}

Port&
SecureMemory::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "cpu_side_port") {
        return cpuSidePort;
    } else if (if_name == "mem_side_port") {
        return memSidePort;
    } else {
        return ClockedObject::getPort(if_name, idx);
    }
}

Tick
SecureMemory::align(Tick when)
{
    return clockEdge((Cycles) std::ceil((when - curTick()) / clockPeriod()));
}

void
SecureMemory::inspectRequest(PacketPtr pkt)
{
    panic_if(!pkt->isRequest(), "Should only inspect requests!");
    SequenceNumberTag* seq_num_tag = new SequenceNumberTag(nextAvailableSeqNum);
    pkt->pushSenderState(seq_num_tag);
    nextAvailableSeqNum++;
}

void
SecureMemory::inspectResponse(PacketPtr pkt)
{
    panic_if(!pkt->isResponse(), "Should only inspect responses!");
    SequenceNumberTag* seq_num_tag = pkt->findNextSenderState<SequenceNumberTag>();
    panic_if(seq_num_tag == nullptr, "There is not tag attached to pkt!");
    if (seq_num_tag->sequenceNumber != nextExpectedSeqNum) {
        stats.numReqRespDisplacements++;
    }
    delete pkt->popSenderState();
    nextExpectedSeqNum++;
}

AddrRangeList
SecureMemory::CPUSidePort::getAddrRanges() const
{
    return owner->getAddrRanges();
}

AddrRangeList
SecureMemory::getAddrRanges() const
{
    return memSidePort.getAddrRanges();
}

bool
SecureMemory::CPUSidePort::recvTimingReq(PacketPtr pkt)
{
    DPRINTF(SecureMemoryDebugFlag, "%s: Received pkt: %s in timing mode.\n", __func__, pkt->print());
    if (owner->recvTimingReq(pkt)) {
        return true;
    }
    needToSendRetry = true;
    return false;
}

bool
SecureMemory::recvTimingReq(PacketPtr pkt)
{
    if (inspectionBuffer.size() >= inspectionBufferEntries) {
        return false;
    }
    inspectionBuffer.push(pkt, curTick());
    scheduleNextInspectionEvent(nextCycle());
    return true;
}

Tick
SecureMemory::CPUSidePort::recvAtomic(PacketPtr pkt)
{
    DPRINTF(SecureMemoryDebugFlag, "%s: Received pkt: %s in atomic mode.\n", __func__, pkt->print());
    return owner->recvAtomic(pkt);
}

Tick
SecureMemory::recvAtomic(PacketPtr pkt)
{
    return clockPeriod() + memSidePort.sendAtomic(pkt);
}

void
SecureMemory::CPUSidePort::recvFunctional(PacketPtr pkt)
{
    DPRINTF(SecureMemoryDebugFlag, "%s: Received pkt: %s in functional mode.\n", __func__, pkt->print());
    owner->recvFunctional(pkt);
}

void
SecureMemory::recvFunctional(PacketPtr pkt)
{
    memSidePort.sendFunctional(pkt);
}

// Too-Much-Code
void
SecureMemory::CPUSidePort::sendPacket(PacketPtr pkt)
{
    panic_if(blocked(), "Should never try to send if blocked!");

    DPRINTF(SecureMemoryDebugFlag, "%s: Sending pkt: %s.\n", __func__, pkt->print());
    if (!sendTimingResp(pkt)) {
        DPRINTF(SecureMemoryDebugFlag, "%s: Failed to send pkt: %s.\n", __func__, pkt->print());
        blockedPacket = pkt;
    }
}

// Too-Much-Code
void
SecureMemory::CPUSidePort::recvRespRetry()
{
    panic_if(!blocked(), "Should never receive retry if not blocked!");

    DPRINTF(SecureMemoryDebugFlag, "%s: Received retry signal.\n", __func__);
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;
    sendPacket(pkt);

    if (!blocked()) {
        owner->recvRespRetry();
    }
}

// Too-Much-Code
void
SecureMemory::recvRespRetry()
{
    scheduleNextRespSendEvent(nextCycle());
}

void
SecureMemory::MemSidePort::sendPacket(PacketPtr pkt)
{
    panic_if(blocked(), "Should never try to send if blocked!");

    DPRINTF(SecureMemoryDebugFlag, "%s: Sending pkt: %s.\n", __func__, pkt->print());
    if (!sendTimingReq(pkt)) {
        DPRINTF(SecureMemoryDebugFlag, "%s: Failed to send pkt: %s.\n", __func__, pkt->print());
        blockedPacket = pkt;
    }
}

// Too-Much-Code
bool
SecureMemory::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    DPRINTF(SecureMemoryDebugFlag, "%s: Received pkt: %s in timing mode.\n", __func__, pkt->print());
    if (owner->recvTimingResp(pkt)) {
        return true;
    }
    needToSendRetry = true;
    return false;
}

// Too-Much-Code
bool
SecureMemory::recvTimingResp(PacketPtr pkt)
{
    if (responseBuffer.size() >= responseBufferEntries) {
        return false;
    }
    responseBuffer.push(pkt, curTick());
    scheduleNextRespSendEvent(nextCycle());
    return true;
}

void
SecureMemory::MemSidePort::recvReqRetry()
{
    panic_if(!blocked(), "Should never receive retry if not blocked!");

    DPRINTF(SecureMemoryDebugFlag, "%s: Received retry signal.\n", __func__);
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;
    sendPacket(pkt);

    if (!blocked()) {
        owner->recvReqRetry();
    }
}

void
SecureMemory::recvReqRetry()
{
    scheduleNextReqSendEvent(nextCycle());
}

void
SecureMemory::processNextInspectionEvent()
{
    panic_if(!inspectionBuffer.hasReady(curTick()), "Should never try to inspect if no ready packets!");

    int insp_window_left = inspectionWindow;
    for (int i = 0; i < numInspectionUnits; i++) {
        if (inspectionUnitAvailableTimes[i] > curTick()) {
            DPRINTF(SecureMemoryDebugFlag, "%s: Inspection unit %d is busy.\n", __func__,  i);
            continue;
        }
        if (inspectionBuffer.empty()) {
            DPRINTF(SecureMemoryDebugFlag, "%s: Inspection buffer is empty.\n", __func__);
            break;
        }
        if (outputBuffer.size() >= outputBufferEntries) {
            DPRINTF(SecureMemoryDebugFlag, "%s: Output buffer is full.\n", __func__);
            break;
        }
        stats.totalInspectionBufferLatency += curTick() - inspectionBuffer.frontTime();
        PacketPtr pkt = inspectionBuffer.front();
        inspectRequest(pkt);
        outputBuffer.push(pkt, clockEdge(totalInspectionLatency));
        inspectionBuffer.pop();
        inspectionUnitAvailableTimes[i] = clockEdge(totalInspectionLatency);
        insp_window_left--;
        if (insp_window_left == 0) {
            break;
        }
    }

    for (int i = 0; i < numInspectionUnits; i++) {
        inspectionUnitAvailableTimes[i] = std::max(inspectionUnitAvailableTimes[i], nextCycle());
    }

    scheduleNextReqSendEvent(nextCycle());
    scheduleNextReqRetryEvent(nextCycle());
    scheduleNextInspectionEvent(nextCycle());
}

void
SecureMemory::scheduleNextInspectionEvent(Tick when)
{
    bool have_packet = !inspectionBuffer.empty();
    bool have_entry = outputBuffer.size() < outputBufferEntries;

    if (have_packet && have_entry && !nextInspectionEvent.scheduled()) {
        Tick first_avail_insp_unit_time = \
            *std::min_element(
                            inspectionUnitAvailableTimes.begin(),
                            inspectionUnitAvailableTimes.end()
                            );
        Tick schedule_time = align(std::max({when,
                                            inspectionBuffer.firstReadyTime(),
                                            first_avail_insp_unit_time
                                            }));
        schedule(nextInspectionEvent, schedule_time);
    }
}

void
SecureMemory::processNextReqSendEvent()
{
    panic_if(memSidePort.blocked(), "Should never try to send if blocked!");
    panic_if(!outputBuffer.hasReady(curTick()), "Should never try to send if no ready packets!");

    stats.numRequestsFwded++;
    PacketPtr pkt = outputBuffer.front();
    memSidePort.sendPacket(pkt);
    outputBuffer.pop();

    scheduleNextInspectionEvent(nextCycle());
    scheduleNextReqSendEvent(nextCycle());
}

void
SecureMemory::scheduleNextReqSendEvent(Tick when)
{
    bool port_avail = !memSidePort.blocked();
    bool have_items = !outputBuffer.empty();

    if (port_avail && have_items && !nextReqSendEvent.scheduled()) {
        Tick schedule_time = align(std::max(when, outputBuffer.firstReadyTime()));
        schedule(nextReqSendEvent, schedule_time);
    }
}

void
SecureMemory::processNextReqRetryEvent()
{
    panic_if(!cpuSidePort.needRetry(), "Should never try to send retry if not needed!");
    cpuSidePort.sendRetryReq();
}

void
SecureMemory::scheduleNextReqRetryEvent(Tick when)
{
    if (cpuSidePort.needRetry() && !nextReqRetryEvent.scheduled()) {
        schedule(nextReqRetryEvent, align(when));
    }
}

// Too-Much-Code
void
SecureMemory::processNextRespSendEvent()
{
    panic_if(cpuSidePort.blocked(), "Should never try to send if blocked!");
    panic_if(!responseBuffer.hasReady(curTick()), "Should never try to send if no ready packets!");

    stats.numResponsesFwded++;
    stats.totalResponseBufferLatency += curTick() - responseBuffer.frontTime();

    PacketPtr pkt = responseBuffer.front();
    inspectResponse(pkt);
    cpuSidePort.sendPacket(pkt);
    responseBuffer.pop();

    scheduleNextRespRetryEvent(nextCycle());
    scheduleNextRespSendEvent(nextCycle());
}

// Too-Much-Code
void
SecureMemory::scheduleNextRespSendEvent(Tick when)
{
    bool port_avail = !cpuSidePort.blocked();
    bool have_items = !responseBuffer.empty();

    if (port_avail && have_items && !nextRespSendEvent.scheduled()) {
        Tick schedule_time = align(std::max(when, responseBuffer.firstReadyTime()));
        schedule(nextRespSendEvent, schedule_time);
    }
}

// Too-Much-Code
void
SecureMemory::processNextRespRetryEvent()
{
    panic_if(!memSidePort.needRetry(), "Should never try to send retry if not needed!");
    memSidePort.sendRetryResp();
}

// Too-Much-Code
void
SecureMemory::scheduleNextRespRetryEvent(Tick when)
{
    if (memSidePort.needRetry() && !nextRespRetryEvent.scheduled()) {
        schedule(nextRespRetryEvent, align(when));
    }
}

SecureMemory::SecureMemoryStats::SecureMemoryStats(SecureMemory* secure_memory):
    statistics::Group(secure_memory),
    ADD_STAT(totalInspectionBufferLatency, statistics::units::Tick::get(), "Total inspection buffer latency."),
    ADD_STAT(numRequestsFwded, statistics::units::Count::get(), "Number of requests forwarded."),
    ADD_STAT(totalResponseBufferLatency, statistics::units::Tick::get(), "Total response buffer latency."),
    ADD_STAT(numResponsesFwded, statistics::units::Count::get(), "Number of responses forwarded."),
    ADD_STAT(numReqRespDisplacements, statistics::units::Count::get(), "Number of request-response displacements.")
{}

} // namespace gem5

