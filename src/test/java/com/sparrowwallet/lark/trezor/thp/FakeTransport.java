package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.DeviceTimeoutException;
import com.sparrowwallet.lark.trezor.Transport;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * A queued packet, or a read that times out after the given delay when the packet is null.
 */
record DeviceRead(byte[] packet, long delayMs) {}

/**
 * Transport that replays queued device packets, then reports a bounded number of read timeouts
 * before failing outright so that a desynchronised read cannot hang the build.
 */
class FakeTransport implements Transport {
    private static final int MAX_EMPTY_READS = 3;

    private final Deque<DeviceRead> deviceReads = new ArrayDeque<>();
    private final List<byte[]> writtenPackets = new ArrayList<>();
    private final int defaultChannelId;
    private int emptyReads;
    private boolean closed;

    FakeTransport(int defaultChannelId) {
        this.defaultChannelId = defaultChannelId;
    }

    void queueDeviceMessage(byte controlByte, byte[] applicationData) {
        queueDeviceMessage(controlByte, defaultChannelId, applicationData);
    }

    void queueDeviceMessage(byte controlByte, int channelId, byte[] applicationData) {
        for(byte[] packet : PacketCodec.segment(controlByte, channelId, applicationData)) {
            deviceReads.add(new DeviceRead(packet, 0));
        }
    }

    void queueDevicePacket(byte[] packet) {
        deviceReads.add(new DeviceRead(packet, 0));
    }

    void queueDeviceTimeout(long delayMs) {
        deviceReads.add(new DeviceRead(null, delayMs));
    }

    List<Byte> getWrittenControlBytes() {
        List<Byte> controlBytes = new ArrayList<>();
        for(byte[] packet : writtenPackets) {
            if(!ControlByte.isContinuation(packet[0])) {
                controlBytes.add(packet[0]);
            }
        }

        return controlBytes;
    }

    @Override
    public void write(byte[] packet) {
        writtenPackets.add(packet);
    }

    @Override
    public byte[] read() throws DeviceException {
        return read(0);
    }

    @Override
    public byte[] read(int timeoutMs) throws DeviceException {
        DeviceRead deviceRead = deviceReads.poll();
        if(deviceRead == null) {
            if(++emptyReads > MAX_EMPTY_READS) {
                throw new DeviceException("No further packets queued");
            }

            throw new DeviceTimeoutException("No packet queued");
        }

        emptyReads = 0;
        if(deviceRead.packet() == null) {
            try {
                Thread.sleep(deviceRead.delayMs());
            } catch(InterruptedException e) {
                //ignore
            }

            throw new DeviceTimeoutException("Read timed out");
        }

        return deviceRead.packet();
    }

    @Override
    public void close() {
        closed = true;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }
}
