package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessage;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageCommon;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class ProtocolFactoryTest {
    private static final int PACKET_SIZE = 64;

    /** A THP packet, which carries a control byte where protocol v1 expects its magic */
    private static final byte[] THP_PACKET = thpPacket();

    @Test
    public void testDeviceRejectingV1SpeaksThpOnly() throws DeviceException {
        ProbeTransport transport = new ProbeTransport(failureChunk(TrezorMessageCommon.Failure.FailureType.Failure_InvalidProtocol));
        assertInstanceOf(V2Protocol.class, ProtocolFactory.createProtocol(transport, null, null, null));
    }

    @Test
    public void testDeviceAnsweringV1IsV1Capable() throws DeviceException {
        ProbeTransport transport = new ProbeTransport(failureChunk(TrezorMessageCommon.Failure.FailureType.Failure_ActionCancelled));
        assertInstanceOf(V1Protocol.class, ProtocolFactory.createProtocol(transport, null, null, null));
    }

    /**
     * A device that replies only in THP framing speaks THP, and must not be taken for a V1 device that
     * was merely too busy to answer.
     */
    @Test
    public void testDeviceReplyingOnlyInThpFramingSpeaksThpOnly() throws DeviceException {
        ProbeTransport transport = new ProbeTransport(THP_PACKET, THP_PACKET);
        assertInstanceOf(V2Protocol.class, ProtocolFactory.createProtocol(transport, null, null, null));
    }

    /**
     * Packets left in flight by an earlier attempt are skipped to find the reply behind them, so a device
     * that answers in V1 is still recognised as V1 capable rather than taken for a THP only device.
     */
    @Test
    public void testStaleThpPacketsBeforeTheV1ReplyAreSkipped() throws DeviceException {
        ProbeTransport transport = new ProbeTransport(THP_PACKET, THP_PACKET,
                failureChunk(TrezorMessageCommon.Failure.FailureType.Failure_ActionCancelled));
        assertInstanceOf(V1Protocol.class, ProtocolFactory.createProtocol(transport, null, null, null));
    }

    /**
     * A chunk carrying the V1 magic but too short to hold the header that follows it cannot be parsed, so
     * it has to be skipped like any other chunk that is not a V1 message.
     */
    @Test
    public void testChunkTooShortToHoldTheV1HeaderIsSkipped() throws DeviceException {
        ProbeTransport transport = new ProbeTransport(new byte[] { '?', '#', '#' },
                failureChunk(TrezorMessageCommon.Failure.FailureType.Failure_ActionCancelled));
        assertInstanceOf(V1Protocol.class, ProtocolFactory.createProtocol(transport, null, null, null));
    }

    /**
     * Silence leaves open that this is a V1 device busy waiting for a PIN, which is the case the probe
     * has always resolved in favour of V1.
     */
    @Test
    public void testSilentDeviceIsAssumedV1Capable() throws DeviceException {
        ProbeTransport transport = new ProbeTransport();
        assertInstanceOf(V1Protocol.class, ProtocolFactory.createProtocol(transport, null, null, null));
    }

    /**
     * A device is opened once per operation, so the probe runs between prompting for a PIN and sending it.
     * Cancel would discard the matrix the PIN positions refer to, rejecting every PIN on a Trezor One.
     */
    @Test
    public void testProbeDoesNotCancelAPendingDeviceWorkflow() throws DeviceException {
        ProbeTransport transport = new ProbeTransport(failureChunk(TrezorMessageCommon.Failure.FailureType.Failure_ActionCancelled));
        ProtocolFactory.createProtocol(transport, null, null, null);

        assertEquals(TrezorMessage.MessageType.MessageType_Ping.getNumber(), transport.getProbedMessageType());
    }

    private static byte[] thpPacket() {
        byte[] packet = new byte[PACKET_SIZE];
        packet[0] = 0x01; // HANDSHAKE_INIT_RESP, as retransmitted for an abandoned channel

        return packet;
    }

    /**
     * Build the single chunk of a protocol v1 Failure message: "?##" + type + length + protobuf.
     */
    private static byte[] failureChunk(TrezorMessageCommon.Failure.FailureType failureType) {
        byte[] failure = TrezorMessageCommon.Failure.newBuilder().setCode(failureType).build().toByteArray();

        ByteBuffer chunk = ByteBuffer.allocate(PACKET_SIZE).order(ByteOrder.BIG_ENDIAN);
        chunk.put(new byte[] { '?', '#', '#' });
        chunk.putShort((short)TrezorMessage.MessageType.MessageType_Failure.getNumber());
        chunk.putInt(failure.length);
        chunk.put(failure);

        return chunk.array();
    }

    /**
     * Transport that stays silent until the probe is written, as a device does, then replies with the
     * given chunks. Reads report a timeout whenever nothing is queued.
     */
    private static class ProbeTransport implements Transport {
        private final Deque<byte[]> deviceChunks = new ArrayDeque<>();
        private final List<byte[]> reply;
        private int probedMessageType = -1;
        private boolean replied;
        private boolean closed;

        private ProbeTransport(byte[]... reply) {
            this.reply = List.of(reply);
        }

        private int getProbedMessageType() {
            return probedMessageType;
        }

        @Override
        public void write(byte[] packet) {
            if(!replied && packet[0] == '?') {
                probedMessageType = ByteBuffer.wrap(packet, 3, 2).order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;
                deviceChunks.addAll(reply);
                replied = true;
            }
        }

        @Override
        public byte[] read() throws DeviceException {
            return read(0);
        }

        @Override
        public byte[] read(int timeoutMs) throws DeviceException {
            byte[] chunk = deviceChunks.poll();
            if(chunk == null) {
                throw new DeviceTimeoutException("No chunk queued");
            }

            return chunk;
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
}
