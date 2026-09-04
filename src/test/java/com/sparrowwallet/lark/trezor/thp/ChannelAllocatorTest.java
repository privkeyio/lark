package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageThp;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ChannelAllocatorTest {
    private static final int ALLOCATED_CHANNEL_ID = 0x1234;
    private static final int ABANDONED_CHANNEL_ID = 0x5678;

    private static final byte ENCRYPTED_TRANSPORT = 0x04;
    private static final int NONCE_LENGTH = 8;
    private static final int PACKET_SIZE = 64;

    /**
     * An attempt that ended mid session leaves the device sending packets for the abandoned channel for
     * up to 104 seconds, and allocation is the first read of the attempt that follows.
     */
    @Test
    public void testPacketsForAnAbandonedChannelAreDiscarded() throws DeviceException {
        AllocatingTransport transport = new AllocatingTransport();
        transport.queueDeviceMessage(ENCRYPTED_TRANSPORT, ABANDONED_CHANNEL_ID, new byte[32]);

        ChannelAllocationMessages.AllocationResponse response =
                new ChannelAllocator(transport).allocateChannel(ChannelAllocationMessages.PROTOCOL_VERSION_V1);

        assertEquals(ALLOCATED_CHANNEL_ID, response.channelId);
    }

    /**
     * A request abandoned before its response was read leaves an allocation response carrying a nonce
     * that is no longer the one being waited for.
     */
    @Test
    public void testAllocationResponseForAnotherRequestIsDiscarded() throws DeviceException {
        AllocatingTransport transport = new AllocatingTransport();
        byte[] stalePayload = buildAllocationResponse(new byte[NONCE_LENGTH], ABANDONED_CHANNEL_ID);
        transport.queueDeviceMessage(ControlByte.CHANNEL_ALLOCATION_RESP, Channel.BROADCAST_CHANNEL_ID, stalePayload);

        ChannelAllocationMessages.AllocationResponse response =
                new ChannelAllocator(transport).allocateChannel(ChannelAllocationMessages.PROTOCOL_VERSION_V1);

        assertEquals(ALLOCATED_CHANNEL_ID, response.channelId);
    }

    /**
     * Draining an abandoned channel means meeting packets that are corrupt or truncated, which must not
     * fail the allocation they are being drained ahead of.
     */
    @Test
    public void testMalformedPacketsBeforeAllocationAreDiscarded() throws DeviceException {
        AllocatingTransport transport = new AllocatingTransport();

        // A zero filled packet declares a length shorter than the CRC every message carries
        transport.queueDevicePacket(new byte[PACKET_SIZE]);

        // A length field far larger than any message the device sends
        byte[] oversized = new byte[PACKET_SIZE];
        oversized[3] = (byte)0xFF;
        oversized[4] = (byte)0xFF;
        transport.queueDevicePacket(oversized);

        // A message whose payload no longer matches its CRC
        byte[] corrupted = PacketCodec.segment(ENCRYPTED_TRANSPORT, ABANDONED_CHANNEL_ID, new byte[8]).get(0);
        corrupted[5] ^= (byte)0xFF;
        transport.queueDevicePacket(corrupted);

        ChannelAllocationMessages.AllocationResponse response =
                new ChannelAllocator(transport).allocateChannel(ChannelAllocationMessages.PROTOCOL_VERSION_V1);

        assertEquals(ALLOCATED_CHANNEL_ID, response.channelId);
    }

    private static byte[] buildAllocationResponse(byte[] nonce, int channelId) {
        byte[] deviceProperties = TrezorMessageThp.ThpDeviceProperties.newBuilder()
                .setInternalModel("T3W1")
                .setProtocolVersionMajor(2)
                .setProtocolVersionMinor(1)
                .build().toByteArray();

        byte[] payload = new byte[NONCE_LENGTH + 2 + deviceProperties.length];
        System.arraycopy(nonce, 0, payload, 0, NONCE_LENGTH);
        System.arraycopy(Channel.channelIdToBytes(channelId), 0, payload, NONCE_LENGTH, 2);
        System.arraycopy(deviceProperties, 0, payload, NONCE_LENGTH + 2, deviceProperties.length);

        return payload;
    }

    /**
     * Transport that answers a channel allocation request the way the device does, echoing the nonce the
     * allocator generated.
     */
    private static class AllocatingTransport extends FakeTransport {
        private AllocatingTransport() {
            super(Channel.BROADCAST_CHANNEL_ID);
        }

        @Override
        public void write(byte[] packet) {
            super.write(packet);

            if(packet[0] == ControlByte.CHANNEL_ALLOCATION_REQ) {
                // The payload of an initiation packet starts after the control byte, channel ID and length
                byte[] nonce = Arrays.copyOfRange(packet, 5, 5 + NONCE_LENGTH);
                queueDeviceMessage(ControlByte.CHANNEL_ALLOCATION_RESP, Channel.BROADCAST_CHANNEL_ID,
                        buildAllocationResponse(nonce, ALLOCATED_CHANNEL_ID));
            }
        }
    }
}
