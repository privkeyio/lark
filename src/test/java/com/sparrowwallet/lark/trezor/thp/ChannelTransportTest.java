package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ChannelTransportTest {
    private static final int CHANNEL_ID = 0x1234;
    private static final int OTHER_CHANNEL_ID = 0x5678;

    private static final byte ACK_SEQ0 = 0x20;
    private static final byte ACK_SEQ1 = 0x28;
    private static final byte HANDSHAKE_INIT_REQ = 0x00;
    private static final byte HANDSHAKE_INIT_RESP = 0x01;
    private static final byte HANDSHAKE_COMP_REQ = 0x12;
    private static final byte HANDSHAKE_COMP_RESP = 0x13;
    private static final byte ENCRYPTED_TRANSPORT = 0x04;

    private static final byte UNALLOCATED_CHANNEL = 2;

    /** Long enough for the acknowledgment deadline to pass while the read is outstanding */
    private static final long ACK_TIMEOUT_OVERRUN_MS = 600;

    /** Long enough for the wait for the rest of a message to be given up on */
    private static final long CONTINUATION_TIMEOUT_OVERRUN_MS = 2100;

    /**
     * The sequence bits the THP spec fixes for the handshake fall out of the alternating send and
     * receive bits, so a session must still put the same control bytes on the wire.
     */
    @Test
    public void testSequenceBitsFollowTheHandshake() throws DeviceException {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);
        transport.queueDeviceMessage(HANDSHAKE_INIT_RESP, new byte[96]);
        transport.queueDeviceMessage(ACK_SEQ1, new byte[0]);
        transport.queueDeviceMessage(HANDSHAKE_COMP_RESP, new byte[17]);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);
        transport.queueDeviceMessage(ENCRYPTED_TRANSPORT, new byte[32]);

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        channelTransport.sendMessage(ControlByte.PacketType.HANDSHAKE_INIT_REQ, new byte[49]);
        channelTransport.receiveMessage();
        channelTransport.sendMessage(ControlByte.PacketType.HANDSHAKE_COMP_REQ, new byte[64]);
        channelTransport.receiveMessage();
        channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, new byte[32]);
        channelTransport.receiveMessage();

        assertEquals(List.of(HANDSHAKE_INIT_REQ, ACK_SEQ0, HANDSHAKE_COMP_REQ, ACK_SEQ1, ENCRYPTED_TRANSPORT, ACK_SEQ0),
                transport.getWrittenControlBytes());
    }

    /**
     * The device retransmits a message it considers unacknowledged 200ms after sending it, so the
     * copy already handled must be acknowledged again and discarded rather than failing the session.
     */
    @Test
    public void testRetransmittedResponseIsAcknowledgedAndDiscarded() throws DeviceException {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);
        transport.queueDeviceMessage(HANDSHAKE_INIT_RESP, new byte[96]);
        transport.queueDeviceMessage(HANDSHAKE_INIT_RESP, new byte[96]);
        transport.queueDeviceMessage(ACK_SEQ1, new byte[0]);
        transport.queueDeviceMessage(HANDSHAKE_COMP_RESP, new byte[17]);

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        channelTransport.sendMessage(ControlByte.PacketType.HANDSHAKE_INIT_REQ, new byte[49]);
        channelTransport.receiveMessage();

        assertDoesNotThrow(() -> {
            channelTransport.sendMessage(ControlByte.PacketType.HANDSHAKE_COMP_REQ, new byte[64]);
            channelTransport.receiveMessage();
        });

        // The retransmission is acknowledged a second time before the awaited acknowledgment arrives
        assertEquals(List.of(HANDSHAKE_INIT_REQ, ACK_SEQ0, HANDSHAKE_COMP_REQ, ACK_SEQ0, ACK_SEQ1),
                transport.getWrittenControlBytes());
    }

    /**
     * A reply whose remaining packets never arrive must not fail the session - the device sends the whole
     * message again, and the partial copy has to be discarded for that one to reassemble.
     */
    @Test
    public void testMessageStallingMidReassemblyIsDiscarded() throws DeviceException {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);

        // Only the initiation packet of a reply that spans two packets
        List<byte[]> truncated = PacketCodec.segment(ENCRYPTED_TRANSPORT, CHANNEL_ID, new byte[96]);
        transport.queueDevicePacket(truncated.get(0));
        transport.queueDeviceTimeout(CONTINUATION_TIMEOUT_OVERRUN_MS);
        transport.queueDeviceMessage(ENCRYPTED_TRANSPORT, new byte[96]);

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, new byte[32]);
        PacketCodec.ReassembledMessage message = channelTransport.receiveMessage();

        assertEquals(96, message.applicationData.length);

        // The partial copy is never acknowledged, only the message that reassembles
        assertEquals(List.of(ENCRYPTED_TRANSPORT, ACK_SEQ0), transport.getWrittenControlBytes());
    }

    @Test
    public void testMessageForAnotherChannelIsDiscarded() throws DeviceException {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceMessage(ENCRYPTED_TRANSPORT, OTHER_CHANNEL_ID, new byte[32]);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);
        transport.queueDeviceMessage(ENCRYPTED_TRANSPORT, new byte[32]);

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, new byte[32]);
        channelTransport.receiveMessage();

        // Nothing is acknowledged on behalf of the other channel
        assertEquals(List.of(ENCRYPTED_TRANSPORT, ACK_SEQ0), transport.getWrittenControlBytes());
    }

    /**
     * An acknowledgment lost in either direction must not fail the session - the same packets are
     * sent again, and the device replies with the acknowledgment it already sent or a fresh one.
     */
    @Test
    public void testMessageIsSentAgainWhenAcknowledgmentIsLost() throws DeviceException {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceTimeout(ACK_TIMEOUT_OVERRUN_MS);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, new byte[32]);

        assertEquals(List.of(ENCRYPTED_TRANSPORT, ENCRYPTED_TRANSPORT), transport.getWrittenControlBytes());
    }

    /**
     * A reply that overtakes the acknowledgment of the message it answers has already been acknowledged by
     * the read, so the device will not send it again and it has to be held rather than discarded.
     */
    @Test
    public void testReplyArrivingBeforeItsAcknowledgmentIsHeld() throws DeviceException {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceMessage(ENCRYPTED_TRANSPORT, new byte[32]);
        transport.queueDeviceTimeout(ACK_TIMEOUT_OVERRUN_MS);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, new byte[32]);
        PacketCodec.ReassembledMessage message = channelTransport.receiveMessage();

        assertEquals(32, message.applicationData.length);

        // The reply is acknowledged when read, then the message is sent again to draw out the acknowledgment
        assertEquals(List.of(ENCRYPTED_TRANSPORT, ACK_SEQ0, ENCRYPTED_TRANSPORT), transport.getWrittenControlBytes());
    }

    @Test
    public void testMessageIsSentAgainWhenDeviceIsBusy() throws DeviceException {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceMessage(ControlByte.TRANSPORT_ERROR, new byte[] { TransportErrorException.TRANSPORT_BUSY });
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, new byte[32]);

        assertEquals(List.of(ENCRYPTED_TRANSPORT, ENCRYPTED_TRANSPORT), transport.getWrittenControlBytes());
    }

    @Test
    public void testTransportErrorOtherThanBusyIsNotRetried() {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceMessage(ControlByte.TRANSPORT_ERROR, new byte[] { UNALLOCATED_CHANNEL });

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        TransportErrorException e = assertThrows(TransportErrorException.class,
                () -> channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, new byte[32]));

        assertEquals(UNALLOCATED_CHANNEL, e.getErrorCode());
        assertEquals(List.of(ENCRYPTED_TRANSPORT), transport.getWrittenControlBytes());
    }

    /**
     * Sending a message again produces a second acknowledgment when the first was merely late, which
     * must not be mistaken for the reply.
     */
    @Test
    public void testStrayAcknowledgmentIsDiscardedWhenReceiving() throws DeviceException {
        FakeTransport transport = new FakeTransport(CHANNEL_ID);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);
        transport.queueDeviceMessage(ACK_SEQ0, new byte[0]);
        transport.queueDeviceMessage(ENCRYPTED_TRANSPORT, new byte[32]);

        ChannelTransport channelTransport = new ChannelTransport(transport, CHANNEL_ID);
        channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, new byte[32]);
        channelTransport.receiveMessage();

        assertEquals(List.of(ENCRYPTED_TRANSPORT, ACK_SEQ0), transport.getWrittenControlBytes());
    }
}
