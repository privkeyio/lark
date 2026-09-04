package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.DeviceTimeoutException;
import com.sparrowwallet.lark.trezor.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * THP message transport for a single allocated channel.
 *
 * Owns the Alternating Bit Protocol (ABP) state shared by the handshake and encrypted transport
 * phases of a channel, and frames application data into 64 byte packets.
 *
 * The device retransmits a message it considers unacknowledged 200ms after sending it, so a message
 * that has already been received can arrive again at any point. Reads therefore acknowledge and
 * discard messages repeating the sequence bit already seen, along with packets belonging to other
 * channels, rather than treating them as protocol errors.
 */
public class ChannelTransport {
    private static final Logger log = LoggerFactory.getLogger(ChannelTransport.class);

    /** How long to wait for the device to acknowledge a sent message before sending it again */
    private static final int ACK_TIMEOUT_MS = 500;

    /** How many times to send a message again when it is not acknowledged, or the device is busy */
    private static final int MAX_SEND_RETRIES = 5;

    /** How long to wait before sending a message again, doubling with each retry */
    private static final int SEND_BACKOFF_MS = 100;

    /** The longest wait between retries */
    private static final int MAX_SEND_BACKOFF_MS = 500;

    private final Transport transport;
    private final int channelId;

    // Alternating Bit Protocol state
    private boolean syncBitSend;
    private boolean syncBitReceive;

    // A reply read while awaiting the acknowledgment of the message it answers. The next receive returns
    // it, which is only correct because every message sent is followed by a single receive before the next
    // is sent
    private PacketCodec.ReassembledMessage pendingMessage;

    public ChannelTransport(Transport transport, int channelId) {
        if(!Channel.isAllocatable(channelId)) {
            throw new IllegalArgumentException("Invalid channel ID: 0x" + String.format("%04X", channelId));
        }

        this.transport = transport;
        this.channelId = channelId;
        this.syncBitSend = false;
        this.syncBitReceive = false;
    }

    /**
     * Send a message on this channel and wait for the device to acknowledge it.
     *
     * @param messageType The type of message to send
     * @param applicationData The message payload
     */
    public void sendMessage(ControlByte.PacketType messageType, byte[] applicationData) throws DeviceException {
        // The ACK bit is left clear on outgoing messages - setting it on a handshake initiation request
        // tells the device to piggyback its acknowledgments, which this host does not support
        byte controlByte = switch(messageType) {
            case HANDSHAKE_INIT_REQ -> ControlByte.createHandshakeInitReq(syncBitSend, false);
            case HANDSHAKE_COMP_REQ -> ControlByte.createHandshakeCompReq(syncBitSend, false);
            case ENCRYPTED_TRANSPORT -> ControlByte.createEncryptedTransport(syncBitSend, false);
            default -> throw new IllegalArgumentException("Cannot send message of type " + messageType);
        };

        List<byte[]> packets = PacketCodec.segment(controlByte, channelId, applicationData);

        // The device drops a message it has no buffer for, and our acknowledgment can be lost in
        // either direction, so send the same packets again rather than failing the session
        int backoffMs = SEND_BACKOFF_MS;
        for(int retries = 0; ; retries++) {
            for(byte[] packet : packets) {
                transport.write(packet);
            }

            try {
                readAck(controlByte);
                break;
            } catch(DeviceTimeoutException e) {
                if(retries >= MAX_SEND_RETRIES) {
                    throw e;
                }

                if(log.isDebugEnabled()) {
                    log.debug("No acknowledgment for {} on channel 0x{}, sending again", messageType, String.format("%04X", channelId));
                }
            } catch(TransportErrorException e) {
                if(e.getErrorCode() != TransportErrorException.TRANSPORT_BUSY || retries >= MAX_SEND_RETRIES) {
                    throw e;
                }

                if(log.isDebugEnabled()) {
                    log.debug("Device busy on channel 0x{}, sending {} again", String.format("%04X", channelId), messageType);
                }
            }

            try {
                Thread.sleep(backoffMs);
            } catch(InterruptedException e) {
                //ignore
            }

            backoffMs = Math.min(backoffMs * 2, MAX_SEND_BACKOFF_MS);
        }

        syncBitSend = !syncBitSend;
    }

    /**
     * Receive the next message addressed to this channel. Waits for as long as it takes, as the device
     * may be waiting for the user to confirm on the device before it replies.
     *
     * @return The reassembled message, already acknowledged
     */
    public PacketCodec.ReassembledMessage receiveMessage() throws DeviceException {
        if(pendingMessage != null) {
            PacketCodec.ReassembledMessage message = pendingMessage;
            pendingMessage = null;

            return message;
        }

        while(true) {
            PacketCodec.ReassembledMessage message = readMessage(PacketReader.NO_DEADLINE);

            // Sending a message again produces a second acknowledgment when the first was merely late
            if(ControlByte.getPacketType(message.controlByte) == ControlByte.PacketType.ACK) {
                if(log.isDebugEnabled()) {
                    log.debug("Discarding unexpected acknowledgment on channel 0x{}", String.format("%04X", channelId));
                }
                continue;
            }

            return message;
        }
    }

    /**
     * Read the acknowledgment for the message just sent.
     *
     * Retransmissions arriving ahead of it are handled by the read itself. A reply that overtakes the
     * acknowledgment of the message it answers has already been acknowledged by the read, so it is held
     * for the next receive rather than lost - the acknowledgment is then waited for, and the message sent
     * again if it never arrives.
     */
    private void readAck(byte sentControlByte) throws DeviceException {
        boolean expectedAckBit = ControlByte.getSequenceBit(sentControlByte);
        long deadline = System.currentTimeMillis() + ACK_TIMEOUT_MS;

        while(true) {
            PacketCodec.ReassembledMessage message = readMessage(deadline);
            ControlByte.PacketType packetType = ControlByte.getPacketType(message.controlByte);
            if(packetType != ControlByte.PacketType.ACK) {
                if(!ControlByte.isAcknowledged(message.controlByte) || pendingMessage != null) {
                    throw new DeviceException("Expected ACK for sent message, got " + packetType +
                            " (control_byte=0x" + String.format("%02X", message.controlByte & 0xFF) + ")");
                }

                log.warn("Holding {} that arrived before its acknowledgment on channel 0x{}",
                        ControlByte.toString(message.controlByte), String.format("%04X", channelId));
                pendingMessage = message;
                continue;
            }

            if(ControlByte.getAckBit(message.controlByte) == expectedAckBit) {
                return;
            }

            if(log.isDebugEnabled()) {
                log.debug("Discarding acknowledgment with unexpected ACK bit on channel 0x{}", String.format("%04X", channelId));
            }
        }
    }

    /**
     * Read the next message for this channel.
     *
     * Messages for other channels are discarded, and a message repeating the sequence bit already seen
     * is a retransmission of one already handled, so it is acknowledged again and discarded.
     *
     * @param deadline When to give up waiting, or NO_DEADLINE to wait for as long as it takes
     */
    private PacketCodec.ReassembledMessage readMessage(long deadline) throws DeviceException {
        while(true) {
            PacketCodec.ReassembledMessage message = PacketReader.read(transport, deadline);

            if(message.channelId != channelId) {
                if(log.isDebugEnabled()) {
                    log.debug("Discarding message for channel 0x{}, expected 0x{}", String.format("%04X", message.channelId), String.format("%04X", channelId));
                }
                continue;
            }

            if(ControlByte.getPacketType(message.controlByte) == ControlByte.PacketType.TRANSPORT_ERROR) {
                throw new TransportErrorException(channelId, message.applicationData.length > 0 ? message.applicationData[0] & 0xFF : 0);
            }

            if(ControlByte.isAcknowledged(message.controlByte)) {
                if(ControlByte.getSequenceBit(message.controlByte) != syncBitReceive) {
                    // The device has not seen our acknowledgment of this message and has sent it again
                    if(log.isDebugEnabled()) {
                        log.debug("Acknowledging retransmitted {} on channel 0x{}", ControlByte.toString(message.controlByte), String.format("%04X", channelId));
                    }
                    sendAck(message.controlByte);
                    continue;
                }

                syncBitReceive = !syncBitReceive;

                // The device retransmits 200ms after sending, so acknowledge before the caller inspects
                // or decrypts the message
                sendAck(message.controlByte);
            }

            return message;
        }
    }

    /**
     * Acknowledge a received message.
     */
    private void sendAck(byte receivedControlByte) throws DeviceException {
        byte controlByte = ControlByte.createAck(ControlByte.getSequenceBit(receivedControlByte));

        // An ACK has an empty payload, but still needs the THP packet format with length and CRC
        for(byte[] packet : PacketCodec.segment(controlByte, channelId, new byte[0])) {
            transport.write(packet);
        }
    }
}
