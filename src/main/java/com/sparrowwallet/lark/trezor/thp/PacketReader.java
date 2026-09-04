package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.DeviceTimeoutException;
import com.sparrowwallet.lark.trezor.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Reads THP packets from a transport and reassembles them into a message.
 *
 * The device can have packets of its own in flight for an earlier channel or an abandoned message, so
 * packets that cannot form a complete message are discarded rather than failing the read. Which of the
 * reassembled messages is of interest is left to the caller.
 */
public class PacketReader {
    private static final Logger log = LoggerFactory.getLogger(PacketReader.class);

    private static final int PACKET_SIZE = 64;

    /** Safety limit for reassembly */
    private static final int MAX_PACKETS = 1000;

    /** How many malformed messages to discard before treating the device as no longer following the protocol */
    private static final int MAX_MALFORMED_MESSAGES = 10;

    /** How long to wait for the remaining packets of a message already being received */
    private static final int CONTINUATION_TIMEOUT_MS = 2000;

    /** Deadline indicating a read should wait for as long as it takes */
    public static final long NO_DEADLINE = 0L;

    /**
     * Read the next complete message, verifying its CRC.
     *
     * @param transport The transport to read packets from
     * @param deadline When to give up waiting, or NO_DEADLINE to wait for as long as it takes
     */
    public static PacketCodec.ReassembledMessage read(Transport transport, long deadline) throws DeviceException {
        byte[] firstPacket = null;
        int malformedMessages = 0;

        while(true) {
            if(firstPacket == null) {
                firstPacket = readPacket(transport, deadline);
            }

            if(ControlByte.isContinuation(firstPacket[0])) {
                if(log.isDebugEnabled()) {
                    log.debug("Discarding unexpected continuation packet for channel 0x{}", String.format("%04X", PacketCodec.getChannelId(firstPacket)));
                }
                firstPacket = null;
                continue;
            }

            int messageChannelId = PacketCodec.getChannelId(firstPacket);
            int requiredPackets = calculateRequiredPackets(PacketCodec.getLength(firstPacket));
            if(requiredPackets > MAX_PACKETS) {
                if(log.isDebugEnabled()) {
                    log.debug("Discarding message declaring {} packets for channel 0x{}", requiredPackets, String.format("%04X", messageChannelId));
                }
                firstPacket = null;
                malformedMessages = countMalformed(malformedMessages);
                continue;
            }

            List<byte[]> packets = new ArrayList<>();
            packets.add(firstPacket);

            // The remaining packets of a message follow immediately, so bound the wait for them even when
            // the caller is prepared to wait for as long as it takes for the message itself
            long continuationDeadline = System.currentTimeMillis() + CONTINUATION_TIMEOUT_MS;
            if(deadline != NO_DEADLINE) {
                continuationDeadline = Math.min(continuationDeadline, deadline);
            }

            byte[] initiationPacket = null;
            while(packets.size() < requiredPackets) {
                byte[] packet;
                try {
                    packet = readPacket(transport, continuationDeadline);
                } catch(DeviceTimeoutException e) {
                    // The device sends a message it considers unacknowledged again, so the copy that
                    // follows can be reassembled in place of this one
                    break;
                }

                if(!ControlByte.isContinuation(packet[0])) {
                    // An initiation packet belongs to a new message, so this one can never be completed
                    initiationPacket = packet;
                    break;
                }

                if(PacketCodec.getChannelId(packet) == messageChannelId) {
                    packets.add(packet);
                } else {
                    if(log.isDebugEnabled()) {
                        log.debug("Discarding continuation packet for channel 0x{}", String.format("%04X", PacketCodec.getChannelId(packet)));
                    }
                }
            }

            if(packets.size() < requiredPackets) {
                // Deliberately not counted as malformed - a truncated message is what the device's own
                // retransmission repairs, so a caller waiting for as long as it takes waits for the copy
                // that follows rather than giving up
                if(log.isDebugEnabled()) {
                    log.debug("Discarding incomplete message for channel 0x{}", String.format("%04X", messageChannelId));
                }
                firstPacket = initiationPacket;
                continue;
            }

            firstPacket = null;
            try {
                return PacketCodec.reassemble(packets);
            } catch(DeviceException e) {
                if(log.isDebugEnabled()) {
                    log.debug("Discarding message for channel 0x{} that could not be reassembled: {}", String.format("%04X", messageChannelId), e.getMessage());
                }
                malformedMessages = countMalformed(malformedMessages);
            }
        }
    }

    /**
     * Count a message discarded as malformed, giving up once there have been too many to be the stray
     * packets of an abandoned message.
     */
    private static int countMalformed(int malformedMessages) throws DeviceException {
        int discarded = malformedMessages + 1;
        if(discarded > MAX_MALFORMED_MESSAGES) {
            throw new DeviceException("Discarded " + discarded + " malformed messages (possible protocol error)");
        }

        return discarded;
    }

    /**
     * Read a single 64 byte packet.
     *
     * @param transport The transport to read from
     * @param deadline When to give up waiting, or NO_DEADLINE to wait for as long as it takes
     */
    private static byte[] readPacket(Transport transport, long deadline) throws DeviceException {
        while(true) {
            int timeoutMs = 0;
            if(deadline != NO_DEADLINE) {
                long remainingMs = deadline - System.currentTimeMillis();
                if(remainingMs <= 0) {
                    throw new DeviceTimeoutException("Timed out reading packet");
                }

                timeoutMs = (int)remainingMs;
            }

            try {
                byte[] packet = timeoutMs > 0 ? transport.read(timeoutMs) : transport.read();
                if(packet == null || packet.length != PACKET_SIZE) {
                    throw new DeviceException("Invalid packet received (" + (packet == null ? "null" : packet.length + " bytes") + ")");
                }

                return packet;
            } catch(DeviceTimeoutException e) {
                // A device waiting for the user to confirm can take far longer than the transport read timeout
                if(log.isTraceEnabled()) {
                    log.trace("Read timeout, continuing to poll for a packet");
                }
            }
        }
    }

    /**
     * Calculate the number of packets a message of the given transport payload length occupies.
     */
    private static int calculateRequiredPackets(int transportPayloadLength) {
        // Length already includes CRC
        int firstPacketPayload = 59;
        if(transportPayloadLength <= firstPacketPayload) {
            return 1;
        }

        int remainingBytes = transportPayloadLength - firstPacketPayload;
        int continuationPacketPayload = 61;

        return 1 + (remainingBytes + continuationPacketPayload - 1) / continuationPacketPayload;
    }
}
