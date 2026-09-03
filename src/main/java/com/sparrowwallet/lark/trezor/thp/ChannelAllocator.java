package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.trezor.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

/**
 * THP channel allocation protocol.
 *
 * Handles requesting channel allocation from the device on the broadcast channel (0xFFFF).
 * The allocation must complete before the handshake can begin.
 *
 * Protocol flow:
 * 1. Generate nonce and build allocation request
 * 2. Send request on broadcast channel with CHANNEL_ALLOCATION_REQ control byte
 * 3. Receive allocation response with channel ID and device properties
 * 4. Device properties are used as Noise protocol prologue
 */
public class ChannelAllocator {
    private static final Logger log = LoggerFactory.getLogger(ChannelAllocator.class);

    /** How long to wait for the device to allocate a channel */
    private static final int ALLOCATION_TIMEOUT_MS = 5000;

    private static final int NONCE_LENGTH = 8;

    private final Transport transport;

    /**
     * Create channel allocator.
     *
     * @param transport The transport for sending/receiving packets
     */
    public ChannelAllocator(Transport transport) {
        this.transport = transport;
    }

    /**
     * Request channel allocation from the device.
     *
     * @param protocolVersion The THP protocol version to request
     * @return Allocation response with channel ID and device properties
     * @throws DeviceException if allocation fails
     */
    public ChannelAllocationMessages.AllocationResponse allocateChannel(int protocolVersion) throws DeviceException {
        // Generate nonce for request/response matching
        byte[] nonce = Channel.generateNonce();

        // Build allocation request
        byte[] requestPayload = ChannelAllocationMessages.buildAllocationRequest(nonce, protocolVersion);

        if(log.isDebugEnabled()) {
            log.debug("Sending channel allocation request (nonce: {}, {} bytes)", com.sparrowwallet.drongo.Utils.bytesToHex(nonce), requestPayload.length);
        }

        // Send allocation request on broadcast channel
        sendAllocationRequest(requestPayload);

        if(log.isDebugEnabled()) {
            log.debug("Waiting for channel allocation response...");
        }

        // Receive and parse allocation response
        byte[] responsePayload = receiveAllocationResponse(nonce);

        if(log.isDebugEnabled()) {
            log.debug("Received channel allocation response ({} bytes)", responsePayload.length);
        }

        return ChannelAllocationMessages.parseAllocationResponse(responsePayload, nonce);
    }

    /**
     * Send allocation request on broadcast channel.
     */
    private void sendAllocationRequest(byte[] payload) throws DeviceException {
        // Create control byte for channel allocation request
        // Sequence and ACK bits are 0 for allocation messages
        byte controlByte = ControlByte.createChannelAllocationReq(false, false);

        // Segment into packets with broadcast channel ID
        List<byte[]> packets = PacketCodec.segment(controlByte, Channel.BROADCAST_CHANNEL_ID, payload);

        if(log.isDebugEnabled()) {
            log.debug("Sending {} packet(s) on broadcast channel 0xFFFF",  packets.size());
            for(int i = 0; i < packets.size(); i++) {
                log.debug("Packet {}: {}", i, com.sparrowwallet.drongo.Utils.bytesToHex(packets.get(i)));
            }
        }

        // Send all packets
        for(byte[] packet : packets) {
            transport.write(packet);
        }
    }

    /**
     * Receive allocation response from broadcast channel.
     *
     * An attempt that ended without reading its response leaves the device sending packets for minutes,
     * so anything that is not the response to this request is discarded rather than failing allocation.
     */
    private byte[] receiveAllocationResponse(byte[] nonce) throws DeviceException {
        long deadline = System.currentTimeMillis() + ALLOCATION_TIMEOUT_MS;

        while(true) {
            PacketCodec.ReassembledMessage message = PacketReader.read(transport, deadline);

            if(ControlByte.getPacketType(message.controlByte) != ControlByte.PacketType.CHANNEL_ALLOCATION_RESP
                    || message.channelId != Channel.BROADCAST_CHANNEL_ID) {
                if(log.isDebugEnabled()) {
                    log.debug("Discarding {} for channel 0x{} while awaiting channel allocation",
                            ControlByte.toString(message.controlByte), String.format("%04X", message.channelId));
                }
                continue;
            }

            // A response carrying a different nonce answers an allocation request we have abandoned
            if(message.applicationData.length < NONCE_LENGTH || !Arrays.equals(message.applicationData, 0, NONCE_LENGTH, nonce, 0, NONCE_LENGTH)) {
                if(log.isDebugEnabled()) {
                    log.debug("Discarding channel allocation response for another request");
                }
                continue;
            }

            return message.applicationData;
        }
    }
}
