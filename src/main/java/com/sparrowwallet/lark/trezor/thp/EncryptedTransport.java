package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.noise.NoiseTransport;

import javax.crypto.AEADBadTagException;

/**
 * THP encrypted transport layer.
 *
 * Wraps NoiseTransport to provide encrypted communication over an allocated THP channel. Packet
 * framing and the Alternating Bit Protocol are handled by the underlying ChannelTransport.
 */
public class EncryptedTransport {
    private final ChannelTransport channelTransport;
    private final NoiseTransport noiseTransport;

    /**
     * Create encrypted transport.
     *
     * @param channelTransport The channel transport for message I/O
     * @param noiseTransport The Noise transport for encryption/decryption
     */
    public EncryptedTransport(ChannelTransport channelTransport, NoiseTransport noiseTransport) {
        this.channelTransport = channelTransport;
        this.noiseTransport = noiseTransport;
    }

    /**
     * Send encrypted message on the allocated channel.
     *
     * @param applicationData The plaintext application data to send
     * @throws DeviceException if encryption or transmission fails
     */
    public void sendMessage(byte[] applicationData) throws DeviceException {
        channelTransport.sendMessage(ControlByte.PacketType.ENCRYPTED_TRANSPORT, noiseTransport.writeMessage(applicationData));
    }

    /**
     * Receive and decrypt message from the allocated channel.
     *
     * @return Decrypted application data
     * @throws DeviceException if reception or decryption fails
     */
    public byte[] receiveMessage() throws DeviceException {
        PacketCodec.ReassembledMessage message = channelTransport.receiveMessage();

        ControlByte.PacketType packetType = ControlByte.getPacketType(message.controlByte);
        if(packetType != ControlByte.PacketType.ENCRYPTED_TRANSPORT) {
            throw new DeviceException("Unexpected packet type: " + packetType);
        }

        try {
            return noiseTransport.readMessage(message.applicationData);
        } catch(AEADBadTagException e) {
            throw new DeviceException("Decryption failed: invalid authentication tag", e);
        }
    }
}
