package com.sparrowwallet.lark.trezor;

import com.sparrowwallet.lark.DeviceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Arrays;

/**
 * UDP transport for the Trezor emulator, which speaks the same 64-byte packet framing as USB
 * but over a datagram socket. It exists so the signing path can be exercised end to end without
 * hardware; the emulator runs the same firmware sources as a device.
 */
public class UdpTransport implements Transport {
    private static final Logger log = LoggerFactory.getLogger(UdpTransport.class);

    public static final String DEFAULT_HOST = "127.0.0.1";
    public static final int DEFAULT_PORT = 21324;

    private static final int PACKET_SIZE = 64;
    private static final int DEFAULT_TIMEOUT = 30000;

    private final DatagramSocket socket;
    private final InetAddress address;
    private final int port;
    private boolean closed = false;

    public UdpTransport(String host, int port) throws DeviceException {
        try {
            this.address = InetAddress.getByName(host);
            this.port = port;
            this.socket = new DatagramSocket();
            this.socket.setSoTimeout(DEFAULT_TIMEOUT);
        } catch(IOException e) {
            throw new DeviceException("Could not open UDP transport to " + host + ":" + port, e);
        }
    }

    /**
     * Answers whether an emulator is listening, using the same ping the emulator answers before
     * any protocol is negotiated. Avoids a long blocking read against a port nothing is bound to.
     */
    public static boolean isPresent(String host, int port, int timeoutMs) {
        try(DatagramSocket probe = new DatagramSocket()) {
            probe.setSoTimeout(timeoutMs);
            byte[] ping = "PINGPING".getBytes();
            probe.send(new DatagramPacket(ping, ping.length, InetAddress.getByName(host), port));
            byte[] buf = new byte[8];
            DatagramPacket response = new DatagramPacket(buf, buf.length);
            probe.receive(response);
            return new String(buf, 0, response.getLength()).equals("PONGPONG");
        } catch(IOException e) {
            return false;
        }
    }

    @Override
    public void write(byte[] packet) throws DeviceException {
        checkOpen();
        byte[] chunk = packet;
        if(chunk.length != PACKET_SIZE) {
            chunk = Arrays.copyOf(chunk, PACKET_SIZE);
        }
        try {
            socket.send(new DatagramPacket(chunk, chunk.length, address, port));
        } catch(IOException e) {
            throw new DeviceException("Could not write to the Trezor emulator", e);
        }
    }

    @Override
    public byte[] read() throws DeviceException {
        return read(DEFAULT_TIMEOUT);
    }

    @Override
    public byte[] read(int timeoutMs) throws DeviceException {
        checkOpen();
        try {
            socket.setSoTimeout(timeoutMs);
            byte[] buf = new byte[PACKET_SIZE];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);
            return Arrays.copyOf(buf, PACKET_SIZE);
        } catch(SocketTimeoutException e) {
            throw new DeviceTimeoutException("Timed out reading from the Trezor emulator");
        } catch(IOException e) {
            throw new DeviceException("Could not read from the Trezor emulator", e);
        }
    }

    @Override
    public void close() {
        if(!closed) {
            socket.close();
            closed = true;
            log.debug("UDP transport closed");
        }
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    private void checkOpen() throws DeviceException {
        if(closed) {
            throw new DeviceException("UDP transport is closed");
        }
    }
}
