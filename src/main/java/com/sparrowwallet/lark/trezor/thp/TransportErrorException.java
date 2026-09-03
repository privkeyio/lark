package com.sparrowwallet.lark.trezor.thp;

import com.sparrowwallet.lark.DeviceException;

/**
 * A THP transport error reported by the device for a channel.
 */
public class TransportErrorException extends DeviceException {

    /** The device has no buffer available and the message should be sent again shortly */
    public static final int TRANSPORT_BUSY = 1;

    private final int errorCode;

    public TransportErrorException(int channelId, int errorCode) {
        super("Transport error on channel 0x" + String.format("%04X", channelId) + ": " + getErrorName(errorCode) + " (code " + errorCode + ")");
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }

    private static String getErrorName(int errorCode) {
        return switch(errorCode) {
            case TRANSPORT_BUSY -> "TRANSPORT_BUSY";
            case 2 -> "UNALLOCATED_CHANNEL";
            case 3 -> "DECRYPTION_FAILED";
            case 5 -> "DEVICE_LOCKED";
            default -> "UNKNOWN";
        };
    }
}
