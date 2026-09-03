package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.KeystoreSource;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.drongo.wallet.WalletNode;
import com.sparrowwallet.lark.trezor.PassphraseUI;
import com.sparrowwallet.lark.trezor.TrezorDevice;
import com.sparrowwallet.lark.trezor.TrezorModel;
import com.sparrowwallet.lark.trezor.UdpTransport;
import com.sparrowwallet.lark.trezor.generated.TrezorMessageDebug;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Drives the shipped Trezor signing path against the emulator, so the unified opt-in can be verified
 * end to end without hardware. The emulator runs the same firmware sources as a device and speaks the
 * same protocol; only the transport differs, and that is the one thing this subclass replaces.
 *
 * scriptpubkey scriptType
 *          prints the scriptPubKey of the wallet's first receive address, so the funding side and the
 *          signing side cannot disagree about which output is being spent
 * send scriptType prevTxid prevVout prevValue destScriptHex destValue unified prevTxHex
 *          signs that output and prints the finalised transaction. unified is true or false
 */
public class TrezorEmulatorHarness {
    private static final String HOST = System.getProperty("trezor.emulator.host", UdpTransport.DEFAULT_HOST);
    private static final int PORT = Integer.getInteger("trezor.emulator.port", UdpTransport.DEFAULT_PORT);

    /**
     * Answers the emulator's confirmation prompts over the debug link, which is what a finger does on a
     * device. Pressing is driven by the device asking rather than by a timer, because the emulator
     * serves both links from one loop and unsolicited debug traffic desynchronises the main one.
     */
    private static class AutoConfirmUI extends PassphraseUI {
        AutoConfirmUI() {
            super("");
        }

        @Override
        public void buttonRequest(Integer code) {
            //callbackButton() has already sent ButtonAck and is about to wait for the device, so the
            //press belongs here.
            try(DatagramSocket socket = new DatagramSocket()) {
                byte[] decision = TrezorMessageDebug.DebugLinkDecision.newBuilder()
                        .setButton(TrezorMessageDebug.DebugLinkDecision.DebugButton.YES)
                        .build().toByteArray();
                for(byte[] packet : frameV1(MESSAGE_TYPE_DEBUG_LINK_DECISION, decision)) {
                    socket.send(new DatagramPacket(packet, packet.length, InetAddress.getByName(HOST), PORT + 1));
                }
            } catch(IOException e) {
                throw new IllegalStateException("Could not press the emulator's button", e);
            }
        }
    }

    private static final int MESSAGE_TYPE_DEBUG_LINK_DECISION = 100;

    /** The v1 framing: "?##" then type and length big endian, in 64 byte packets. */
    private static List<byte[]> frameV1(int messageType, byte[] payload) {
        ByteBuffer header = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        header.put((byte)'#').put((byte)'#').putShort((short)messageType).putInt(payload.length);
        byte[] body = new byte[header.capacity() + payload.length];
        System.arraycopy(header.array(), 0, body, 0, header.capacity());
        System.arraycopy(payload, 0, body, header.capacity(), payload.length);

        List<byte[]> packets = new ArrayList<>();
        for(int offset = 0; offset < body.length || packets.isEmpty(); offset += 63) {
            byte[] packet = new byte[64];
            packet[0] = (byte)'?';
            int length = Math.min(63, body.length - offset);
            System.arraycopy(body, offset, packet, 1, Math.max(length, 0));
            packets.add(packet);
        }
        return packets;
    }

    /**
     * The client under test, reaching the emulator over UDP rather than USB. Everything else, including
     * signTransaction() and the opt-in it now sets, is the code that ships.
     */
    private static class EmulatorClient extends TrezorClient {
        EmulatorClient() {
            super(TrezorModel.T1B1);
        }

        @Override
        protected TrezorDevice openDevice() throws DeviceException {
            return new TrezorDevice(new UdpTransport(HOST, PORT), new AutoConfirmUI(), TrezorModel.T1B1, null);
        }
    }

    /** A watch only wallet over the account the device exports, so every key comes from the device. */
    private static Wallet deviceWallet(EmulatorClient client, ScriptType scriptType) throws DeviceException {
        String accountPath = scriptType.getDefaultDerivationPath();
        ExtendedKey accountKey = client.getPubKeyAtPath(accountPath);

        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(scriptType);

        Keystore keystore = new Keystore();
        keystore.setSource(KeystoreSource.HW_USB);
        keystore.setWalletModel(WalletModel.TREZOR_1);
        keystore.setKeyDerivation(new KeyDerivation(client.fingerprint(), accountPath));
        keystore.setExtendedPublicKey(accountKey);
        wallet.getKeystores().add(keystore);

        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, scriptType, wallet.getKeystores(), null));
        wallet.getNode(KeyPurpose.RECEIVE);
        return wallet;
    }

    private static WalletNode firstReceiveNode(Wallet wallet) {
        return wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
    }

    public static void main(String[] args) throws Exception {
        Network.set(Network.REGTEST);

        EmulatorClient client = new EmulatorClient();
        client.initializeMasterFingerprint();

        String mode = args[0];
        ScriptType scriptType = ScriptType.valueOf(args[1]);
        Wallet wallet = deviceWallet(client, scriptType);

        if("scriptpubkey".equals(mode)) {
            System.out.println("SPK=" + Utils.bytesToHex(wallet.getOutputScript(firstReceiveNode(wallet)).getProgram()));
            return;
        }
        if(!"send".equals(mode)) {
            throw new IllegalArgumentException("Unknown mode " + mode);
        }

        Sha256Hash prevTxid = Sha256Hash.wrap(args[2]);
        int prevVout = Integer.parseInt(args[3]);
        long prevValue = Long.parseLong(args[4]);
        byte[] destScript = Utils.hexToBytes(args[5]);
        long destValue = Long.parseLong(args[6]);
        boolean unified = Boolean.parseBoolean(args[7]);
        Transaction prevTx = new Transaction(Utils.hexToBytes(args[8]));

        WalletNode receiveNode = firstReceiveNode(wallet);
        Script spk = wallet.getOutputScript(receiveNode);

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(prevTxid, prevVout, new Script(new byte[0]));
        transaction.getInputs().getFirst().setSequenceNumber(0xFFFFFFFDL);
        transaction.addOutput(destValue, new Script(destScript));

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.setWitnessUtxo(new TransactionOutput(null, prevValue, spk.getProgram()));
        //Trezor verifies every input amount against the transaction that created it, so it wants the
        //whole previous transaction rather than only the output being spent.
        psbtInput.setNonWitnessUtxo(prevTx);

        //Where the device looks to decide the input is one of its own.
        KeyDerivation keyDerivation = wallet.getKeystores().getFirst().getKeyDerivation()
                .extend(receiveNode.getDerivation());
        ECKey pubKey = receiveNode.getPubKey();
        if(scriptType == ScriptType.P2TR) {
            psbtInput.setTapInternalKey(pubKey);
            psbtInput.getTapDerivedPublicKeys().put(pubKey, java.util.Map.of(keyDerivation, java.util.List.of()));
        } else {
            psbtInput.getDerivedPublicKeys().put(pubKey, keyDerivation);
        }
        if(scriptType == ScriptType.P2SH_P2WPKH) {
            psbtInput.setRedeemScript(ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, pubKey));
        }

        psbtInput.setSigHash(unified ? SigHash.UNIFIED_ALL : SigHash.ALL);
        System.out.println("DECLARED=" + psbtInput.getSigHash());

        client.signTransaction(psbt);

        TransactionSignature signature = scriptType == ScriptType.P2TR
                ? psbtInput.getTapKeyPathSignature()
                : psbtInput.getPartialSignatures().values().iterator().next();
        System.out.println("RETURNED_SIGHASH=0x" + String.format("%02x", signature.sighashFlags));

        wallet.finalise(psbt);
        System.out.println("TX=" + Utils.bytesToHex(psbt.extractTransaction().bitcoinSerialize()));
    }
}
