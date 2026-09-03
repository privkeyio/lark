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
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
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
import java.util.Base64;
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

    /**
     * A 2-of-2 P2WSH wallet: one key on the device, one a software seed. The second key is what makes
     * the device's multisig path run, and it is also the cosigner that finishes the transaction.
     *
     * A P2WSH input takes the witnessScript as the script code the unified message commits to, where a
     * P2WPKH input takes the implied P2PKH script instead, so this exercises the other branch.
     */
    private static final String COSIGNER_MNEMONIC =
            "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";

    private static Wallet multisigWallet(EmulatorClient client) throws Exception {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);

        String accountPath = KeyDerivation.writePath(ScriptType.P2WSH.getDefaultDerivation());
        Keystore deviceKeystore = new Keystore("Trezor");
        deviceKeystore.setSource(KeystoreSource.HW_USB);
        deviceKeystore.setWalletModel(WalletModel.TREZOR_1);
        deviceKeystore.setKeyDerivation(new KeyDerivation(client.fingerprint(), accountPath));
        deviceKeystore.setExtendedPublicKey(client.getPubKeyAtPath(accountPath));
        wallet.getKeystores().add(deviceKeystore);

        DeterministicSeed seed = new DeterministicSeed(COSIGNER_MNEMONIC, "", 0, DeterministicSeed.Type.BIP39);
        wallet.getKeystores().add(Keystore.fromSeed(seed, PolicyType.MULTI_HD, ScriptType.P2WSH.getDefaultDerivation()));

        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.getNode(KeyPurpose.RECEIVE);
        return wallet;
    }

    /**
     * A 2-of-2 where both keys are on the same device, two accounts apart. This is the case that makes
     * TrezorClient run its signing loop more than once, which a wallet with one device key never does.
     */
    private static Wallet twoDeviceKeyWallet(EmulatorClient client) throws DeviceException {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);

        for(int account = 0; account < 2; account++) {
            String accountPath = KeyDerivation.writePath(ScriptType.P2WSH.getDefaultDerivation(account));
            Keystore keystore = new Keystore("Trezor" + account);
            keystore.setSource(KeystoreSource.HW_USB);
            keystore.setWalletModel(WalletModel.TREZOR_1);
            keystore.setKeyDerivation(new KeyDerivation(client.fingerprint(), accountPath));
            keystore.setExtendedPublicKey(client.getPubKeyAtPath(accountPath));
            wallet.getKeystores().add(keystore);
        }

        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
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

        if("signpsbt".equals(mode)) {
            //Signs a PSBT built elsewhere, which is how the wallet's own decision about the hash type is
            //carried into the device path without this harness making that decision itself. Handled before
            //any script type is read, because the PSBT already says what the inputs are.
            PSBT given = new PSBT(Base64.getDecoder().decode(args[1]));
            System.out.println("DECLARED=" + given.getPsbtInputs().getFirst().getSigHash());
            client.signTransaction(given);
            System.out.println("SIGNED_PSBT=" + Base64.getEncoder().encodeToString(given.serialize()));
            return;
        }

        boolean twoDeviceKeys = mode.startsWith("twokey");
        boolean multisig = twoDeviceKeys || mode.startsWith("multisig");
        ScriptType scriptType = multisig ? ScriptType.P2WSH : ScriptType.valueOf(args[1]);
        Wallet wallet = twoDeviceKeys ? twoDeviceKeyWallet(client)
                : (multisig ? multisigWallet(client) : deviceWallet(client, scriptType));
        if(multisig) {
            mode = mode.substring(twoDeviceKeys ? "twokey".length() : "multisig".length()).toLowerCase();
        }

        if("xpub".equals(mode)) {
            //What a wallet imports from the device, and the fingerprint it files it under.
            String accountPath = ScriptType.valueOf(args[1]).getDefaultDerivationPath();
            System.out.println("XPUB=" + client.getPubKeyAtPath(accountPath));
            System.out.println("FP=" + client.fingerprint());
            return;
        }

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
        //"true"/"false" pick the two ordinary types; anything else names a SigHash directly, which is
        //how the types the device must refuse are exercised.
        SigHash requestedSigHash;
        if(args[7].equalsIgnoreCase("true")) {
            requestedSigHash = SigHash.UNIFIED_ALL;
        } else if(args[7].equalsIgnoreCase("false")) {
            requestedSigHash = scriptType == ScriptType.P2TR ? SigHash.DEFAULT : SigHash.ALL;
        } else {
            requestedSigHash = SigHash.valueOf(args[7]);
        }
        boolean unified = requestedSigHash.isUnified();
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
        //A witness utxo belongs only on a segwit input; PSBT rejects one on a legacy input. Trezor
        //verifies every input amount against the transaction that created it, so the whole previous
        //transaction is supplied either way.
        if(scriptType != ScriptType.P2PKH) {
            psbtInput.setWitnessUtxo(new TransactionOutput(null, prevValue, spk.getProgram()));
        }
        psbtInput.setNonWitnessUtxo(prevTx);

        if(multisig) {
            //The script code a segwit v0 multisig input commits to, and the xpubs the device needs to
            //recognise the redeem script as its own.
            psbtInput.setWitnessScript(ScriptType.MULTISIG.getOutputScript(
                    wallet.getDefaultPolicy().getNumSignaturesRequired(), receiveNode.getPubKeys()));
            for(Keystore keystore : wallet.getKeystores()) {
                psbt.getExtendedPublicKeys().put(keystore.getExtendedPublicKey(), keystore.getKeyDerivation());
                psbtInput.getDerivedPublicKeys().put(
                        keystore.getPubKey(receiveNode),
                        keystore.getKeyDerivation().extend(receiveNode.getDerivation()));
            }
            psbtInput.setSigHash(requestedSigHash);
            System.out.println("DECLARED=" + psbtInput.getSigHash());

            //The device signs first. With one device key a software cosigner finishes it; with two, the
            //device supplies both and TrezorClient runs its loop twice.
            client.signTransaction(psbt);
            if(!twoDeviceKeys) {
                wallet.sign(psbt);
            }

            TransactionSignature deviceSignature = psbtInput.getPartialSignatures().values().iterator().next();
            System.out.println("RETURNED_SIGHASH=0x" + String.format("%02x", deviceSignature.sighashFlags));
            System.out.println("SIGNATURES=" + psbtInput.getPartialSignatures().size());

            wallet.finalise(psbt);
            System.out.println("TX=" + Utils.bytesToHex(psbt.extractTransaction().bitcoinSerialize()));
            return;
        }

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

        psbtInput.setSigHash(requestedSigHash);
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
