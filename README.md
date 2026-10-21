# Lark, for Shrike

An unofficial fork of [Lark](https://github.com/sparrowwallet/lark), the hardware wallet library [Shrike](https://github.com/privkeyio/shrike) uses. It asks a Trezor running the [unified opt-in signature hash firmware](https://github.com/privkeyio/trezor-firmware) for that hash type, and refuses the opt-in where the device cannot honor it. It is not affiliated with the Sparrow project.

> **Not audited. Use at your own risk, and no warranty of any kind, see the [Apache 2.0 license](LICENSE).** Everything below the divider is upstream's documentation and describes Lark rather than this fork.

---

# Lark

Lark is Java library for interacting with USB hardware wallets in Bitcoin related functions. 
The initial implementation is a port of the Python library [HWI](https://github.com/bitcoin-core/HWI), but the library has since been extended to support additional functionality.

The following hardware wallets (for all models, unless specified) are supported:
- Coldcard
- Trezor
- Ledger
- BitBox02
- Jade
- Keepkey
- OneKey (Classic 1S and Pro)

## Example usage

```java
Lark lark = new Lark();
List<HardwareClient> clients = lark.enumerate();

for(HardwareClient client : clients) {
    ExtendedKey xpub = lark.getPubKeyAtPath(client.getType(), client.getPath(), "m/84'/1'/0'");
}
```