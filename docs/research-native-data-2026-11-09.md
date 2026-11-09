# Open-source references for native content protection

The protection target in this experiment is exact recovery of a generated 32-byte asset from a complete application release. The test also changes an application gate and forces an authentication-success return. It separately supplies the correct key to verify normal use. All inputs, keys and payloads are generated for this project.

| Reference reviewed | Relevant behavior | Engineering decision |
| --- | --- | --- |
| O-MVLL | Its string-encoding documentation describes runtime reconstruction and discusses memory dumps, dynamic instrumentation and emulation. The pass documentation also describes code-size, memory and execution costs. | Measure actual data recovery. Keep the sensitive decryption key outside the shipped implementation. |
| UPX | Its README describes a reversible executable compressor and explicitly declines a protection or encryption role. | Compression is useful for packaging. It cannot establish the confidentiality measured here. |
| age | Its design separates secret identities from encrypted files and authenticates encrypted payloads. | Keep external key delivery explicit. Continue using the project's existing sealed-asset protocol. |
| libsodium | Its authenticated-decryption API checks the authenticator before exposing accepted plaintext. | Require authenticated completion before returning a native asset and clear temporary output on refusal. |
| OpenSSL | Its EVP API provides HKDF-SHA256 and AES-GCM. GCM update output must be discarded if final authentication fails. | Add a small native reader that interoperates with the existing Python format. Test failure behavior and a deliberately bypassed final check. |

Sources are fixed where repository commits are available. [O-MVLL string implementation](https://github.com/open-obfuscator/o-mvll/blob/0bee964f797cdcab69953671134efac336d2bb72/src/passes/string-encoding/StringEncoding.cpp) · [O-MVLL pass documentation](https://obfuscator.re/omvll/passes/strings-encoding/) · [UPX README](https://github.com/upx/upx/blob/f8cda4018efe0961365d0568d332e52482e987b1/README) · [age design](https://github.com/FiloSottile/age/blob/b74dce4cdbe35b5e5f66c06d9612b72f89028758/age.go) · [libsodium decryption implementation](https://github.com/jedisct1/libsodium/blob/bbccd06144cc26d5c67d554bd87abb8dc1edcb30/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c) · [OpenSSL GCM API](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/) · [OpenSSL HKDF API](https://docs.openssl.org/3.0/man3/EVP_PKEY_CTX_set_hkdf_md/)

## Cryptographic and experimental boundaries

The shipped envelope contains a salt, nonce and authenticated ciphertext. HKDF derives a package key from the external random 256-bit master key and the exact application context. The compiler receives only public arrays. The native implementation is a reader for data assets up to 1 MiB.

Changing a local branch changes control flow. With a wrong key, decrypting the ciphertext still produces different bytes. The fixture therefore checks the exact original payload hash even when a patched program returns success. An accidental-key control restores recovery, demonstrating why independent key delivery is necessary.

At legitimate use time, the application possesses its key and plaintext. A process owner can inspect that execution. Encryption of selected assets does not conceal every instruction of an executable, prevent copying a licensed user's key, or establish resistance to unrestricted manual reverse engineering. The observation records the precise tool versions, architecture, inputs and bounded extraction procedure. Ghidra and IDA receive only the public executable for each run.
