# CSL: Custom Security Layer

This is a TLS-inspired secure channel over raw TCP sockets, written in C with OpenSSL for the primitives. It has a handshake, a record layer, and a simple client/server chat on top. It also has a small CA and certificates for identity checking (Level 8).

## Status by level

| Level | Topic | Status |
| --- | --- | --- |
| 1 | TCP plumbing and framing | Done (length-prefixed frames, no type byte) |
| 2 | Diffie-Hellman | Done, using X25519 (ECDH bonus) |
| 3 | Key derivation | Done, using HKDF-SHA256 (bonus) |
| 4 | Handshake confirmation | Done |
| 5 | Encrypted, authenticated messaging | Done, AES-256-GCM with per-message nonce and sequence number (bonus) |
| 6 | Chat application | Partial: a client-to-server chat works, but it is not a proper 1-1 chat |
| 7 | Chat room | Not done |
| 8 | PKI | Done |

## Files

| File | What it holds |
| --- | --- |
| `com.h`, `com.c` | Socket helpers: `accept_connection`, `sendall`, `receive_message`. Ports, buffer and frame sizes. |
| `encrypt.h`, `encrypt.c` | HKDF key derivation, nonce construction, AES-256-GCM encrypt/decrypt, Ed25519 sign/verify, certificate create/verify. Also the `Certificate` struct. |
| `key.h`, `key.c` | X25519 key exchange with identity authentication (`secret_key`), the full `handshake`, and loaders for PEM keys and certificates. |
| `server.c` | Server: listen, accept one client, handshake, receive and decrypt messages. |
| `client.c` | Client: connect, handshake, read lines from stdin, encrypt and send. |
| `make_cert.c` | Command-line tool that makes a CA-signed certificate for a user. |

The server and client both look for these files at runtime:

- `keys/server_private.pem` or `keys/client_private.pem` (own identity key)
- `keys/ca_public.pem`
- `certs/server.cert` or `certs/client.cert`

The client connects to `127.0.0.1:6996`, and the server listens on port `6996` (set in `com.h`).

## Level 1: TCP plumbing and framing

The server does the usual `socket`, `bind`, `listen`, `accept`. The client does `socket` and `connect`.

Since TCP is a byte stream, every message is sent as a frame:

```
[ 1 byte: payload length ][ payload ]
```

`sendall` builds the frame in a 256-byte buffer, puts the length in byte 0, copies the payload after it, and loops on `send()` until the whole frame has gone out. It refuses payloads longer than 255 bytes.

`receive_message` keeps a work buffer (`workbuf`) and a count of bytes in it (`bytes_in_buffer`) `between calls`. It reads the length from the first byte, keeps calling `recv()` until a full frame is in the buffer, and copies the payload out. It then moves any leftover bytes to the front of the work buffer with `memmove`, so two frames arriving in one `recv()` (or a frame split across two) are both handled. Return values: `1` for a message, `0` if the peer closed, `-1` on a recv error.

The frame has only a length field. There is no separate type byte; what a message means is decided by where it is in the protocol (handshake message, then Finished MAC, then chat records).

## Level 2: Diffie-Hellman (X25519)

I used elliptic-curve DH (the bonus). In `secret_key()`:

1. A fresh X25519 keypair is generated with `EVP_PKEY_Q_keygen` for every connection.
2. The 32-byte raw public key is taken out with `EVP_PKEY_get_raw_public_key`.
3. The public key is sent to the peer (inside the handshake message, see Level 8) and the peer’s one is received.
4. The peer’s raw key is loaded with `EVP_PKEY_new_raw_public_key`, and `EVP_PKEY_derive` gives the 32-byte shared secret.

Neither side sends its private key, and both get the same secret on their own.

## Level 3: Key derivation (HKDF)

The raw shared secret is never used as a key. `derive_key()` in `encrypt.c` uses OpenSSL’s `HKDF` with SHA-256, in two stages:

1. **Extract**: the shared secret goes in (`EXTRACT_ONLY` mode) and a 32-byte pseudorandom key (`prk`) comes out.
2. **Expand**: two separate expansions of `prk`, each with its own `info` label, give two 32-byte keys:
    - encryption key, label `"CSL Client-to-Server Encryption-Key"`
    - MAC key, label `"CSL Client-to-Server MAC-Key"`

The function also has `SERVER` labels (`"CSL Server-to-Client ..."`), picked by the `writer` argument. In `handshake()` it is always called with `CLIENT`, so both sides derive the same encryption key and the same MAC key.

## Level 4: Handshake confirmation

After the keys are derived, each side builds a 64-byte transcript:

```
client X25519 public key || server X25519 public key
```

The order is fixed by role, so both sides build identical bytes. Each side computes `HMAC-SHA256(mac_key, transcript)` and exchanges it as a frame. The server receives first and then sends. The client sends first and then receives.

The received value must be exactly 32 bytes and is compared to the local one with `CRYPTO_memcmp` (constant time). On a match it prints `Handshake successful!`. Otherwise it prints `Handshake unsuccessful!` and returns an error, and `server.c` / `client.c` then print `Handshake failed` and exit before any chat message is sent.

If a public value is changed in transit, the two sides derive different secrets and different keys, so the MACs do not match and the handshake aborts. With Level 8, a modified X25519 key would also fail the signature check earlier, in `secret_key()`.

## Level 5: Encrypted, authenticated messages

Each chat message is encrypted with **AES-256-GCM** (`encrypt_message` / `decrypt_message`). GCM is an AEAD mode: it produces a 16-byte authentication tag over the ciphertext and the associated data, and decryption fails if either is altered. So a separate MAC is not needed for chat messages. (HMAC is used only for the handshake Finished message.)

**Record format** (this is the payload of one frame):

```
[ 8 bytes: sequence number ][ ciphertext ][ 16 bytes: GCM tag ]
```

**Nonce.** 12 bytes, built by `make_nonce()`. It starts from the first 12 bytes of the client’s X25519 public key (used as an IV), and the 64-bit sequence number is XORed into the last 8 bytes. Since the sequence number goes up by one per message, the nonce is different for every message in a session.

**Sequence number.** The client starts at 0 and increments after every message. The 8-byte sequence number is also passed to GCM as AAD, so it is authenticated too.

**Receiving side** (`server.c`) checks, in order:

1. The record is at least 24 bytes (8 + 16), otherwise `Record too short`.
2. The sequence number in the record equals `expected_seq`, otherwise `Bad sequence number`. This catches replays and reordering.
3. `decrypt_message` succeeds. A bad tag gives `Authentication FAILED` and the loop ends.

`expected_seq` is incremented only after a message is accepted.

Because `sendall` allows at most 255 bytes per frame and a record has 24 bytes of overhead, one chat message can be at most 231 bytes.

## Level 6: Chat application (partial)

What works: the handshake runs automatically when the client connects. After that, the user types a line in the client terminal, and it is encrypted and sent. The server decrypts it and prints it.

- `client.c` reads lines with `getline`, removes the newline, encrypts, packs the record and sends it.
- Typing `exit` sends the message and the client prints `Good-Bye User!` and quits. The server prints `User left!`.

What is missing: messages go in one direction only (client to server). The server never sends anything back, and it serves just one client connection. So this is a working encrypted client-to-server chat, but I did not complete Level 6 as a proper two-way 1-1 chat.

## Level 7: Chat room

Not implemented.

## Level 8: PKI

**Identity keys.** Each user (and the CA) has an Ed25519 keypair stored as PEM and loaded with `load_private_key` / `load_public_key`.

**Certificate.** A fixed-size struct, 128 bytes:

```
username (32) || identity_public_key (32) || ca_signature (64)
```

The CA signature is Ed25519 over `username || identity_public_key` (64 bytes). `create_certificate()` signs, `verify_certificate()` rebuilds the same 64 bytes and verifies against the CA public key.

**`make_cert`** is the CA tool:

```
./make_cert <identity_private.pem> <username> <certificate.bin>
```

It loads `keys/ca_private.pem` and the given identity private key, copies the username into the struct, takes the raw public key out of the identity key, has the CA sign it, and writes the raw struct to the output file. The server and client read that file back with `load_certificate`.

**Handshake message.** Each side signs its ephemeral X25519 public key with its identity key, then sends one 224-byte frame:

```
username (32) || identity_public_key (32) || ca_signature (64)
|| x25519_public_key (32) || signature_of_x25519_key (64)
```

**Verification** on receipt (in `secret_key()`):

1. The frame must be exactly 224 bytes.
2. The peer certificate is verified against the CA public key. On success it prints `Peer certificate verified: <username>`.
3. The identity public key from that certificate is used to verify the signature over the peer’s X25519 public key. On success it prints `Peer X25519 public key authenticated`.

If any step fails, the function frees its keys and returns an error, the handshake is aborted and the program exits. This stops someone in the middle from swapping in their own DH value, since they cannot produce a valid signature under a CA-certified identity key.

## Limitations

These are things visible in the code as it stands:

- Frames have a 1-byte length and no type byte, and a payload is capped at 255 bytes.
- Both directions would share the same derived keys, because `derive_key` is always called with `CLIENT`. This is fine today since only the client sends records.
- Chat is one-way and single-client (see Level 6). No chat room (Level 7).
