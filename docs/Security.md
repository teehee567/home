## Security stack

- Network concealment
  - WireGuard is embedded through `boringtun` underneath QUIC as a silent public-port
    gatekeeper.
  - The client tries the server's local IP first, then its last-known public IP.
  - For cold-start discovery, the server publishes its public IP and an epoch in an
    AEAD-encrypted DNS TXT record. The rendezvous key is embedded at compile time.
  - The Cloudflare record uses a long random subdomain. This provides obscurity,
    not an additional security boundary.
  - IPv6 is preferred when available, and QUIC uses tunnel-aware MTU settings.

- QUIC and mutual TLS 1.3
  - Both peers require an exact byte-for-byte match against an embedded DER
    certificate. There is no CA, hostname validation, expiry check or OCSP.
  - ALPN is `noob_v1`.
  - The client certificate and key are shared because every client is built from
    the same compile-time bundle.

- Enrollment and server-key pinning
  - OPAQUE registration creates the `owner` password record without storing the
    password itself.
  - The client records the server's Noise static public key and ML-KEM public key.
  - These keys are trusted on first enrollment and pinned in the client database.
  - A TLS fingerprint is also stored, but it is currently all zeroes and is not
    checked by the authentication code.

- Authenticated hybrid login
  - Noise `IK` uses X25519, ChaCha20-Poly1305 and SHA-256.
  - The pinned Noise key authenticates the server, the client's Noise key is fresh
    per login, so stable client authentication comes from mutual TLS and OPAQUE.
  - OPAQUE uses Ristretto255, 3DH, SHA-512 and Argon2 to prove password knowledge.
  - A fourth flight confirms that both sides derived the same final key.

- Hybrid session key
  - The final 32-byte key is:
    `HKDF-SHA-512(salt = Noise transcript hash, ikm = ML-KEM secret || OPAQUE session key, info = "noob:transport:final:v1")`.
  - The result rekeys Noise into separate initiator and responder keys.
  - This binds the classical Noise transcript, the post-quantum KEM and password
    authentication into one session key.

- Application data
  - Frames are serialized with `postcard`.
  - On each stream, XChaCha20-Poly1305 encrypts first, Noise encrypts that result,
    QUIC encrypts the Noise ciphertext, and WireGuard carries the QUIC packets.

## Complete architecture and data flow

```mermaid
flowchart TB
    classDef current fill:#e8f3ff,stroke:#2563eb,color:#172554,stroke-width:1.5px
    classDef crypto fill:#ecfdf5,stroke:#059669,color:#052e16,stroke-width:1.5px
    classDef store fill:#fff7ed,stroke:#ea580c,color:#431407,stroke-width:1.5px
    classDef risk fill:#fff1f2,stroke:#e11d48,color:#4c0519,stroke-width:1.5px

    subgraph CLIENT["Windows desktop — outbound only"]
        direction TB
        UI["Slint desktop UI"]:::current
        CNODE["Noob client node<br/>ephemeral UDP bind"]:::current
        CDB["Client SQLite<br/>pinned Noise + ML-KEM keys"]:::store
        CPASS["noob-secrets.txt<br/>plaintext password<br/>default: noob"]:::risk
        CCERT["Embedded client cert + key<br/>embedded pinned server cert"]:::store
        UI --> CNODE
        CDB --> CNODE
        CPASS --> CNODE
        CCERT --> CNODE
    end

    subgraph DISCOVERY["Cold-start discovery"]
        direction TB
        LOCAL["Try local server IP"]:::current
        CACHE["Try last-known home IP"]:::current
        TXT["Random DNS name<br/>TXT = AEAD(home IP + epoch)"]:::store
        VERIFY["Verify tag + freshness<br/>decrypt with rendezvous key"]:::crypto
        LOCAL -. "connection fails" .-> CACHE
        CACHE -. "cache miss / connection fails" .-> TXT
        TXT -.-> VERIFY
    end

    subgraph PUBLIC["Public network boundary"]
        direction TB
        OUTER["UDP / preferred IPv6<br/>tunnel-aware MTU"]:::current
        WG["Embedded WireGuard gatekeeper<br/>silent to unknown peers"]:::crypto
        QUIC["QUIC + mutual TLS 1.3<br/>exact DER pins · ALPN noob_v1"]:::crypto
        STREAM["One bidirectional framed stream"]:::current
        OUTER --> WG
        WG --> QUIC
        QUIC --> STREAM
    end

    subgraph SERVER["Home server — only inbound listener"]
        direction TB
        ENDPOINT["Noob server node<br/>UDP 4433"]:::current
        SCERT["Embedded server cert + key<br/>embedded pinned client cert"]:::store
        MODULES["Module router<br/>requests · responses · events"]:::current
        SDB["Server SQLite on host bind mount<br/>OPAQUE record + setup<br/>Noise/ML-KEM private keys<br/>wrapped at-rest key"]:::store
        DDNS["Detect public IP<br/>encrypt + update TXT"]:::crypto
        SCERT --> ENDPOINT
        SDB --> ENDPOINT
        ENDPOINT --> MODULES
        DDNS --> TXT
    end

    CNODE --> LOCAL
    LOCAL -. "local IP works" .-> OUTER
    CACHE -. "cached IP works" .-> OUTER
    VERIFY -.-> OUTER
    STREAM --> ENDPOINT

    subgraph AUTH["Registration once, then four-flight login"]
        direction LR
        REG["Registration<br/>OPAQUE record + server key pins<br/>+ wrapped at-rest key"]:::crypto
        F1["1 · Client → Server<br/>Noise IK: OPAQUE KE1<br/>+ ML-KEM ciphertext"]:::crypto
        F2["2 · Server → Client<br/>Noise IK: OPAQUE KE2<br/>+ wrapped at-rest key"]:::crypto
        F3["3 · Client → Server<br/>Noise transport: OPAQUE KE3<br/>+ session-wrapped at-rest key"]:::crypto
        KDF["Hybrid HKDF-SHA-512<br/>Noise transcript hash<br/>+ ML-KEM secret<br/>+ OPAQUE session key"]:::crypto
        F4["4 · Server → Client<br/>post-rekey MEOW_OK<br/>key confirmation"]:::crypto
        REG --> F1 --> F2 --> F3 --> KDF --> F4
    end

    STREAM --> REG
    SDB <--> REG
    CDB <--> REG
    F4 --> SESSION

    subgraph DATA["Authenticated session — each application message"]
        direction LR
        FRAME["Frame<br/>kind · module · request ID · payload"]:::current
        POSTCARD["postcard serialization"]:::current
        XCHACHA["XChaCha20-Poly1305<br/>random 24-byte nonce"]:::crypto
        NOISE["Rekeyed Noise transport<br/>stream ID + counter nonce"]:::crypto
        TLS["QUIC / TLS 1.3"]:::crypto
        WGWIRE["WireGuard"]:::crypto
        WIRE["UDP datagram"]:::current
        FRAME --> POSTCARD --> XCHACHA --> NOISE --> TLS
        TLS --> WGWIRE --> WIRE
    end

    SESSION["Final 32-byte session key"]:::crypto
    SESSION --> XCHACHA
    SESSION -->|"derive directional rekey keys"| NOISE
    MODULES <--> FRAME
```

## Login flights

```mermaid
sequenceDiagram
    autonumber
    participant C as Desktop client
    participant S as Home server

    Note over C,S: QUIC mutual TLS is already established
    C->>S: Noise IK flight 1: OPAQUE KE1 + ML-KEM ciphertext
    S->>C: Noise IK flight 2: OPAQUE KE2 + wrapped at-rest key
    Note over C,S: Capture Noise transcript hash and enter transport mode
    C->>S: Noise-encrypted flight 3: OPAQUE KE3 + session-wrapped at-rest key
    Note over C,S: Derive hybrid key and rekey Noise
    S->>C: Post-rekey MEOW_OK
    Note over C,S: Application frames may now flow
```