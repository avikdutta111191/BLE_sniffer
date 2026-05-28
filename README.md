# ⚡ BLE-Sniff-&-Destroy: Protocol Analysis & Re-Pairing Vulnerabilities Matrix

This repository serves as an advanced technical reference manual for analyzing, sniffing, and auditing Bluetooth Low Energy (BLE) security implementations. It focuses on the packet-level execution of the **Pairing & Bonding** process between a Central device (such as an Android smartphone) and a Peripheral device (such as wireless earphones, using structural signatures mapped from the Sony `LE_WF-C500`). 

This documentation provides security researchers and protocol auditors with a complete blueprint of over-the-air BLE frames, layer encapsulations, and cryptographic state transitions to evaluate implementation robustness against legacy and modern vulnerability vectors.

---
## 🔍 1. Live Capture Inspection & Wireshark Filter Matrix

When auditing a pre-recorded protocol trace file—such as `LE_WF-CF500_pairing.pcapng` captured via the nRF Sniffer—analysts navigate multiple abstraction layers across the Bluetooth Low Energy (BLE) stack. Modern Wireshark profile definitions for the BLE dissector process link management and host layers through specialized schema maps, requiring display filters to utilize underscores (e.g., `btle.control_opcode`) instead of legacy dot syntax.

To systematically trace point-to-point interactions between the Initiator and Responder, an analyst must map static identity addresses to dynamic over-the-air indicators before isolating distinct pairing, bonding, and IP-encapsulated telemetry packets.

### Device Identification & Architecture Boundaries

* **Initiator (Smartphone) Identity Address:** `5b:3a:90:11:c2:4f` (Random Static / Public Initiator MAC)
* **Responder (Sony Earbuds LE_WF-C500):** `79:4c:e8:54:91:e9` (Public Device MAC)

During the initial over-the-air discovery sequence, these literal MAC addresses populate the headers of unencrypted advertising frames. However, the moment the smartphone initiates a connection by broadcasting a `CONNECT_IND` frame, both devices negotiate a randomized, volatile 4-byte **Data Channel Access Address** (e.g., `0x2b4c6e81`).

Following this handshake, the physical MAC boundaries are stripped from over-the-air packet headers to maximize data efficiency. To inspect subsequent link control traffic, host pairing events, attribute changes, or network layer transport headers, display filters must track this dynamic data channel session token (`btle.access_address == 0x2b4c6e81`).

---

### Protocol Analysis & Filter Mapping Matrix

The comprehensive matrix below maps every consecutive phase of the wireless connection lifecycle inside `LE_WF-CF500_pairing.pcapng` to explicit, validated Wireshark display filters, detailing the specific structural fields and metrics targeted during inspection.

| Protocol Sequence Phase | Analysis Objective | Target Protocol Layer | Validated Wireshark Display Filter Syntax | Expected Security Field Triggers, Structural Metrics & RFC 7668 Indicators |
| --- | --- | --- | --- | --- |
| **Phase 1: Discovery** | Isolate Public Advertising | Link Layer (Public Space) | `btle.access_address == 0x8e89bed6` | Targets channels 37, 38, and 39 to extract raw undirected advertisements (`ADV_IND`) emitted by the Sony earbuds. |
| **Phase 2: Connection** | Pinpoint Connection Pivot | Link Layer (Handshake) | `btle.access_address == 0x8e89bed6 && btle.control_opcode == 0x00` | Pinpoints the `CONNECT_IND` frame mapping the Phone to the Headset. Used to extract the session's dynamic Data Channel Access Address. |
| **Phase 3: Isolation** | Filter Out Background Noise | Link Layer (Session) | `btle.access_address != 0x8e89bed6` | Hides public advertisement channels to render a clean, linear conversation line of the target connection. |
| **Phase 4: Capabilities** | Audit Protocol Feature Flags | Link Layer Control | `btle.control_opcode == 0x08 || btle.control_opcode == 0x09` | Evaluates feature vectors inside `LL_FEATURE_REQ` / `RSP`. Checks if **Bit 16 (LE Secure Connections)** is active. |
| **Phase 4.1: Feature Masking** | Bitwise Feature Verification | Link Layer Control | `btle.control_opcode == 0x08 && (btle.control.features[0] & 0x10)` | Directly targets the feature array payload byte using a bitwise mask to isolate host devices declaring LE Secure Connection capability. |
| **Phase 5: Pairing** | Isolate Security Channel | L2CAP Multiplexer | `btl2cap.cid == 0x0006` | Filters out GATT and link frames to expose the host-layer Security Manager Protocol (SMP) transaction stream. |
| **Phase 5: Pairing** | Audit Security Boundaries | Security Manager (SMP) | `btsmp.opcode == 0x01 || btsmp.opcode == 0x02` | Audits `Pairing Request` and `Response` fields to isolate device I/O capabilities and authentication mandates. |
| **Phase 5: Pairing** | Extract Public Keys | Security Manager (SMP) | `btsmp.opcode == 0x0c` | Exposes the raw 64-byte over-the-air P-256 Elliptic Curve Diffie-Hellman (ECDH) public coordinates (`X` and `Y`). |
| **Phase 5: Pairing** | Track Authentication Core | Security Manager (SMP) | `btsmp.opcode == 0x03 || btsmp.opcode == 0x04` | Filters commitment hashes (`Pairing Confirm`) and nonces (`Pairing Random`) used to authenticate the link. |
| **Phase 5: Pairing** | Verify Shared Secret Math | Security Manager (SMP) | `btsmp.opcode == 0x0d` | Inspects the `Pairing DHKey Check` frames to verify if both components computed matching cryptovariables. |
| **Phase 6: Encryption** | Capture Crypto Parameters | Link Layer Control | `btle.control_opcode == 0x03` | Captures the unencrypted `LL_ENC_REQ` frame revealing the Session Master Key Diversifier (`SKDm`) and Initial Vector (`IVm`). |
| **Phase 6: Encryption** | Verify Crypto Enforcement | Link Layer Control | `btle.control_opcode == 0x05 || btle.control_opcode == 0x06` | Tracks the `LL_START_ENC_REQ` / `RSP` loop, confirming that the physical radio coprocessor has engaged AES-CCM mode. |
| **Phase 7: Bonding** | Trace Long-Term Storage | Security Manager (SMP) | `btsmp.opcode >= 0x05 && btsmp.opcode <= 0x0a` | Captures long-term identity escrow frames (`Encrypted LTK Distribution`, `Identity Resolving Key (IRK) Distribution`). |
| **Phase 8: Upper Data** | Monitor Host Attributes | Attribute Protocol (ATT) | `btatt.opcode == 0x1d` | Isolates plaintext GATT service configurations (e.g., `Execute Write Response`) to measure the exact point of ciphertext conversion. |
| **Phase 9: Network Link** | Isolate IPv6 Internet Flow | L2CAP Channel Layer | `btl2cap.cid == 0x0025` | **RFC 7668 Pivot.** Isolates the dedicated Internet Protocol Support Profile (IPSP) fixed channel routing 6LoWPAN payloads. |
| **Phase 9: Network Link** | Audit 6LoWPAN Compression | IPv6 / 6LoWPAN Header | `6lowpan` | Decodes IPv6 dispatch headers, stateless header compression states (LOWPAN_IPHC), and UDP port elisions over BLE. |

---

### Chronological Step-by-Step Packet Inspection Breakdown

#### 1. Extracting the Dynamic Data Channel Access Address & Hopping Sync

Apply the primary public discovery filter `btle.access_address == 0x8e89bed6` and scroll to the end of the initial advertising loop. Locate the `CONNECT_IND` control frame sent from the Smartphone Initiating Address to the Sony Earbud Responding Address.

Expand the **Bluetooth Low Energy Link Layer** tree in the Packet Details pane, navigate down into the **Link Layer Data** block, and isolate the runtime session parameters:

```text
Bluetooth Low Energy Link Layer
    Access Address: 0x8e89bed6 (Mandatory Public Channel Identifier)
    Data Header: 0x05 (Connect Indication PDU)
    Link Layer Data
        InitAddress: 5b:3a:90:11:c2:4f (Smartphone)
        AdvAddress: 79:4c:e8:54:91:e9 (Sony Earbuds LE_WF-C500)
        Access Address: 0x2b4c6e81  <-- DYNAMIC KEYSTONE: Copy this generated session address
        CRC Init: 0x555555
        Hop Increment: 9
        Channel Map (ChM): 0x1FFFFFFFFF (All 37 Data Channels Available)

```

##### Adaptive Frequency Hopping (AFH) Synchronization Math

To follow the connection across data channels (0–36), the nRF Sniffer instantiates its internal tracking state machine using the parameters found within this `CONNECT_IND` packet. The next hop frequency index ($f_n$) is derived deterministically from the current channel index ($f_{n-1}$) via the following core specification formula:

$$f_n = (f_{n-1} + \text{hopIncrement}) \bmod 37$$

Using our captured `hopIncrement = 9`, if the previous transaction transpired on Channel $0$, the next transmission is scheduled for Channel $9$, followed sequentially by Channel $18$, $27$, $36$, $(36+9) \bmod 37 = 8$, and so forth. If a channel index hits an unmapped frequency designated by the `Channel Map (ChM)` bitmask, it is adaptively remapped to a valid pseudo-random channel pool index.

To maintain packet tracking across these active data channels, clear your filter engine and input: `btle.access_address == 0x2b4c6e81`.

#### 2. Evaluating Cryptographic Capabilities (Secure Connections Verification)

Execute the filter `btle.control_opcode == 0x08 || btle.control_opcode == 0x09` to intercept the low-level Link Layer Feature Request and Response structures exchanged over the newly opened data link.

```text
Bluetooth Low Energy Link Layer
    Link Layer Control PDU
        Opcode: LL_FEATURE_REQ (0x08)
        Feature Set: 0x0100000000000000
            .... .... .... .... .... .... .... ...1 = LE Secure Connections: Supported

```

* **Analysis Insight:** If Bit 16 (`LE Secure Connections`) displays a value of `1` for both the smartphone and the Sony earbuds, the architecture will execute an asymmetric FIPS-compliant P-256 ECDH exchange. If either device presents a `0`, the session drops down to Legacy Pairing, exposing the link to passive offline PIN guessing and brute-force cracking.

#### 3. Inspecting Security Parameters & Unauthenticated Association Models

Apply the filter `btl2cap.cid == 0x0006` to filter out background data and reveal host-layer security transactions. Select the **Pairing Request** (`btsmp.opcode == 0x01`) frame to decode the device profile constraints negotiated by the operating system:

```text
Security Manager Protocol
    Opcode: Pairing Request (0x01)
    IO Capability: NoInputNoOutput (0x03)
    OOB Data Flag: Authentication Data Not Present (0x00)
    AuthReq: 0x2d (Bonding, MITM Protection, LE Secure Connections)
        .... ..01 = Bonding Flags: Bonding (0x01)
        .... .1.. = MITM: Set
        ...0 vanity = SC: LE Secure Connections (Set)

```

* **Analysis Insight:** Because the input/output capability bit field resolves to `0x03` (**NoInputNoOutput**) for both the smartphone and the Sony earbuds, the Security Manager engine automatically defaults to the **Just Works** unauthenticated association model. This configuration represents a core structural risk, as it lacks out-of-band validation or passkey authorization to verify link identity during the initial handshake.

#### 4. Capturing Asymmetric Public Key Elements & Cryptographic Toolbox Evaluation

Apply the filter `btsmp.opcode == 0x0c` to track the over-the-air key exchange protocol step.

```text
Security Manager Protocol
    Opcode: Pairing Public Key (0x0c)
    Long Term Key (LTK) Public Key X: e2815197b4961026040e34c9192d6199...
    Long Term Key (LTK) Public Key Y: ad8b22a07f6e0ad83949ce25ea3b12f4...

```

##### Mathematical Derivation of the Shared Cryptographic Secret

The 64-byte payload strings exposed by the filter contain the unencrypted spatial points $(X, Y)$ on the NIST P-256 elliptic curve. Let $PK_a$ represent the public key of the Smartphone, and $PK_b$ represent the public key of the Sony Earbuds. Under the hood, both devices compute the identical scalar multiplication result ($DHKey$) using their respective non-transmitted private keys ($SK_a, SK_b$):

$$\text{DHKey} = \text{Point-Multiplication}(SK_a, PK_b) = \text{Point-Multiplication}(SK_b, PK_a)$$

A passive observer monitoring the sniffer path cannot calculate the resulting $DHKey$ from the public coordinates alone, ensuring perfect forward secrecy for the session keys derived later.

#### 5. Pinpointing Verification Seeds and the AES-CCM Cutoff

Apply the filter `btsmp.opcode == 0x03 || btsmp.opcode == 0x04 || btsmp.opcode == 0x0d` to track the mathematical verification checks of Authentication Stage 1 and Stage 2:

```text
Security Manager Protocol
    Opcode: Pairing Confirm (0x03) -> Confirm Value: c4a82d91ef35...
Security Manager Protocol
    Opcode: Pairing Random (0x04)  -> Random Value: 73be10fa2d96...
Security Manager Protocol
    Opcode: Pairing DHKey Check (0x0d) -> DHKey Check Value: 89ab34cd12ef...

```

##### Security Manager Protocol Cryptographic Core Functions

The authentication phase relies on specific cryptographic toolbox utility functions outlined in the Bluetooth Core Specification:

1. **Function `f4` (Confirmation Generation):** Evaluates the commitment hashes during the exchange. It computes the over-the-air confirmation values using a specialized Advanced Encryption Standard Cipher-based Message Authentication Code engine ($\text{AES-CMAC}$):

$$\text{Confirm} = f4(PK_a, PK_b, N_a, 0)$$


2. **Function `f5` (Key Generation):** Derives the primary cryptovariables once nonces ($N_a, N_b$) are safely distributed. This function computes both the internal verification verification variable ($MacKey$) and the 128-bit Long Term Key ($LTK$):

$$\text{MacKey} \parallel \text{LTK} = f5(\text{DHKey}, N_a, N_b, \text{Address}_a, \text{Address}_b)$$


3. **Function `f6` (DHKey Check Verification):** Validates the `Pairing DHKey Check` packets (`btsmp.opcode == 0x0d`). Both endpoints execute an $\text{AES-CMAC}$ operation using the freshly minted $MacKey$ to prove possession of the shared secret:

$$E_a = \text{AES-CMAC}_{\text{MacKey}}(N_a, N_b, R, \dots)$$



If the locally generated $E_a$ matches the over-the-air payload value, the identity parameters are mathematically locked.

Immediately following this verification step, the link triggers physical hardware encryption. To locate this exact boundary, apply the filter `btle.control_opcode == 0x03`:

```text
Bluetooth Low Energy Link Layer
    Access Address: 0x2b4c6e81
    Link Layer Control PDU
        Opcode: LL_ENC_REQ (0x03)
        Random Vector (Rand): 0x73bc918e74d1a932
        Master Session Key Diversifier (SKDm): 0xab92cd01ef456789
        Master Initialization Vector (IVm): 0x12345678

```

* **The Definitive Security Check:** Monitor the sequence directly after this packet. Once `LL_START_ENC_REQ` (`0x05`) and `LL_START_ENC_RSP` (`0x06`) are exchanged, the AES-CCM hardware encryption engine engages.
* If your upper-layer Attribute Protocol packets (`btatt.opcode == 0x1d`) are **only visible before** this handshake, the link successfully transitioned to a secure state. If attribute writes or data payloads continue to display as plaintext after the encryption control frames, the encryption handshake failed, and the link is actively leaking plaintext information.

#### 6. Auditing Post-Encryption Key Distribution & Bonding

If the nRF Sniffer has been supplied with the session keys (or the link remains unencrypted during a testing capture), apply the filter `btsmp.opcode >= 0x05 && btsmp.opcode <= 0x0a` to observe the **Bonding Phase**.

```text
Security Manager Protocol
    Opcode: Encrypted Master Identification (0x07)
    Opcode: Identity Information (0x08) -> Identity Resolving Key (IRK): 4f8a92...
    Opcode: Identity Address Information (0x09) -> Public DB MAC: 79:4c:e8:54:91:e9

```

* **Analysis Insight:** During this phase, the devices securely exchange long-term keys (LTK) along with the Identity Resolving Key (IRK). This distribution enables the Sony earbuds to resolve the smartphone's randomized private address on future connection attempts, allowing for seamless, secure auto-reconnections.

#### 7. Deconstructing RFC 7668 IPv6 over BLE (6LoWPAN) Low-Power Telemetry

When the Sony earbuds register as an internet-connected smart node via the Internet Protocol Support Profile (IPSP), they initialize a dedicated L2CAP transport layer. Apply the filter `btl2cap.cid == 0x0025` to isolate this specialized IPv6 channel, bypassing generic GATT or pairing traffic.

To analyze the structural encapsulation mechanisms defined under **RFC 7668**, clear the filter bar and input `6lowpan`. This exposes the optimized network datagram layer:

```text
6LoWPAN (IPv6 over Bluetooth Low Energy)
    6LoWPAN Dispatch Header: IP HC Compression (0x60)
    IPv6 Header type: LOWPAN_IPHC Compressed Header
        011. .... = TF: Traffic Class and Flow Label are elided
        ...0 1... = NH: Next Header is Compressed (UDP / Next Header Engine)
        .... ..00 = HLIM: Hop Limit field is carried in-line (64)
        SAM / DAM: Stateless Address Autoconfiguration (SLAAC) Enabled
    Source Interface Identifier: Derived via RFC 7668 64-bit Bluetooth Link-Layer Address
        [Derived Address: fe80::5b3a:90ff:fe11:c24f]
    Destination Interface Identifier: Derived via Sony EUI-64 Mapping
        [Derived Address: fe80::794c:e8ff:fe54:91e9]

```

* **Analysis Insight (RFC 7668 Structural Audit):** Because BLE packet data units (PDUs) enforce strict payload limits, standard 40-byte IPv6 headers introduce excessive over-the-air overhead. RFC 7668 resolves this by applying **LOWPAN_IPHC** compression.
* By auditing the header flags, you can verify that the Traffic Class, Flow Label, and 128-bit prefix identifiers have been stripped (**elided**) from transmission.

##### Critical RFC 7668 Addressing Metric: The No-Bit-Flipping Rule

Unlike conventional IPv6 over Ethernet topologies (defined in RFC 2464) which dictate flipping the 7th bit (Universal/Local bit) of the MAC address during Modified EUI-64 creation, **RFC 7668 explicitly forbids altering any bits of the link identifier.** The 64-bit Interface Identifier (IID) is formed exclusively by splitting the 48-bit Bluetooth device MAC directly in half and injecting the `0xFFFE` padding array into the central boundary, copying all bits verbatim.

* **Sony Earbuds IPv6 Construction:** Public MAC `79:4c:e8:54:91:e9` maps exactly to IID `794c:e8ff:fe54:91e9`, yielding a full Link-Local IPv6 endpoint of `fe80::794c:e8ff:fe54:91e9`.
* **Smartphone IPv6 Construction:** Static Random MAC `5b:3a:90:11:c2:4f` maps exactly to IID `5b3a:90ff:fe11:c24f`, yielding a full Link-Local IPv6 endpoint of `fe80::5b3a:90ff:fe11:c24f`.

---

### Production-Grade Wireshark Diagnostics & Edge-Case Troubleshooting

#### Scenario A: Handling L2CAP Fragmentation & ATT MTU Overruns

When auditing extensive upper-layer data exchanges—such as large GATT attribute reads or firmware updates over 6LoWPAN—the Maximum Transmission Unit (MTU) negotiated at the host layer frequently surpasses the physical Link Layer Data Packet Length (typically 27 bytes on legacy BLE hardware, up to 251 bytes on LE Data Length Extension devices).

When this occurs, the L2CAP multiplexer splits the transmission across multiple consecutive Link Layer connection packets.

##### Diagnostic Indicators

If you apply a high-level filter like `btatt` or `6lowpan` and notice that critical payload sequences appear missing or display dissection errors, inspect the low-level L2CAP flags. The initial fragment carries an L2CAP header with an embedded length argument, while subsequent fragments contain raw trailing data frames without intermediate protocol headers.

##### Resolution Path via Wireshark Display Rules

To verify that the packet analyzer is accurately reconstructing these multi-segment streams, verify that the L2CAP protocol reassembly parameters are active inside the Wireshark preferences stack. You can target intermediate fragments directly by filtering for the L2CAP Start and Continuation boundary definitions:

```text
# Isolate the initial L2CAP PDU fragment frame containing the length header
btle.data_header.llid == 0x02

# Isolate all subsequent continuation fragments carrying segmented host data
btle.data_header.llid == 0x01

```

To view only completely assembled transaction nodes, use the compound expression:
`btl2cap.payload and not btl2cap.fragment`

#### Scenario B: Resolving Sniffer Decryption De-synchronization

A common point of failure when collecting traces via hardware sniffers is the random drop of critical link control packets due to physical interference or antenna constraints. If the sniffer hardware fails to capture the exact over-the-air frame containing the `LL_ENC_REQ` control payload or the subsequent `LL_START_ENC_RSP` handshake loop, Wireshark's internal cryptographic engine cannot synchronize its state parameters.

##### Diagnostic Indicators

Directly after the pairing sequence, all subsequent packets on the data channel display as generic, unparsed "Encrypted LE Data" payloads, and upper-layer filters like `btatt`, `btsmp`, or `6lowpan` return completely blank fields.

##### Resolution Path & Manual Key Injection

When the sniffer misses the initial dynamic key derivation exchange, you can restore full protocol visibility by manually providing the Long-Term Key ($LTK$) directly to the Wireshark dissector engine:

1. Navigate to the top menu bar and select **Edit** $\rightarrow$ **Preferences**.
2. Expand the **Protocols** dropdown list in the left-hand configuration panel and scroll down to select **Bluetooth SM (Security Manager)**.
3. Locate the **Key Management Table** field and click the **Edit...** button.
4. Click the **+** icon to append a new cryptographic mapping rule.
5. In the fields provided, enter the Responder's explicit physical identity coordinates:
* **BD Address:** `79:4c:e8:54:91:e9`
* **Address Type:** `Public` (or `Random` if targeting the Smartphone node)
* **Key Type:** `Long Term Key (LTK)`
* **Value:** *[Input the 32-character hexadecimal key array extracted from your device's debug logs or peripheral memory dump]*



Click **OK** to save the entry and apply the new configuration. The Wireshark dissector will perform a retrospective parsing pass over the pcapng file, matching the stored crypto parameters against the capture stream to decode the encrypted blocks and expose the underlying data payloads.
## 📑 3. Chronological Protocol Sequence & Packet Structures

To audit or intercept a BLE session, you must track its progression through five structural phases. Below is the exact packet-level lifecycle of a connection transitioning into an encrypted, bonded state.

### Phase 1: Advertising & Data Link Establishment

Operating under the fixed global access address `0x8E89BED6` across the primary advertising channels (37, 38, 39).

```text
Peripheral (Earbuds)                                         Central (Android Host)
         |                                                             |
         | -------- 1. ADV_IND (Connectable Advertisement) ---------> |
         | <------- 2. CONNECT_IND (Connection Request Request) ------ |

```

#### Packet 1: `ADV_IND` (Advertising Indication)

* **Access Address:** `0x8E89BED6`
* **LL Header (2 Bytes):**
* `PDU Type` (4 bits): `0000b` (Connectable Undirected Advertising)
* `ChSel` (1 bit): Channel Selection algorithm preference.
* `TxAdd` (1 bit): `1` (Indicates the target MAC address uses a Random/Private structure).
* `Length` (8 bits): Size of the payload (typically 6 bytes for address + variable advertisement structures).


* **Payload Structure:**
* `AdvA` (6 Bytes): The transmitter hardware MAC identity (e.g., `79:4c:e8:54:91:e9`).
* `AdvData` (Variable): Grouped into standard Length-Type-Value (LTV) structures. For example:
* `0x0B` (Length) | `0x09` (Type: Complete Local Name) | `LE_WF-C500` (ASCII Data Payload).





#### Packet 2: `CONNECT_IND` (Connection Indication)

Sent by the Central device to instantly establish a dedicated point-to-point data channel.

* **LL Header (2 Bytes):** `PDU Type` set to `0101b` (Connection Request).
* **Payload Structure (34 Bytes):**
* `InitA` (6 Bytes): The initiator phone's local MAC identity.
* `AdvA` (6 Bytes): The targeted peripheral's MAC identity (`79:4c:e8:54:91:e9`).
* `LLData` (22 Bytes - Operational Channel Parameters):
* `Access Address` (4 Bytes): A unique, randomly generated 32-bit signature token (e.g., `0x1A2B3C4D`). Every future packet in this session must lead with this address.
* `CRC Init` (3 Bytes): Parity checksum generation seed.
* `WinSize / WinOffset` (2 Bytes): Frame transmission timing offsets.
* `Interval` (2 Bytes): Sets the physical transaction cycle speed ($\text{Value} \times 1.25\text{ ms}$).
* `Latency` (2 Bytes): Slave latency allowance (how many empty connection cycles the peripheral can ignore to conserve power).
* `Timeout` (2 Bytes): Connection supervision timeout ($\text{Value} \times 10\text{ ms}$). Max link silence allowed before the session drops.
* `ChM` (5 Bytes / 40 bits): A precise bitmask mapping clean vs noisy data channels (0–36).
* `Hop Increment` (5 bits): Random value scalar (1–16) fed to the hopping formula to change data channel frequencies on every single packet event.





---

### Phase 2: Link Layer Control Exchange

The connection moves to the data channels (0-36). Packets are marked with `LLID = 11b` (Link Layer Control PDU).

```text
Peripheral (Earbuds)                                         Central (Android Host)
         |                                                             |
         | <------- 3. LL_FEATURE_REQ (Negotiate Feature Flags) ------ |
         | -------- 4. LL_FEATURE_RSP (Confirm Secure Connections) --> |
         | <------- 5. LL_LENGTH_REQ (Negotiate Payload Limits) ----- |
         | -------- 6. LL_LENGTH_RSP (Confirm Maximum MTU Size) ------|

```

#### Packet 3 & 4: `LL_FEATURE_REQ` / `LL_FEATURE_RSP`

Negotiates baseline hardware operational profiles.

* **Control Payload:**
* `Opcode` (1 Byte): `0x08` (Request) / `0x09` (Response).
* `Feature Set Bitmask` (8 Bytes): Evaluates low-level feature options. The following bits must be active (`1`) to execute authenticated modern pairing:
* `Bit 0`: LE Encryption
* `Bit 8`: LE Data Packet Length Extension
* `Bit 16`: LE Secure Connections (Enables modern ECDH routines over legacy pairing)





#### Packet 5 & 6: `LL_LENGTH_REQ` / `LL_LENGTH_RSP`

Sets the processing payload ceiling for raw transmission frames.

* **Control Payload:**
* `Opcode` (1 Byte): `0x14` (Request) / `0x15` (Response).
* `Payload Size Parameters` (8 Bytes total):
* `MaxTxOctets` (2 Bytes) & `MaxTxTime` (2 Bytes)
* `MaxRxOctets` (2 Bytes) & `MaxRxTime` (2 Bytes)





---

### Phase 3: Cryptographic Pairing Exchange (SMP Layer)

The processing state transitions to the Host stack. The Link Layer header sets `LLID = 10b` (Start of L2CAP message) and routes data over L2CAP Fixed Channel ID `0x0006` (Security Manager Protocol).

```text
Peripheral (Earbuds)                                         Central (Android Host)
         |                                                             |
         | <------- 7. SMP_Pairing_Request (Declare Capabilities) ----- |
         | -------- 8. SMP_Pairing_Response (Acknowledge Bonding) ----> |
         | <------- 9. SMP_Pairing_Public_Key (ECDH Key Exchange) ---- |
         | -------- 10. SMP_Pairing_Public_Key (ECDH Key Exchange) ---> |
         | <------- 11. SMP_Pairing_Confirm (Commit Hash) ------------ |
         | -------- 12. SMP_Pairing_Confirm (Commit Hash) -----------> |
         | <------- 13. SMP_Pairing_Random (Nonce Value Reveal) ------ |
         | -------- 14. SMP_Pairing_Random (Nonce Value Reveal) ------>|
         | <------- 15. SMP_Pairing_DHKey_Check (Key Validation) ----- |
         | -------- 16. SMP_Pairing_DHKey_Check (Key Validation) ----> |

```

#### Packet 7 & 8: `SMP_Pairing_Request` / `SMP_Pairing_Response`

Maps the security boundaries, capability rules, and pairing models for the session.

```text
+-----------------------------------------------------------------------+
|  SMP Opcode  | IO Capability | OOB Data Flag | AuthReq (Auth Options) |
|   (1 Byte)   |   (1 Byte)    |   (1 Byte)    |       (1 Byte)         |
+-----------------------------------------------------------------------+
| Max Key Size |  Initiator Key Dist Mask      | Responder Key Dist Mask|
|   (1 Byte)   |         (1 Byte)              |        (1 Byte)        |
+-----------------------------------------------------------------------+

```

* **Field Specifications:**
* `SMP Opcode` (1 Byte): `0x01` (Pairing Request) / `0x02` (Pairing Response).
* `IO Capability` (1 Byte):
* `0x00` (Display Only) | `0x01` (Display Yes/No) | `0x02` (Keyboard Only) | `0x04` (Keyboard Display)
* `0x03` (**No Input No Output**): Standard for compact devices like the `LE_WF-C500`. If both endpoints advertise `0x03`, the protocol bypasses passkeys and switches to the **Just Works** model.


* `OOB Data Flag` (1 Byte): `0x00` (Out-Of-Band mechanisms like NFC are inactive).
* `AuthReq` (1 Byte Authentication Requirements Bitmask):
* `Bits 0-1 (Bonding Flags)`: Set to `01b` (**Bonding Active**). Instructs both components to write generated key payloads to non-volatile flash memory.
* `Bit 2 (MITM)`: Man-in-the-Middle protection request flag.
* `Bit 3 (SC)`: Set to `1` (**LE Secure Connections**). Dictates the use of FIPS-compliant ECDH pairing routines rather than legacy structures.


* `Max Encryption Key Size` (1 Byte): Set to `0x10` (Enforces full 16-Byte/128-bit key parameters).
* `Key Distribution Masks` (1 Byte Each): Bit flags indicating which operational keys will be transferred over L2CAP during Phase 5 (`EncKey` for LTK, `IdKey` for IRK, `SignKey` for CSRK).



#### Packet 9 & 10: `SMP_Pairing_Public_Key`

Exchanges the public cryptographic coordinates required to compute a shared secret without transmitting it over the air.

* **SMP Opcode:** `0x0C`
* **Payload (64 Bytes):** Contains the 32-Byte Public X coordinate and 32-Byte Public Y coordinate generated using the NIST P-256 elliptic curve model.

#### Packet 11 & 12: `SMP_Pairing_Confirm`

Acts as a cryptographic commitment to bind the exchanged information.

* **SMP Opcode:** `0x03`
* **Payload (16 Bytes):** A local verification hash value computed using the public coordinates, generated nonces, and MAC addresses.

#### Packet 13 & 14: `SMP_Pairing_Random`

Reveals the secret generation nonces to validate the handshake's cryptographic integrity.

* **SMP Opcode:** `0x04`
* **Payload (16 Bytes):** The raw pseudo-random seed string used to construct the earlier `Pairing_Confirm` block. Exchanging this value allows both devices to verify that the session has not been intercepted.

#### Packet 15 & 16: `SMP_Pairing_DHKey_Check`

Verifies that both nodes have successfully calculated the identical Diffie-Hellman secret key.

* **SMP Opcode:** `0x0D`
* **Payload (16 Bytes):** A checking token compiled by hashing the derived Long-Term Key (LTK) alongside session variables.

---

### Phase 4: Link Encryption Activation

The devices return to the Link Layer to initialize hardware-level encryption. Packets are marked with `LLID = 11b` (Link Layer Control PDU).

```text
Peripheral (Earbuds)                                         Central (Android Host)
         |                                                             |
         | <------- 17. LL_ENC_REQ (Provide Session Seeds) ------------ |
         | -------- 18. LL_ENC_RSP (Acknowledge Seeds) ---------------> |
         | <------- 19. LL_START_ENC_REQ (Acknowledge HW Crypto Mode) - |
         | -------- 20. LL_START_ENC_RSP (Confirm Handshake Output) ---> |
         | <------- 21. LL_START_ENC_RSP (Hardware Interlock Complete) |
         X                                                             X
  =====================================================================================
  ==  CRITICAL CUTOFF: EVERY PACKET BEYOND THIS POINT IS FULLY ENCRYPTED VIA AES-CCM  ==
  =====================================================================================

```

#### Packet 17: `LL_ENC_REQ`

* **Opcode:** `0x03`
* **Payload Data (22 Bytes):**
* `Rand` (8 Bytes): A completely random salt string.
* `EDIV` (2 Bytes): Encrypted Diversifier payload.
* `SKDm` (8 Bytes): The Initiator's half of the Master Session Key Diversifier string.
* `IVm` (4 Bytes): The Initiator's half of the Master Initialization Vector.



#### Packet 18: `LL_ENC_RSP`

* **Opcode:** `0x04`
* **Payload Data (12 Bytes):**
* `SKDs` (8 Bytes): The Peripheral's half of the Slave Session Key Diversifier string.
* `IVs` (4 Bytes): The Peripheral's half of the Slave Initialization Vector.



*Both physical radio chipsets merge `SKDm + SKDs` with the generated `LTK` to yield the live, operational session key.*

#### Packet 19, 20 & 21: `LL_START_ENC_REQ` / `LL_START_ENC_RSP`

* **Opcodes:** `0x05` and `0x06`
* These frames contain zero data payloads. They serve as mechanical acknowledgments indicating that the internal hardware engines have successfully loaded the session key into their active AES-CCM crypto coprocessors.

---

### Phase 5: Persistent Bonding Key Distribution

Executed entirely within the encrypted AES-CCM link container. These packets are hidden from passive sniffers unless the session's parent keys are provided to the analysis tool.

```bash
Peripheral (Earbuds)                                         Central (Android Host)
         |                                                                      |
         | <------- 22. SMP_Identity_Information (Share Central IRK) ---------- |
         | <------- 23. SMP_Identity_Address_Info (Share Static MAC) ---------- |
         | -------- 24. SMP_Identity_Information (Share Slave IRK) -----------> |
         | -------- 25. SMP_Identity_Address_Info (Share Static MAC) ---------> |

```

#### Packet 22 & 24: `SMP_Identity_Information`

* **Opcode:** `0x08`
* **Payload (16 Bytes):** Contains the **Identity Resolving Key (IRK)**.
* *Protocol Purpose:* Operating systems change their over-the-air MAC addresses every few minutes to mitigate location tracking. Storing the IRK in non-volatile flash memory allows the bonded peripheral to cryptographicly resolve future randomized private addresses back to the single trusted device identity.

#### Packet 23 & 25: `SMP_Identity_Address_Info`

* **Opcode:** `0x09`
* **Payload (7 Bytes):** Contains the true, static, un-randomized public hardware MAC address of the device, identifying the root owner of the accompanying IRK token.

---

## 🎯 3. Vulnerability Analysis & Attack Surface Mapping

Analyzing the bitfields and packet sequences exposed during these transactions reveals the primary architectural entry points leveraged during security evaluations.

### 1. Legacy Pairing PIN Cracking (Offline Exhaustion)

When auditing legacy pairing mechanisms that rely on small PIN configurations, capturing the initialization sequence can lead to a complete compromise of link security.

```text
[ Intercepted Phase 2 Telemetry Elements ]
  ├── IN_RAND (16 Bytes)
  ├── Confirm Hash (16 Bytes)
  └── BD_ADDR (6 Bytes)
        │
        ▼
[ Offline Brute-Force Routine Loop ]
  For PIN_Guess = 0000 to 9999:
    │
    ├── Compute K_init = SAFER+_E22(PIN_Guess, IN_RAND, BD_ADDR)
    ├── Compute Confirm_Check = SAFER+_E21(K_init, Nonce_Values)
    │
    └── Check: If (Confirm_Check == Intercepted Confirm Hash) ->
          └── SUCCESS: PIN Cracked, Extract LTK, Decrypt Session.

```

* **Vulnerability Vector:** Legacy pairing constructs the initialization key ($K_{init}$) using the custom **SAFER+** block cipher function ($E_{22}$). The security of this phase relies entirely on the key space entropy of the PIN.
* **Exploit Impact:** A passive observer who intercepts `IN_RAND` and the `Confirm Hash` can run an offline brute-force loop through the SAFER+ block cipher. Because a standard 4-digit PIN yields only 10,000 possible permutations, modern computing architectures can crack the PIN code in less than **0.06 seconds**, deriving the parent session key and exposing the entire data link.

### 2. BLERP: BLE Re-Pairing Design Flaws (Core Specification v6.1)

The Bluetooth Core Specification permits paired devices to renegotiate long-term keys via *re-pairing* to adjust security levels. However, structural flaws in how this state machine operates introduce critical vulnerabilities.

| Vulnerability Vector Name | Technical Vulnerability Signature Description |
| --- | --- |
| **Unauthenticated Re-pairing Request** | A paired node accepts an incoming unauthenticated pairing request over an active link, overwriting its existing valid keys with an attacker's parameters. |
| **Security Level Downgrade** | A host accepts an unauthenticated, unencrypted re-pairing process that overrides an existing authenticated long-term connection bond. |
| **Session Establishment Interception** | An adversary injects link-layer terminate instructions to interrupt normal session establishment, forcing the target nodes into a re-pairing fallback mode. |
| **Re-pairing Entropy Downgrade** | An injection vector during key renegotiation that forces the maximum encryption key size down to its lowest allowable value (7 bytes), simplifying offline brute-force attacks. |

#### Exploit Impact

* **0-Click Impersonation:** Attackers can bypass standard pairing prompts to spoof trusted hosts or peripherals, gaining unauthorized control or access to data streams without requiring manual user interaction.
* **Man-in-the-Middle (MitM) Injections:** By combining session disruption with security level downgrades, an adversary can position themselves between an Android host and a target wireless headset, allowing them to intercept or inject arbitrary audio data and control commands.

---

## 🔒 6. Protocol Hardening & Defense Matrix

To defend against passive sniffing, offline cracking, and re-pairing exploits, implement the following security controls within your BLE stack:

1. **Enforce LE Secure Connections Only:** Disable legacy pairing modes entirely within the host profile application configuration to mitigate SAFER+ offline brute-force vectors.
2. **Implement Hardened Re-pairing Protections:** Configure device software to block unauthenticated re-pairing requests if a valid bond already exists in the local security database.
3. **Enforce Cross-Transport Key Derivation (CTKD) Checks:** Validate key distribution flags during transport switches to prevent context-switching and impersonation attacks.
4. **Require User Confirmation for Re-Bonding:** If a re-pairing event is triggered, the host application must prompt for user verification (e.g., a manual confirmation click) before updating or replacing existing security keys in non-volatile flash storage.

"
