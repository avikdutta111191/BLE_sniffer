# ⚡ BLE-Sniff-&-Destroy: Protocol Analysis & Re-Pairing Vulnerabilities Matrix

This repository serves as an advanced technical reference manual for analyzing, sniffing, and auditing Bluetooth Low Energy (BLE) security implementations. It focuses on the packet-level execution of the **Pairing & Bonding** process between a Central device (such as an Android smartphone) and a Peripheral device (such as wireless earphones, using structural signatures mapped from the Sony `LE_WF-C500`). 

This documentation provides security researchers and protocol auditors with a complete blueprint of over-the-air BLE frames, layer encapsulations, and cryptographic state transitions to evaluate implementation robustness against legacy and modern vulnerability vectors.

---

## 📡 1. Over-the-Air Packet Encapsulation Architecture

Every BLE packet captured by a passive sniffer follows a multi-tiered layer structure. Before analyzing upper-layer security arguments, you must understand how these protocols pack bits into raw radio frames.

```text
+---------------------------------------------------------------------------------------+
|                                PHYSICAL LAYER CONTAINER                               |
+---------------------------------------------------------------------------------------+
|  Preamble   |   Access Address   |            PDU (Payload Data Unit)      |   CRC    |
| (1-2 Bytes) |     (4 Bytes)      |                 (2-258 Bytes)           | (3 Bytes)|
+---------------------------------------------------------------------------------------+
                                   |
                                   v
+---------------------------------------------------------------------------------------+
|                                  LINK LAYER (LL) PDU                                  |
+---------------------------------------------------------------------------------------+
|          LL Header (2 Bytes)             |               Payload Data                 |
| (LLID | NESN | SN | MD | CP | Length)    |              (0-256 Bytes)                 |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
|                                     L2CAP LAYER                                       |
+---------------------------------------------------------------------------------------+
|     L2CAP Length     |     Channel ID (CID)     |            Information              |
|      (2 Bytes)       |   (2 Bytes, e.g. 0x0006) |            (Variable)               |
+---------------------------------------------------------------------------------------+
                                                          |
                                                          v
+---------------------------------------------------------------------------------------+
|                          SECURITY MANAGER PROTOCOL (SMP) LAYER                        |
+---------------------------------------------------------------------------------------+
|      Command Opcode (1 Byte)       |             Command Specific Parameters          |
+---------------------------------------------------------------------------------------+

```

### The Layer Stack Functions

1. **Physical Layer (PHY):** Handles synchronization patterns (`Preamble`) and applies the bitmask seed (`CRC`) to evaluate channel noise or corruption.
2. **Link Layer (LL):** Directs hardware synchronization, adaptive frequency hopping, data channel routing, and hardware encryption switches (`AES-CCM`).
3. **L2CAP:** Functions as a frame demultiplexer. For security auditing, it routes raw packets using a hardcoded Channel Identifier (**CID `0x0006**`), which is reserved exclusively for the Security Manager Protocol.
4. **Security Manager Protocol (SMP):** Directs peer-to-peer security capabilities exchange, authentication procedures, and cryptographic key routing.

---

## ️ 2. Environment Setup: nRF BLE Sniffer & Wireshark Integration

To capture and visualize the live over-the-air packet structures documented below, you must interface a supported hardware development board (e.g., nRF52840 Dongle, nRF52 DK) with Wireshark using Nordic Semiconductor's sniffer firmware.

### Hardware & Prerequisites
*   **Supported Hardware:** nRF52840 Dongle (PCA10059), nRF52840 DK (PCA10056), or nRF52 DK (PCA10040).
*   **Wireshark Stable Release:** Version 3.6.x or newer installed on your system.
*   **Python Environment:** Python 3.10+ with the `pyserial` module installed (`pip install pyserial`).

### Step-by-Step Implementation

#### Step 1: Flash Sniffer Firmware
1.  Download the official **nRF Sniffer for Bluetooth LE** software zip file from Nordic Semiconductor's download portal.
2.  Extract the archive contents to a local working folder.
3.  Open the **nRF Connect for Desktop** application suite and launch the **Programmer** tool.
4.  Insert your nRF52 board into a USB port. Select your target device in the upper-left dropdown.
5.  Click **Add HEX file**, browse to the extracted folder under `hex/`, and select the firmware binary matching your specific board version (e.g., `sniffer_nrf52840dongle_nrf52840_*.hex`).
6.  Click **Erase and Write** to load the sniffer microcode into the hardware's internal flash.

#### Step 2: Install Wireshark Extcap Plugin
1.  Open Wireshark. Navigate to **Help -> About Wireshark** and select the **Folders** tab.
2.  Locate the path assigned to the **Extcap path** entry, then click the hyperlink to open that directory.
3.  Locate your extracted nRF Sniffer software archive folder and copy all items located inside the `extcap/` directory.
4.  Paste these items directly into your local Wireshark Extcap path folder. The directory should now contain files such as `nrf_sniffer_ble.py`, `nrf_sniffer_ble.bat`, and an internal `SnifferAPI/` module subfolder.

#### Step 3: Verify and Launch Live Captures
1.  Ensure your freshly flashed nRF hardware is connected to a local USB port.
2.  Relaunch Wireshark to trigger an internal plugin environment re-scan.
3.  You will see a new active hardware adapter list option on the home splash screen labeled: **nRF Sniffer for Bluetooth LE**.
4.  Double-click the nRF Sniffer row interface to initialize a passive RF monitoring session.

```text
+------------------------------------------------------------------------------------+
| Wireshark [Capture Interface Panel]                                                |
+------------------------------------------------------------------------------------+
|                                                                                    |
|  Device Name                       Traffic  Capture Filter                         |
|  --------------------------------- -------- ------------------------------------   |
|  [X] nRF Sniffer for Bluetooth LE   ~~~~~~  [                                 ]    |
|                                                                                    |
+------------------------------------------------------------------------------------+
               │
               ▼ (Double-Click to Launch Sniffer Interface UI)
+------------------------------------------------------------------------------------+
| Wireshark Sniffer Toolbar (Top View Layer)                                         |
+------------------------------------------------------------------------------------+
| Device: [79:4C:E8:54:91:E9] WF-C500 | Passkey: [      ] | Adv Hop: [37, 38, 39] [v] |
+------------------------------------------------------------------------------------+
```

Once active, a dedicated nRF Sniffer Toolbar appears below the filter text bar.

Click the **Device** dropdown menu button and choose your peripheral device target signature string (`LE_WF-C500` or its target MAC hardware marker `79:4c:e8:54:91:e9`) to instruct the sniffer hardware to lock onto that device's connection events.

---

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

## 🎯 4. Vulnerability Analysis & Attack Surface Mapping

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

## 🔒 5. Protocol Hardening & Defense Matrix

To defend against passive sniffing, offline cracking, and re-pairing exploits, implement the following security controls within your BLE stack:

1. **Enforce LE Secure Connections Only:** Disable legacy pairing modes entirely within the host profile application configuration to mitigate SAFER+ offline brute-force vectors.
2. **Implement Hardened Re-pairing Protections:** Configure device software to block unauthenticated re-pairing requests if a valid bond already exists in the local security database.
3. **Enforce Cross-Transport Key Derivation (CTKD) Checks:** Validate key distribution flags during transport switches to prevent context-switching and impersonation attacks.
4. **Require User Confirmation for Re-Bonding:** If a re-pairing event is triggered, the host application must prompt for user verification (e.g., a manual confirmation click) before updating or replacing existing security keys in non-volatile flash storage.

