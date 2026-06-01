# KARTHIK ITHIKASH G
# THREE-WAY-HANDSHAKE-PROTOCOL
## 1. Abstract
The Transmission Control Protocol (TCP) three-way handshake is a fundamental process that establishes a reliable, connection-oriented communication session between two networked devices before any actual data exchange begins. This report provides an in-depth analysis of the TCP three-way handshake mechanism, examining its theoretical foundations, step-by-step operational sequence, flag structures, timing considerations, security implications, and practical behavior observed through Cisco Packet Tracer network simulation software.
The simulation results presented in this report demonstrate the packet flow between a PC client (PC0) and a server (Server0), visually confirming the SYN, SYN-ACK, and ACK phases of the handshake process. By understanding this protocol, network engineers and students can better design, troubleshoot, and secure modern TCP/IP networks.

## 2. Introduction
In the landscape of modern networking, reliable data communication between devices is a cornerstone of the digital ecosystem. The Internet and virtually all enterprise networks rely on the Transmission Control Protocol/Internet Protocol (TCP/IP) suite for transporting data between systems. Within this suite, TCP provides a connection-oriented, reliable, full-duplex communication channel between endpoints.

Before any data transfer can occur over a TCP connection, the two communicating parties must agree to establish a connection through a process known as the three-way handshake (also called the TCP handshake or SYN-SYN/ACK-ACK handshake). This mechanism ensures that both the client and server are ready to communicate, synchronizes their initial sequence numbers, and negotiates certain connection parameters. The three-way handshake gets its name from the three distinct message exchanges required to establish a connection: the client sends a SYN (synchronize) segment, the server responds with a SYN-ACK (synchronize-acknowledge) segment, and finally the client acknowledges with an ACK segment. Only after these three steps is the connection considered established and data transfer permitted.

### 2.1 Objectives
* To understand the theoretical foundation of the TCP three-way handshake protocol.
* To examine the structure of TCP segment flags used during connection establishment.
* To analyze each phase of the handshake process in detail.
* To validate the handshake behavior through Cisco Packet Tracer simulation.
* To explore the security considerations and real-world applications of the protocol.

### 2.2 Scope
This report covers TCP connection establishment (three-way handshake), TCP header flag analysis, connection termination (four-way FIN), common issues and attacks targeting the handshake, and simulation evidence using Cisco Packet Tracer. IPv4-based TCP communication is the primary focus, with references to IPv6 where relevant.

---

## 3. Background and Theoretical Foundation

### 3.1 The OSI and TCP/IP Models
TCP operates at the Transport Layer (Layer 4) of the OSI model and within the Transport layer of the TCP/IP model. Its purpose is to provide processes with reliable, ordered, and error-checked delivery of a stream of bytes. TCP works in tandem with IP (Internet Protocol), which handles addressing and routing at the Network Layer (Layer 3).

### 3.2 TCP vs. UDP
The Transport layer offers two primary protocols: TCP and UDP (User Datagram Protocol). While UDP is connectionless and faster, it offers no guarantees of delivery, ordering, or error correction. TCP, by contrast, uses mechanisms like the three-way handshake, sequence numbers, acknowledgments, and flow control to ensure reliability.

| Feature | TCP | UDP |
| :--- | :--- | :--- |
| **Connection** | Connection-oriented | Connectionless |
| **Reliability** | Guaranteed delivery | No guarantee |
| **Ordering** | Ordered delivery | No ordering |
| **Speed** | Slower (overhead) | Faster (minimal overhead) |
| **Use Cases** | HTTP, FTP, SMTP, SSH | DNS, Video streaming, VoIP |

*Table 1: Comparison of TCP and UDP protocols*

### 3.3 TCP Segment Structure
A TCP segment consists of a header (minimum 20 bytes) and a data payload. The header contains critical fields used during the three-way handshake:
* **Source Port (16 bits):** Port number of the sending application.
* **Destination Port (16 bits):** Port number of the receiving application.
* **Sequence Number (32 bits):** Identifies the byte in the stream from the sender.
* **Acknowledgment Number (32 bits):** The next expected byte from the other side.
* **Data Offset (4 bits):** Size of the TCP header in 32-bit words.
* **Control Flags (6 bits):** URG, ACK, PSH, RST, SYN, FIN - critical for handshake.
* **Window Size (16 bits):** Receiver's advertised buffer size for flow control.
* **Checksum (16 bits):** Error-detection field.
* **Urgent Pointer (16 bits):** Points to urgent data when URG flag is set.

---

## 4. TCP Control Flags
TCP control flags are single-bit fields within the TCP header that control the state and behavior of the connection. The six standard flags are particularly important for understanding the three-way handshake:

| Flag | Bit Value | Description |
| :--- | :--- | :--- |
| **SYN** | `0x002` | Synchronize sequence numbers. Used to initiate a connection. |
| **ACK** | `0x010` | Acknowledgment field is significant. Confirms receipt of data. |
| **FIN** | `0x001` | Finish. Indicates the sender has finished sending data. |
| **RST** | `0x004` | Reset the connection. Used to abort a connection. |
| **PSH** | `0x008` | Push function. Instructs receiver to push data to application layer. |
| **URG** | `0x020` | Urgent pointer field is significant. |

*Table 2: TCP Control Flags and their functions*

During the three-way handshake, only SYN and ACK flags are relevant. The SYN flag signals a connection request and synchronizes sequence numbers. The ACK flag confirms that a segment has been received. The combination SYN+ACK is used in the server's response to the initial connection request.

---

## 5. The Three-Way Handshake Process
The TCP three-way handshake is the procedure by which two TCP entities agree to establish a connection. It involves exactly three message exchanges, each with a specific purpose. The following sections describe each step in detail.

### 5.1 Step 1: SYN (Synchronize)
The connection initiation begins with the client sending a TCP segment with the SYN flag set to 1. This segment carries no application data but includes a randomly generated Initial Sequence Number (ISN), denoted as `x`. The client enters the `SYN_SENT` state after transmitting this segment.
* **SYN Flag:** Set to 1
* **ACK Flag:** Set to 0
* **Sequence Number:** `x` (randomly chosen Initial Sequence Number)
* **Acknowledgment Number:** 0 (not valid since ACK=0)
* **Client State after sending:** `SYN_SENT`

The random ISN is chosen to prevent collisions with previous connections and to provide a basic level of security against certain TCP hijacking attacks. Modern operating systems use a cryptographically secure random number generator for ISN selection.

### 5.2 Step 2: SYN-ACK (Synchronize-Acknowledge)
Upon receiving the SYN segment, the server responds with a segment that has both the SYN and ACK flags set. This serves a dual purpose: it acknowledges the client's SYN, and it sends the server's own ISN (`y`) to the client for synchronization in the reverse direction.
* **SYN Flag:** Set to 1
* **ACK Flag:** Set to 1
* **Sequence Number:** `y` (server's randomly chosen ISN)
* **Acknowledgment Number:** `x+1` (acknowledges client's ISN)
* **Server State:** Transitions from `LISTEN` to `SYN_RECEIVED`

The acknowledgment number `x+1` means the server has received all bytes up to sequence number `x` and is expecting byte `x+1` next. The server allocates resources and a Transmission Control Block (TCB) at this stage.

### 5.3 Step 3: ACK (Acknowledge)
The client receives the SYN-ACK and responds with a final ACK segment. This segment acknowledges the server's SYN and completes the three-way handshake. After sending this, the client enters the `ESTABLISHED` state.
* **SYN Flag:** Set to 0
* **ACK Flag:** Set to 1
* **Sequence Number:** `x+1` (client's next sequence number)
* **Acknowledgment Number:** `y+1` (acknowledges server's ISN)
* **Client State:** `ESTABLISHED`
* **Server State (upon receipt):** `ESTABLISHED`

Once both sides are in the `ESTABLISHED` state, bidirectional data transfer can begin. The sequence numbers established during the handshake are used for all subsequent data exchange, ensuring ordered and reliable delivery.

### 5.4 TCP State Diagram During Handshake
The TCP protocol is implemented as a finite state machine. The following table summarizes the state transitions for both the client and server during the three-way handshake:

| Step | Action | Client State | Server State |
| :--- | :--- | :--- | :--- |
| **0 (Initial)** | Idle | CLOSED | LISTEN |
| **1** | Client sends SYN | SYN_SENT | LISTEN |
| **2** | Server sends SYN-ACK | SYN_SENT | SYN_RECEIVED |
| **3** | Client sends ACK | ESTABLISHED | SYN_RECEIVED |
| **4 (Final)** | Server receives ACK | ESTABLISHED | ESTABLISHED |

*Table 3: TCP State transitions during the three-way handshake*

### 5.5 Sequence Number Exchange Diagram
The following ASCII-style representation illustrates the exchange of sequence and acknowledgment numbers across the three steps of the handshake:


CLIENT                         SERVER
|                                |
|----[SYN, Seq=x]------------->|
|                                |
|<---[SYN+ACK, Seq=y, Ack=x+1]-|
|                                |
|----[ACK, Seq=x+1, Ack=y+1]-->|
|                                |
|  *** CONNECTION ESTABLISHED *** |


## 6. Cisco Packet Tracer Simulation

### 6.1 Simulation Overview

To validate the theoretical concepts of TCP connection establishment, a network simulation was created using Cisco Packet Tracer. The simulation consists of:

* **Client:** PC0
* **Server:** Server0
* **Protocol:** TCP/IP
* **Tool:** Cisco Packet Tracer (Simulation Mode)

Packet Tracer's Simulation Mode was used to capture and inspect Protocol Data Units (PDUs) during the TCP three-way handshake process.

---

### 6.2 Simulation Topology

| Component     | Description         |
| ------------- | ------------------- |
| Client Device | PC-PT (PC0)         |
| Server Device | Server-PT (Server0) |
| Connection    | Direct Link         |
| Protocol      | TCP/IP              |
| Tool Used     | Cisco Packet Tracer |

---

### 6.3 Simulation Result 1: SYN Phase

**Figure 2:** TCP SYN Packet in Transit

* Client PC0 initiates communication.
* SYN packet is sent to Server0.
* Packet envelope icons represent PDUs in transit.
* Green indicators confirm active packet transmission.

#### Observation

The client enters the **SYN_SENT** state after transmitting the SYN packet.

The server receives the SYN packet and transitions from:


LISTEN → SYN_RECEIVED


---

### 6.4 Simulation Result 2: ACK Phase

**Figure 3:** TCP Connection Established

* Server sends a SYN-ACK response.
* Client sends the final ACK.
* Bidirectional packet exchange is visible.
* Connection establishment is confirmed.

#### Observation

Both devices transition into:

```text
ESTABLISHED
```

Data transfer can now begin.

---

### 6.5 Simulation Interpretation

#### Frame 1

```text
Client → SYN → Server
```

Represents Step 1 of the handshake.

#### Frame 2

```text
Server → SYN-ACK → Client
Client → ACK → Server
```

Represents Steps 2 and 3 of the handshake.

The simulation validates the theoretical TCP connection establishment process.

---

# 7. TCP Connection Termination

TCP uses a **Four-Way Handshake** to terminate a connection.

## 7.1 Four-Way FIN Process

### Step 1: FIN

The initiator sends a FIN segment.

```text
State: FIN_WAIT_1
```

### Step 2: ACK

Receiver acknowledges the FIN.

```text
Initiator → FIN_WAIT_2
Receiver → CLOSE_WAIT
```

### Step 3: FIN

Receiver sends its own FIN.

```text
State: LAST_ACK
```

### Step 4: ACK

Initiator sends the final ACK.

```text
State: TIME_WAIT → CLOSED
```

---

# 8. Security Considerations

## 8.1 SYN Flood Attack

A SYN flood attack sends numerous SYN requests with spoofed addresses.

Result:

* Half-open connections accumulate.
* Server resources become exhausted.
* Legitimate clients are denied service.

---

## 8.2 SYN Cookies

SYN Cookies prevent resource allocation until the final ACK is received.

Benefits:

* Protects against SYN flood attacks.
* Eliminates resource consumption from half-open connections.

---

## 8.3 TCP Session Hijacking

Attackers may attempt to inject packets by predicting TCP sequence numbers.

Modern defenses include:

* Randomized Initial Sequence Numbers (ISN)
* TCP MD5 Signatures
* Stronger cryptographic protections

---

## 8.4 Security Best Practices

* Enable SYN Cookies
* Configure Firewalls
* Deploy IDS/IPS Solutions
* Use DDoS Protection
* Implement TLS/SSL Encryption

---

# 9. Real-World Applications

## 9.1 HTTP / HTTPS

TCP establishes the connection before web requests are exchanged.

Applications:

* Web Browsing
* REST APIs
* Secure Web Services

---

## 9.2 FTP

Uses TCP for:

* Control Connection (Port 21)
* Data Connection (Port 20)

---

## 9.3 Email Protocols

Protocols relying on TCP:

* SMTP
* IMAP
* POP3

---

## 9.4 SSH

SSH first establishes a TCP connection before authentication and encryption begin.

---

## 9.5 Performance Implications

TCP Handshake introduces approximately:

```text
1.5 RTT (Round Trip Time)
```

before application data transfer begins.

Optimization:

* TCP Fast Open (TFO)

---

# 10. Conclusion

The TCP three-way handshake is a fundamental networking mechanism that establishes a reliable, connection-oriented communication channel.

### Handshake Steps

```text
1. SYN
2. SYN-ACK
3. ACK
```

The Cisco Packet Tracer simulation verified the theoretical TCP connection establishment process.

Security concerns such as SYN Flood attacks highlight the importance of mechanisms like SYN Cookies and randomized ISNs.

Despite newer protocols such as QUIC, TCP remains one of the most widely used transport protocols on the Internet.

---

## 10.1 Key Takeaways

* TCP uses SYN, SYN-ACK, and ACK.
* Sequence numbers are synchronized before data transfer.
* Client and server transition through defined TCP states.
* Approximately 1.5 RTT latency is introduced.
* SYN Cookies mitigate SYN Flood attacks.
* Cisco Packet Tracer successfully demonstrates TCP handshake operation.

---

# References

1. Postel, J. (1981). RFC 793 – Transmission Control Protocol.
2. Stevens, W. R. TCP/IP Illustrated, Volume 1.
3. Tanenbaum, A. S., & Wetherall, D. Computer Networks.
4. Forouzan, B. A. Data Communications and Networking.
5. Cisco Networking Academy – Cisco Packet Tracer User Guide.
6. RFC 6528 – Defending Against Sequence Number Attacks.
7. RFC 7413 – TCP Fast Open.
8. Kurose, J. F., & Ross, K. W. Computer Networking: A Top-Down Approach.

---
