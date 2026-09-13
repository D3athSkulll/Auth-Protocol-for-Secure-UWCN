


PEECC-Based Secure Underwater Communication — Base Implementation
Commit: efb4134 — feat: add clean PEECC UWCN base protocol implementation

Status: First / baseline implementation

This repository contains the base implementation of the authentication architecture proposed in:

C. Rupa, M. Karuppiah, Y. Ko, M. K. Khan, and H. I. Sheikh Awal, “A Novel and Robust Authentication Protocol for Secure Underwater Communication Systems,” IEEE Internet of Things Journal, vol. 12, no. 22, pp. 47519–47531, Nov. 2025.

The purpose of this commit is to establish a clean, reproducible software baseline of the protocol architecture before introducing any of the improvements proposed for the project. Later commits can therefore be compared directly against this version.

1. What This Commit Implements
The implementation follows the paper's hierarchical underwater communication architecture:

UWS  →  SUB  →  BUOY  →  SAT  →  BS
where:

UWS — underwater sensor node(s)

SUB — submarine / underwater relay

BUOY (B) — surface communication relay

SAT — satellite relay

BS — terrestrial base station

The first implementation instantiates:

UWS   : U1, U2
SUB   : S1
BUOY  : B1, B2
SAT   : SAT1, SAT2
BS    : BS
The code implements the protocol as three logical stages:

System initialization

Registration

Mutual authentication and protected data forwarding

The authentication/data path is explicitly represented through messages M1–M12.

2. Protocol Flow
The baseline implementation models the complete four-hop communication chain:

        M1-M3          M4-M6          M7-M9          M10-M12
UWS  ───────────►  SUB  ─────────►  B  ─────────►  SAT  ─────────►  BS
 │                 │                │               │                 │
 │ Sensor Data     │ ENV + Alerts  │ ENV + GPS    │ ENV + GPS +     │
 │                 │                │               │ Logs             │
 └─────────────────┴────────────────┴───────────────┴─────────────────┘
M1–M3: UWS ↔ SUB
M1 — UWS → SUB

The underwater sensor sends an authentication request containing its identity, a fresh nonce, and a timestamp.

M2 — SUB → UWS

The submarine authenticates the UWS and returns its identity together with the echoed nonce and a timestamp. Both sides establish a hop-level session.

M3 — UWS → SUB

After authentication, the UWS sends the sensed environmental information:

Temperature
Pressure
Current Velocity
Salinity
The SUB extracts the values and forms the environmental (ENV) payload for the next hop.

M4–M6: SUB ↔ BUOY
M4 — SUB → B

The submarine starts authentication with a surface buoy using a new nonce and timestamp.

M5 — B → SUB

The buoy responds with its identity and the echoed nonce. The timestamp is checked and the SUB/B session is established.

M6 — SUB → B

The submarine forwards the aggregated environmental information together with alert information.

M7–M9: BUOY ↔ SAT
M7 — B → SAT

The buoy initiates authentication with the satellite.

M8 — SAT → B

The satellite authenticates the buoy and establishes the next hop session.

M9 — B → SAT

The buoy forwards the environmental data and alerts together with GPS information.

M10–M12: SAT ↔ BS
M10 — SAT → BS

The satellite initiates authentication with the base station.

M11 — BS → SAT

The base station authenticates the satellite and establishes the SAT/BS session.

M12 — SAT → BS

The satellite forwards the final mission package containing:

ENV
Alerts
GPS
LOGS
The BS decrypts and extracts the final payload.

3. System Initialization
Each network entity is assigned:

a private key PK

a public key PU

an identity value ID

The implementation keeps the identity derivation separate from the protocol so that the cryptographic backend can be replaced later.

Conceptually:

Private Key  ──► PEECC scalar multiplication ──► Public Key
                                      │
                                      ▼
                          ID = H(Public Key || Entity)
A SHA-256 based hash function is used by the simulator for deterministic identifiers and derived protocol values.

4. Registration Phase
After initialization, every entity is registered once with the network.

The baseline derives:

RID_i   = H(ID_i || PU_i || PK_i)
theta_i = H(RID_i || PU_i)
The simulator maintains a registered-ID set:

registration_set
and distributes the registration material to communication peers.

The important distinction in this implementation is that an entity obtains one registration identity, which can then be shared with multiple valid communication peers. This reflects the network-level registration model rather than generating a new RID for every individual link.

5. Mutual Authentication
Authentication is performed independently at each hop.

At each authentication exchange, the initiator provides:

Identity
Nonce
Timestamp
The responder validates the values and returns:

Responder Identity
Initiator Nonce
Responder Timestamp
A hop is accepted only when:

the received identity is correct,

the nonce matches the outstanding request, and

the timestamp values are inside the configured freshness window.

The baseline simulator uses:

DELTA_T = 5.0
as a concrete simulation parameter.

Session Establishment
After successful authentication, the two entities derive a locally stored session identifier:

SessionID = H("SESSION" || EntityA || EntityB || fresh nonce)
The session state is stored for both directions so that the protocol can subsequently forward the associated application data.

6. PEECC Software Abstraction
The paper describes a pentatope / five-dimensional elliptic-curve-style construction and represents points as:

(X, Y, Z, W, T)
with the pentatope relation expressed in the paper as:

X³ + Y³ + Z³ + W³ + T³ = dXYZWT
The paper also uses a generator point and scalar multiplication notation for key establishment.

Important implementation limitation
The paper does not provide enough executable detail to directly reproduce a complete 5-D group implementation from the publication alone. In particular, a complete implementable group law / scalar-multiplication construction and a complete public-key encryption primitive are not specified in sufficient detail for a drop-in production cryptography library.

Therefore, this first commit contains an explicitly isolated PEECC protocol simulation backend.

The backend models the required interface:

private key
     │
     ▼
public = private × generator

shared = private_A × public_B
       = private_B × public_A
The current simulator represents scalar multiplication using a coordinate-wise modular operation. This is an implementation abstraction for protocol experimentation, not a claim that it is the mathematically complete PEECC scheme from the paper.

This distinction is intentional. It allows the protocol implementation to be validated first while keeping the cryptographic primitive replaceable in a later commit.

7. Encryption in the Base Commit
The communication layer requires an encryption/decryption interface so that every hop can model protected protocol messages.

For the baseline implementation, the shared PEECC-derived value is hashed into a byte key and used with a simple XOR stream:

K = H(shared PEECC point)
C = plaintext XOR K-stream
Decryption reconstructs the same shared value and applies the XOR stream again.

Important
This XOR mechanism is not intended as a production cryptographic construction. It is retained only as a lightweight simulation envelope for the first protocol commit.

A later security-improvement commit can replace this layer without changing the M1–M12 protocol state machine.

8. Sensor and Mission Data
The baseline includes representative application data so that the entire UWS-to-BS path can be exercised end-to-end.

Environmental data
Temperature
Pressure
Current Velocity
Salinity
Alerts
The baseline forwards representative alert labels:

jamming
spoofing
eavesdropping
These values are application-level simulation data and are not an additional intrusion-detection mechanism.

GPS data
The buoy-to-satellite stage includes:

latitude
longitude
Mission logs
The final SAT-to-BS package includes a small mission-log field so that the complete application payload can be demonstrated.

9. Fallback Architecture
The base topology includes multiple buoys and satellites so that the architecture can represent alternate registered communication peers.

The implementation keeps peer information locally for entities that may communicate with multiple downstream/upstream nodes:

U1 ─┐
    ├── S1 ──┬── B1 ──┬── SAT1 ──┐
U2 ─┘        │        └── SAT2 ──┤
             └── B2 ─────────────┘
                                  │
                                  ▼
                                  BS
A choose_peer() helper is included to represent the paper's alternate-peer/fallback architecture.

Scope of Commit 1
This commit does not simulate node failure, packet loss, retransmissions, or dynamic route recovery. It only establishes the registered alternate-peer structure that later commits can exercise.

10. What Is Deliberately NOT in the First Commit
The first commit is intentionally a clean protocol baseline.

The following are excluded:

AES-GCM or other authenticated encryption improvements

Thorp acoustic absorption modelling

realistic underwater propagation/channel modelling

Bernoulli packet-loss simulation

retransmission logic

per-node battery depletion

AUV/SUB mobility

delay anomaly detection

forced node failures

dynamic runtime fallback testing

throughput experiments

network scaling experiments

comparison charts against prior schemes

performance optimization

formal Scyther verification integration

production-grade 5-D PEECC cryptographic arithmetic

These should be introduced as separate commits, so each change can be evaluated against this baseline.

11. Repository Structure
The first commit is intentionally small:

eecc-base/
│
├── uwc_simulation_base.py     # Complete baseline protocol simulation
├── README.md                  # This document
├── commit_message.txt         # Suggested Git commit message
└── 0001-base-peecc-uwcn.patch # Patch representing the first commit
The main implementation is organized into the following components:

PEECCBackend
     │
     ├── key generation
     ├── shared-point derivation
     ├── key derivation
     └── baseline encryption/decryption

Entity
     │
     ├── identity
     ├── keys
     ├── registration state
     └── registered peers

UWCNProtocol
     │
     ├── system initialization
     ├── registration
     ├── M1–M12 protocol execution
     ├── session management
     └── alternate peer selection
12. Requirements
Python 3.8+ is recommended.

The first commit uses only Python standard-library modules:

hashlib
os
time
dataclasses
typing
No external cryptography or graphing package is required for this baseline script.

13. Running the Baseline
From the repository directory:

python uwc_simulation_base.py
The program performs:

1. System initialization
2. Key-pair generation for all entities
3. Identity generation
4. Registration of all entities
5. Distribution of registration material to peers
6. Execution of M1–M12
7. Session creation for each authenticated hop
8. Delivery of environmental data, alerts, GPS and logs to BS
A successful execution ends with:

=== PROTOCOL COMPLETE: SUCCESS ===
The program also prints the number of registered RIDs and the session identifiers established during the run.

14. Expected Authentication Path
The demonstration run uses:

U1 → S1 → B1 → SAT1 → BS
with the corresponding protocol sequence:

U1   -- M1 -->  S1
U1   <-- M2 --  S1
U1   -- M3 -->  S1

S1   -- M4 -->  B1
S1   <-- M5 --  B1
S1   -- M6 -->  B1

B1   -- M7 -->  SAT1
B1   <-- M8 --  SAT1
B1   -- M9 -->  SAT1

SAT1 -- M10 --> BS
SAT1 <-- M11 -- BS
SAT1 -- M12 --> BS
At the end of M12, the base station extracts the complete mission package.

15. Design Goals of This Commit
The baseline is intended to provide four things:

Protocol fidelity
The main purpose is to reproduce the logical protocol flow and the four-hop architecture before introducing project-specific improvements.

Isolation of cryptographic assumptions
The PEECC backend is kept separate from the protocol state machine so that a more rigorous implementation can replace it later without rewriting M1–M12.

Reproducible experimentation
Every later improvement should be comparable against the same topology, message sequence, registration model and application payload.

Commit-by-commit development
The repository is intended to evolve approximately as:

Commit 1  ── Clean base protocol
   │
   ├── Commit 2  ── Rigorous / improved PEECC backend
   ├── Commit 3  ── Authenticated encryption
   ├── Commit 4  ── Underwater channel model
   ├── Commit 5  ── Packet loss + retransmission
   ├── Commit 6  ── Energy model
   ├── Commit 7  ── Mobility / dynamic topology
   ├── Commit 8  ── Failure + fallback experiments
   └── Commit 9+ ── Verification / evaluation / comparisons
The exact ordering can be adjusted as the project develops.

16. Security Scope of the Baseline
This commit should be interpreted as a protocol implementation baseline, not as the final security implementation.

The simulation demonstrates the intended protocol checks for:

node identity verification

nonce freshness

timestamp freshness

shared-key based message protection

hop-wise session establishment

However, the baseline does not establish production cryptographic security because the PEECC arithmetic and message-encryption construction are simulation abstractions.

This limitation is documented explicitly so that later security claims are made only after the underlying primitives have been replaced or rigorously implemented.

17. Base Paper Reference
C. Rupa, M. Karuppiah, Y. Ko, M. K. Khan, and H. I. Sheikh Awal, “A Novel and Robust Authentication Protocol for Secure Underwater Communication Systems,” IEEE Internet of Things Journal, vol. 12, no. 22, pp. 47519–47531, Nov. 2025. DOI: 10.1109/JIOT.2025.3601984.