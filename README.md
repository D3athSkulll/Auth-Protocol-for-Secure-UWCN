# PEECC and the UWC Authentication Protocol

An implementation of the IEEE IoT-J paper

> C. Rupa et al., *"A Novel and Robust Authentication Protocol for Secure Underwater Communication Systems"* (**IoT**, `A_Novel_and_Robust_...pdf`),

on top of the cryptosystem of its reference [18],

> D. Jayakumari, C. Rupa, V. Nikhila, *"Pentatope Based Elliptic Curve Encryption for Privacy and Protection of Multimedia Data"* (**[18]**, `PEECC Base.pdf`).

* **Crypto core** ([peecc.c](peecc.c), C + GMP): PEECC in two modes. The default **paper-exact** mode is literal [18]. The opt-in **hardened** mode (`--hardened`, section 4.9) is a labelled deviation from [18]. Messages of any length are split into blocks.
* **Protocol** ([protocol.py](protocol.py)): IoT Sec. IV for UWS, SUB, B, SAT and BS: initialization, registration, mutual authentication M1–M12, fallback and revocation. All modular arithmetic runs in C through ctypes.
* **Simulation** ([simulate.py](simulate.py)): message traces, 11 attacks, fallback scenarios, a 10–200 node scale run, metrics, and a table of each paper claim against the measured value.
* **Formal model** ([uwc_protocol.spdl](uwc_protocol.spdl)): Scyther, run with the bundled binary.

---

## 1. Repository contents

| File | Purpose |
|---|---|
| [peecc.c](peecc.c) | PEECC (≈ 600 lines, GMP big integers): curve arithmetic, both modes, multi-block library API, demo, self-tests |
| [Makefile](Makefile) | `make`, `make lib`, `make run`, `make run-hardened`, `make test`, `make clean` |
| [protocol.py](protocol.py) | ctypes wrapper of `peecc.dll` / `libpeecc.so` and the protocol of IoT Sec. IV (section 11) |
| [simulate.py](simulate.py) | simulator, attacks, metrics, logging, charts, Scyther call (section 12) |
| [uwc_protocol.spdl](uwc_protocol.spdl) | Scyther model of registration and M1–M12 (section 13) |
| [peecc_gui.py](peecc_gui.py) | Tkinter GUI that visualises PEECC in both modes (section 10) |
| [PEECC_EXPLAINED.md](PEECC_EXPLAINED.md) | Beginner-level tutorial (maths from scratch) |
| `docs/thesis/`, `docs/slides/` | Report (LaTeX) and presentation. The thesis still describes the earlier single-block, paper-exact-only code |
| `PEECC Base.pdf`, `A_Novel_and_Robust_...pdf` | The two source papers |
| `prompt.md` | Task description |
| `scyther/`, `launch_scyther_gui.bat` | Bundled Scyther 1.3.0 (Windows) |
| `results/`, `logs/` | Written by `simulate.py` |

`peecc.exe` and `peecc.dll` are build products (`make clean` removes them).

## 2. Build and run

Requirements: `gcc` and the GMP library (Windows: MSYS2 `mingw64`, `pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gmp make`), Python 3.8+ with `matplotlib` (`pip install -r requirements.txt`).

```bash
make test                       # 27 self-tests of the C core (both modes, both point formats)
make run                        # paper-exact: encrypt + decrypt "hello PEECC", printing every intermediate value
make run-hardened               # the same in hardened mode (deviation from [18])
make lib                        # shared library for protocol.py (peecc.dll / libpeecc.so)

python simulate.py --demo       # trace of every message UWS -> SUB -> B -> SAT -> BS
python simulate.py --attacks    # 11 attacks, both modes side by side
python simulate.py --fallback   # unresponsive buoy, delayed satellite, mobile node
python simulate.py --scale      # 10-200 nodes, depth 2-5
python simulate.py --all        # all of the above + Scyther + metrics + claims table (about 1 minute)
python simulate.py --all --hardened   # the same with hardened PEECC
```

> Windows note: if `gcc` fails silently, put `C:\msys64\mingw64\bin` first in `PATH` (other programs' DLLs can shadow the MinGW runtime).

---

## 3. What PEECC does, in one picture

```
 RECEIVER                                             SENDER
 private key d ──(d·B)──► public key Pub ───────────► message m
                                                         │ Koblitz: m → point Pm
                                                         │ S = Pentatope(Bx),  K = S²+S+41
                                                         │ C1 = K·B
                                                         │ C2 = Pm + K·Pub
 Pm = C2 − d·C1  ◄───────────── (C1, C2) ◄───────────────┘
 Koblitz⁻¹: Pm → m
```

---

## 4. The mathematics

### 4.1 Finite field
All arithmetic is done modulo a 256-bit prime $p$ (the field $\mathbb{F}_p$). Division is multiplication by the modular inverse: $a^{-1}$ satisfies $a\cdot a^{-1}\equiv 1 \pmod p$.

### 4.2 The elliptic curve (secp256r1)
$$E:\; y^2 = x^3 + a x + b \pmod p,\qquad a=-3$$
Fixed standard constants: prime $p = 2^{256}-2^{224}+2^{192}+2^{96}-1$, coefficient $b$, generator $B=(B_x,B_y)$ of prime order $N$ (so $N\cdot B=\mathcal{O}$, the point at infinity). The program stores them as hexadecimal strings in `setup_curve()`.

### 4.3 Group law (affine coordinates)
Points on $E$, together with $\mathcal O$, form a group.

For $P=(x_1,y_1)$, $Q=(x_2,y_2)$, $P\neq\pm Q$:

$$\lambda=\frac{y_2-y_1}{x_2-x_1},\qquad x_3=\lambda^2-x_1-x_2,\qquad y_3=\lambda(x_1-x_3)-y_1$$

Doubling $P=Q$:

$$\lambda=\frac{3x_1^2+a}{2y_1},\qquad x_3=\lambda^2-2x_1,\qquad y_3=\lambda(x_1-x_3)-y_1$$

Negation: $-P=(x,\,-y)$. Special cases: $P+\mathcal O=P$ and $P+(-P)=\mathcal O$.

*Toy check you can do by hand* (curve $y^2=x^3+2x+2$ over $\mathbb F_{17}$, $B=(5,1)$): $\lambda=\frac{3\cdot25+2}{2}=13$, so $2B=(13^2-10,\;13(5-6)-1)=(6,3)$, and $3B=(10,6)$.

### 4.4 Scalar multiplication (double-and-add)
$k\cdot P=\underbrace{P+\dots+P}_{k}$ is computed from the binary expansion $k=\sum k_i2^i$ with Horner's rule: start from $\mathcal O$; for each bit from the most significant: **double**, and if the bit is 1, **add** $P$. Cost $\approx 256$ doublings + $128$ additions instead of $2^{256}$ additions.

### 4.5 Keys ([18] Sec. 3.1)
$$d\in[1,N-1]\ \text{random},\qquad Pub = d\cdot B$$
Recovering $d$ from $Pub$ is the elliptic-curve discrete logarithm problem (believed infeasible).

### 4.6 Pentatope number and K ([18] Sec. 3.2, Steps 2-3)
The pentatope number is the fifth diagonal of Pascal's triangle, $\binom{x+3}{4}$:
$$S=\text{Pentatope}(x)=\frac{x(x+1)(x+2)(x+3)}{24},\qquad K=S^2+S+41\ \ (\text{Euler's polynomial})$$
Here $x=B_x$ (the generator's x-coordinate), and everything is a plain big integer (no modulus). The division by 24 is exact (product of 4 consecutive integers). Hand values used in the tests:

| $x$ | $S$ | $K=S^2+S+41$ |
|---|---|---|
| 1 | 1 | 43 |
| 2 | 5 | 71 |
| 3 | 15 | 281 |

For the real generator, $S\approx 2^{1015}$ and $K\approx 2^{2029}$.

### 4.6a Message → curve point (Koblitz) ([18] does not specify this)
Message bytes $\to$ integer $m$ (with a leading `0x01` marker byte so length and leading zeros survive). Try
$$x=256\,m+j,\quad j=0,1,\dots,255$$
and take the first $j$ for which $r=x^3+ax+b$ is a quadratic residue. As $p\equiv3\pmod 4$, a square root is
$$y=r^{(p+1)/4}\bmod p,\qquad \text{valid iff } y^2\equiv r$$
Each $j$ succeeds with probability $\approx\tfrac12$, so failure for all 256 values has probability $\approx2^{-256}$. Decoding: $m=\lfloor x/256\rfloor$, drop the marker.

### 4.7 Encryption ([18] Sec. 3.2, Step 4)
For message point $P_m$ and receiver public key $Pub$:
$$C_1=K\cdot B,\qquad C_2=P_m+K\cdot Pub$$

### 4.8 Decryption ([18] Sec. 3.3)
$$P_m=C_2-d\cdot C_1$$
**Why it works:** $d\cdot C_1=d\cdot(K\cdot B)=K\cdot(d\cdot B)=K\cdot Pub$, hence $C_2-d\cdot C_1=P_m+K\cdot Pub-K\cdot Pub=P_m$.

### 4.9 Hardened mode (`--hardened`, **deviation from [18]**)
Paper-exact PEECC takes the pentatope input from the public generator ($x=B_x$), so $K$ is public (section 8). Hardened mode keeps the pentatope and Euler steps and changes only their input, plus point validation:
$$x\xleftarrow{\$}[1,N-1]\ \text{(fresh and secret per message)},\qquad S=\text{Pentatope}(x),\qquad K=(S^2+S+41)\bmod N$$
$$C_1=K\cdot B,\qquad C_2=P_m+K\cdot Pub,\qquad P_m=C_2-d\cdot C_1\ \ (\text{decryption unchanged})$$
* `encrypt` rejects a public key, and `decrypt` rejects a $C_1$ or $C_2$, that is the point at infinity, has a coordinate outside $[0,p-1]$, or is off the curve (cofactor 1, so on the curve means in $\langle B\rangle$).
* Reducing $K$ mod $N$ gives the same points ($N\cdot B=\mathcal O$) and keeps the multiplier at 256 bits.
* Honest note: the security comes from the random $x$ (the scheme becomes EC-ElGamal with ephemeral scalar $K$); the pentatope polynomial itself adds no strength. As a polynomial of degree 8, $x\mapsto K$ is at most 8-to-1, so at most 3 bits of entropy are lost.
* **Compressed points** (library and protocol, also a deviation from the paper's "512-bit ECC point"): a point is sent as `02`/`03` ‖ x (33 bytes; the prefix is the parity of y, SEC 1 §2.3.3). The receiver recomputes $y=(x^3+ax+b)^{(p+1)/4}$ and picks the root with that parity; a prefix other than 02/03, $x\ge p$ or an $x$ without a square root is rejected. One block shrinks from 128 to 66 bytes (1024 → 528 bit). In the library the two deviations are separate flags (`PEECC_HARDENED = 1`, `PEECC_COMPRESSED = 2`); `protocol.py --hardened` uses both, the default uses neither. The `peecc.exe` demo prints points uncompressed in both modes.

---

## 5. Code map: which part of `peecc.c` does what

| Lines | Function / block | What it does | Math / paper reference |
|---|---|---|---|
| 39-45 | constants, `Pt`, globals | `MAX_MSG=29`, `KAPPA=256`; `Pt` = point `(x,y)` + `inf` flag; globals `P, A, Bc, N, G` | §4.1-4.3 |
| 49 | `os_random` | Secure random bytes from the OS (`rand_s` / `/dev/urandom`) | needed for private keys |
| 64 | `random_private_key` | 384 random bits reduced into $[1,N-1]$ (extra bits ⇒ negligible bias) | [18] 3.1 Step 1 |
| 74-77 | `fp_add/sub/mul/inv` | $\mathbb F_p$ arithmetic; inverse by `mpz_invert` | §4.1 |
| 80-82 | `pt_init/clear/set` | allocate / free / copy a point (GMP needs explicit memory handling) | – |
| 85 | `pt_on_curve` | checks $y^2\equiv x^3+ax+b$ | §4.2 |
| 96 | `pt_double` | doubling formula, handles $y=0$ | §4.3 |
| 108 | `pt_add` | addition formula + special cases ($\mathcal O$, $P=Q$, $P=-Q$) | §4.3 |
| 124 | `pt_neg` | $(x,y)\mapsto(x,p-y)$ | §4.3 |
| 130 | `pt_mul` | double-and-add scalar multiplication | §4.4 |
| 140 | `pt_equal` | point comparison (self-tests only) | – |
| 148 | `pt_valid` | finite, coordinates in $[0,p-1]$, on the curve (hardened mode) | §4.9 |
| 154 | `setup_curve` | loads secp256r1 constants, sets $a=p-3$ | §4.2 |
| 167 | `pentatope` | $S=x(x+1)(x+2)(x+3)/24$ with `mpz_divexact_ui` | [18] 3.2 Step 2 |
| 177 | `euler_K` | $K=S^2+S+41$ | [18] 3.2 Step 3 |
| 184 | `koblitz_encode` | bytes → point | §4.6a |
| 204 | `koblitz_decode` | point → bytes (returns −1 if invalid structure) | §4.6a |
| 216 | `keygen` | random $d$, $Pub=d\cdot B$ | [18] 3.1 |
| 221 | `make_K` | $x=B_x$ (paper-exact) or random $x$ (hardened); then $S$ and $K$ | [18] 3.2 Steps 2-3, §4.9 |
| 230 | `encrypt_K` | $C_1=K B$; $C_2=P_m+K\,Pub$ | [18] 3.2 Step 4 |
| 240 | `encrypt` | validates $Pub$ (hardened), then `make_K` + `encrypt_K` | [18] 3.2 |
| 250 | `decrypt` | validates $C_1,C_2$ (hardened); $P_m=C_2-dC_1$ | [18] 3.3 |
| 261 | `eve_attack` | keyless eavesdropper: $C_2-K_{paper}\cdot Pub$ | section 8 |
| 275-302 | wire format helpers, `lib_init`, `now_ms` | 32-byte scalars, 64-byte points, 128-byte blocks; timer | section 11 |
| 306-385 | `peecc_ct_size`, `peecc_keygen`, `peecc_encrypt`, `peecc_decrypt`, `peecc_eavesdrop`, `peecc_pentatope_K`, `peecc_bench` | exported library API; messages split into 29-byte blocks | section 11 |
| 400-613 | `show`, `demo`, `CHECK`, `test_hardened`, `test_blocks`, `test`, `main` | demo and self-tests (excluded from the library build by `PEECC_LIB`) | section 6 |

**Layering** (each layer uses only the one above it in the list):

```
 field arithmetic (fp_*)  →  point group (pt_*)  →  scalar multiplication (pt_mul)
                                                        ↓
              Koblitz mapping + pentatope/K  →  keygen / encrypt / decrypt  →  peecc_* API (blocks)  →  demo / test
                                                                                               ↓
                                                                        protocol.py (ctypes)  →  simulate.py
```

---

## 6. How correctness is verified (`make test`)

| Check | What it proves |
|---|---|
| $B$ lies on the curve | constants entered correctly |
| $2B$ equals the published secp256r1 value | doubling and scalar multiplication match an **independent reference** |
| $N\cdot B=\mathcal O$ | order and group law consistent |
| 50 random public keys on the curve | key generation yields valid points |
| $Pub = d\cdot B$ (50 keys) | public key = private × generator |
| $(a+b)B = aB+bB$ (20 pairs) | scalar multiplication is a true homomorphism |
| $S(1,2,3)=1,5,15$ | pentatope function equals hand computation |
| $K(1,5,15)=43,71,281$ | Euler formula equals hand computation |
| `decrypt(encrypt(m)) = m`, 1000 random messages (0-29 bytes) | whole scheme is correct |
| **test_K_is_public**: eavesdropper decrypts 100/100 paper-exact messages without a key | the weakness of section 8 is real |
| paper-exact $C_1$ identical for every message | encryption is deterministic |
| hardened: round trip for 1000 random messages | hardened mode is correct |
| hardened: eavesdropper decrypts 0/1000 | the same attack fails |
| hardened: $C_1$ differs from the first in all 999 later encryptions | encryption is randomised |
| hardened: off-curve, out-of-range and infinity $C_1$/$C_2$ rejected | point validation in `decrypt` |
| hardened: off-curve $Pub$ rejected | point validation in `encrypt` |
| hardened: valid ciphertext still decrypts after the checks | no false rejections |
| blocks: round trip of 0–120-byte messages, both modes | multi-block splitting is correct |
| blocks: 128 bytes per started 29-byte block | ciphertext size as specified |
| blocks: paper-exact eavesdropper reads whole messages / hardened reads none | the break and the fix hold for long messages |
| blocks: corrupted block and truncated ciphertext rejected (hardened) | the library API validates its input |
| blocks: all 4 modes (paper-exact / hardened x 512-bit / compressed points), 128 or 66 bytes per block | compression is lossless |
| blocks: compressed points with a bad prefix or an x off the curve rejected | decompression validates its input |

Current result: **all 27 checks pass** (about 45 s, dominated by the 2029-bit $K$ of paper-exact mode).

### Sample demo output (abridged, values vary per run except C1)
```
== Key generation (receiver) ==   private key d = 20e2e5...18d6 ;  Pub = d*B on curve: yes
== Encryption ==    message "hello PEECC" (11 bytes) -> Pm (Koblitz)
   S = Pentatope(Bx) (~1015 bits)   K = S^2+S+41 (2029 bits)
   C1 = K*B :  x = 681dc23639d030c4...      C2 = Pm + K*Pub
== Decryption ==    Pm' = C2 - d*C1   ->  decoded message: "hello PEECC"   result: MATCH
== Keyless eavesdropper ==   reads "hello PEECC"   attack: SUCCEEDS        (with --hardened: FAILS)
```
Every run prints its mode first: `mode: paper-exact [18] ...` or `mode: HARDENED (deviation from [18]: ...)`.

---

## 7. Design decisions and why

| Decision | Reason |
|---|---|
| Implement **[18]'s 2-D curve PEECC**, not the IoT paper's 5-D curve ψ | [18] gives usable formulas on an ordinary curve; the IoT paper only mentions a 5-D group without arithmetic (documented conflict) |
| secp256r1 | specified requirement; standard constants allow testing against published values |
| "512-bit ECC point" = two 256-bit coordinates | 2 × 256 = 512, consistent with the IoT paper's field size |
| Koblitz mapping | [18] says the message "has a point M" but never says how |
| `0x01` marker, $\kappa=256$, 29 bytes per block | keeps leading zeros/length; failure probability $2^{-256}$; keeps $x<p$ (29 is conservative: $x<2^{241}$; 30 bytes would also fit) |
| Longer messages split into independent 29-byte blocks, each 128 bytes on the wire | [18] encrypts one point; the protocol's M6/M9/M12 need more than 29 bytes |
| $S,K$ kept as full big integers | literal to the paper ("as big integers"); costs speed: measured encryption is about 8x slower (14.6 ms vs about 1.7 ms) with the same output |
| GMP, affine coordinates, double-and-add | standard big-number library; textbook formulas that map directly to the maths above |
| OS randomness, 384 bits → $[1,N-1]$ | secure private keys, negligible modulo bias |
| Tests and demo inside the same file | one file, easy to verify and present |
| Paper-exact is the default, hardened is opt-in | the literal scheme is what [18] specifies; the fix is a clearly labelled deviation |
| Hardened mode randomises the pentatope **input** instead of replacing $K$ | keeps PEECC's pentatope and Euler steps while removing the public-$K$ break; only $x$ changes |

---

## 8. Known limitations (important to state honestly)

1. **The weakness of PEECC [18].** $K$ is derived only from the *public* generator, so anyone can compute
   $$P_m = C_2 - K\cdot Pub$$
   **without the private key**, and $C_1=K\cdot B$ is identical for every message (visible: run the demo twice; $C_1$ never changes). The default mode is *paper-exact* on purpose, and `test_K_is_public` demonstrates the break. The opt-in `--hardened` mode (section 4.9) removes it by drawing the pentatope input $x$ at random for every message.
2. Educational code: not constant-time, hence not side-channel safe.
3. Blocks are encrypted independently: an attacker can drop, reorder or swap blocks of a multi-block message.
4. Hardened mode still has no integrity tag: a ciphertext can be changed into another valid one (malleability), and anyone can encrypt to $Pub$, so a ciphertext does not prove who sent it. This is the root of the initiator-impersonation result in section 14.

## 9. Not implemented
The 5-D curve ψ of IoT Sec. IV-A (no arithmetic is given), BAN-logic proofs, tamper-resistant key storage (IoT IV-E-1, hardware), and the thesis update for the protocol work.

---

## 10. GUI simulation (`peecc_gui.py`)

```bash
python peecc_gui.py            # needs tkinter + matplotlib (pip install matplotlib)
python peecc_gui.py --selftest # non-GUI check against peecc.exe values
```

* **Tab 1 - Pipeline:** animated block diagram (Alice / open channel + Eve / Bob) with a clickable 11-step progress bar, a
  plain-English explanation, the equation and the real 256-bit values for each step. Switch between *Paper-exact [18]* and
  *Improved (deviation)*; the table under the diagram logs C1 per run (constant in paper-exact mode).
* **Tab 2 - Toy curve explorer:** `y^2 = x^3 + x + 1 (mod 23)` with every dot labelled by its multiple `k*B`; choose d, m and
  the mode, see the double-and-add path of `d*B`, the `Pm -> C2` jump, the decryption arrow and Eve's attempt.
* **Tab 3 - Math walkthrough (node by node):** the worked example on the toy curve `y^2 = x^3 + x + 1 (mod 23)`, `B = (18,3)`, `N = 28`.
  For each step it shows who computes it (Alice / open channel / Bob / Eve), an input -> operation -> output block, the idea in
  plain words, the core formula, and every number of the computation (slopes, modular inverses, double-and-add, point additions).
* **Tab 4 - Improvements vs base paper:** a live benchmark runs both schemes on random messages and keys and reports
  Eve's keyless success rate, distinct C1 values, repeatability of ciphertexts, multiplier size, point operations and
  encryption time, plus a qualitative property table that also lists what is *not* improved (integrity, constant time).

* **Tab 5 - Performance metrics:** measured/counted metrics for both schemes: key generation, encryption and decryption time,
  scalar multiplications / point doublings / additions / field inversions, key and ciphertext sizes in bits, ciphertext expansion,
  throughput, ciphertext uniqueness, keyless-eavesdropper success and the curve's ECDLP security level. Tabs 4 and 5 also
  show C timings measured live through `peecc.dll` (`peecc_bench`) for both modes. Without the DLL they fall back to the
  earlier thesis measurement.
* **Tab 6 - Protocol M1-M12:** runs `protocol.py` on `peecc.dll` over the Fig. 1 path S1 → SB1 → B1 → SAT1 → BS and draws
  it as a sequence diagram (Play / Next / Back, or the arrow keys).
  * **Scenarios:** normal run, buoy B1 unresponsive (fallback to B2), SAT1 answering 4 s late (fallback to SAT2).
  * **Mode:** paper-exact or hardened.
  * **Details pane, per message:** plaintext fields, every ciphertext block, the receiver's checks, what the receiver
    decrypts, and what a keyless eavesdropper reads. Arrows read by the eavesdropper are labelled "Eve reads it".
  * **Summary line:** bits on the wire vs paper model, simulated time, sessions, and how many messages Eve reads
    (paper-exact 12 of 12, hardened 0 of 12).
  * **"Run attack suite"** runs the 11 attacks of `simulate.py` in the selected mode.
  * Needs `make lib`.

* **Tab 7 - Results & charts:** the paper-claims table from `results/metrics_paper-exact.json` and
  `metrics_hardened.json`: claim, paper value, value in each mode; green = met, red = not met.
  * **Selecting a claim** shows its details and the charts that are evidence for it. For example, computation →
    cost and per-entity charts; attacks → security chart; Scyther → claims grid.
  * **Each chart has a tick box:** ticked charts are shown, unticked ones are hidden, and the area scrolls.
  * **Buttons:** "All" and "None", plus "Redraw from saved results", which runs `simulate.py --figures`.
  * If no results exist yet, the tab says to run `python simulate.py --all` (and `--all --hardened`).

The header badge shows the mode of the tab that is currently visible.

The "improved" scheme is the GUI's name for hardened mode (section 4.9): the pentatope input x is a fresh secret random number,
$K=(S^2+S+41)\bmod N$, and points are validated before use. On the 28-point toy curve $K(x)\bmod 28$ takes only 4 values,
so there the eavesdropper sometimes gets lucky; this is a property of the tiny group, not of secp256r1.
The GUI is a pure-Python re-implementation of the formulas of `peecc.c`; `--selftest` confirms it reproduces `peecc.exe`.

---

## 11. The protocol (`protocol.py`, IoT Sec. IV)

Entities and topology follow IoT Fig. 1: S1–S18 (UWS), SB1–SB6 (SUB), B1–B3, SAT1–SAT3, BS. Each child has a primary
and a preregistered fallback parent: UWS → next SUB, SUB → next buoy, B → next satellite.

| Phase | What the code does | Paper |
|---|---|---|
| Initialization | `PK_i` random, `PU_i = PK_i·B` (C), `ID_i = H(PU_i‖E‖DeviceSerial)` truncated to 64 bit; the BS distributes all `(ID_i, PU_i)` over a trusted link | IV-A Steps 3-6, IV-E-3 |
| Registration | `RID_i = H(ID_i‖PU_i‖PK_i)`, `v_i = H(RID_i‖PU_i)` (160 bit), message `{RID_i, PU_i, v_i}`; receiver: `v` mismatch → INVALID, `PU` not in directory → UNKNOWN, revoked → REVOKED, RID already in R → DUPLICATE, else add to R | IV-B Steps 1-5 |
| Request M1/M4/M7/M10 | `E{PU_R, ID_I ‖ Nonce_I ‖ TS}`; responder checks: decrypts, ID registered and not revoked, nonce unused, `|now − TS| < ΔT` | IV-C Steps 1, 5, 9, 13 |
| Response M2/M5/M8/M11 | `E{PU_I, ID_R ‖ Nonce_I (echo) ‖ TS}`; initiator checks: expected ID, `Nonce_recv = Nonce_sent`, `|TS_resp − TS_req| < ΔT` → session | IV-C Steps 2-3, 6-7, 10-11, 14-15 |
| Data M3/M6/M9/M12 | `E{PU_R, ID_R ‖ payload ‖ TS}`: ENV (M3); + Alerts (M6); + GPS (M9); + LOGS (M12). SUB aggregates the ENV of its UWS | IV-C Steps 4, 8, 12, 16 |
| Fallback | primary peer times out or answers late → next preregistered peer, same nonce/TS rules; mobile UWS re-runs M1–M3 with its fallback SUB | IV-D |
| Revocation | BS issues a list of IDs with an HMAC under the management key; entities verify it before use | IV-E-2 |

Every message is PEECC-encrypted with the receiver's public key, split into 29-byte blocks. The C library's measured
computation time is added to the simulated clock. Links are 10 kbps, 100–1000 m, with sound at 1500 m/s.

## 12. Simulation (`simulate.py`)

* `--demo`: S1, S2, S3 → SB1, then SB1 → B1 → SAT1 → BS. For every message it prints the direction, plaintext fields,
  C1/C2 (truncated hex), blocks and bits on the wire, each check with ok/FAIL, and session creation.
* `--attacks`: 11 attacks, each on a fresh network, in **both** modes side by side (section 14).
* `--fallback`: B1 unresponsive (SB1 → B2), SAT1 answering 4 s late (B1 rejects the stale reply and uses SAT2), and
  mobile S1 → SB2 re-authentication.
* `--scale`: three series, all with real crypto:
  * node count 10–200 at depth 5;
  * depth 2–5 with a fixed 100 nodes;
  * depth 2–5 with a constant fan-out of 3.

  A parent's modem serves its children one after another. A node authenticates upward once its children are done.
* `--all`: everything above. It also runs Scyther, prints the metrics and the **paper claim vs measured** table, and
  writes `results/metrics.json`, `metrics.csv`, `communication_cost.png`, `latency.png` and `scyther_output.txt`.

Every run logs its mode and writes `logs/run_<timestamp>.log`, with one line per step tagged `[INIT]`, `[REGISTER]`,
`[AUTH]`, `[FALLBACK]` or `[ATTACK]`. Metrics come from the messages actually sent; paper values appear only as the
"claim" column.

## 13. Scyther (`uwc_protocol.spdl`)

* **What is modelled:** the registration exchange, plus M1–M12 with exactly the paper's fields in the paper's order.
  Hashes use `hashfunction H`, encryption is `{…}pk(X)`, and nonces and timestamps are fresh per hop.
* **One protocol per hop:** each hop is its own two-role protocol, all analysed together at `--max-runs=5`. In a single
  five-role protocol, Scyther's Alive and agreement claims refer to all five roles, which no hop-local exchange can
  establish. That variant also ran more than 9 minutes without finishing.
* **Claims:** Secret, Alive, Weakagree, Niagree and Nisynch per role, as in IoT Fig. 6.
* **What Scyther cannot see:** it treats PEECC as ideal public-key encryption. It therefore cannot detect the K-public
  flaw, which `test_K_is_public` and the eavesdropping attack demonstrate instead. The 8-bit timestamp wrap isn't
  modelled either.

**Result: 23 claims Ok, 35 Fail** (about 15 s; the full output is in `results/scyther_output.txt`).
* **Initiator side** (UWS in hop 1, SUB in hop 2, …): the nonce and data stay secret, and Alive and Weakagree hold.
  Niagree and Nisynch fail.
* **Responder side:** every claim fails, including secrecy of the received data. M1/M4/M7/M10 contain nothing that
  only the initiator could produce, so the intruder can play the initiator.
* **Registration:** `J: Alive` fails, because the registration message is a plaintext anyone can replay.

The model was not edited to turn claims green. This contradicts the paper's statement that every claim was verified.

## 14. Results (seed 1, this PC; times vary per run)

**Attacks** (`--attacks`):

| Attack | paper-exact | hardened |
|---|---|---|
| replay of M1 within ΔT | detected (nonce reused) | detected |
| delay injection, M1 held 4 s | detected (stale TS) | detected |
| delay injection, M1 held exactly 12.8 s | **not detected**: 8-bit TS wraps, nonce never used | **not detected** |
| impersonate SUB to UWS (wrong private key) | **not detected**: K-public reveals the nonce | detected (nonce mismatch) |
| impersonate UWS to SUB (inject M1 + fake M3) | **not detected** | **not detected** |
| tampered registration (PU swapped) | detected (INVALID) | detected |
| duplicate RID | detected (DUPLICATE) | detected |
| rogue registration (own key pair, correct v) | detected (UNKNOWN: directory, IV-E-3) | detected |
| revoked node | detected | detected |
| forged revocation list | detected (bad HMAC) | detected |
| K-public eavesdropping on M1–M12 | **not detected**: 12 of 12 messages read | detected (0 of 12) |

**Paper claims** (`--all`):

| Claim | Paper | Measured (paper-exact / hardened) | Result |
|---|---|---|---|
| Communication cost, paper model | 2112 bit | 2720 bit (handshakes alone 1088 bit) | FAIL: data-message sizes are not given in the paper |
| 30–34 % reduction vs 3008–3216 bit | 30–34 % | 29.8–34.3 % from the paper's own numbers | PASS (arithmetic) |
| Transmission at 10 kbps | 211 ms | 272 ms model; on the wire **1638 ms** (16 384 bit, 1024-bit blocks) / **845 ms** (8 448 bit, 528-bit compressed blocks) | FAIL |
| Computation per entity | 0.4 / 0.5 ms | UWS ≈ 48–60 / 6.5–10 ms, SUB ≈ 95–125 / 13–20 ms, BS ≈ 27–55 / 8–11 ms (incl. keygen; varies with machine load between runs) | FAIL |
| UWS energy (paper's per-op values, ECC per 256 scalar bits) | 48.8 µJ | 842.5 / 177.6 µJ (6 ECC mult., 4 hash, 2 enc, 1 dec; paper's flat model: 177.6 µJ in both modes) | FAIL |
| Mobile re-authentication | < 1 ms | ≈ 57–83 / 10–13 ms computation; 1.9–2.1 s including the acoustic link | FAIL |
| Registry storage of a UWS | < 250 B | 40 B | PASS |
| Delay linear in depth | linear | fan-out 3: ≈ 4.9 s/level, R² = 0.99. With a fixed 100 nodes the trend reverses (congestion) | PASS (fan-out 3) |
| Scyther: all claims verified | all Ok | 23 Ok, 35 Fail | FAIL |
| 5-D overhead 1.3× | 1.3× | not measured (2-D implementation) | N.A. |

Fallback: buoy down → B2 after 4.3–4.4 s (includes the ΔT wait); SAT1 late → SAT2 after 7.2–7.3 s.

**Figures** (`python simulate.py --figures` redraws them from `results/metrics_paper-exact.json` and
`results/metrics_hardened.json`; each `--all` run writes the file of its mode and redraws everything):

| Figure | Shows |
|---|---|
| [claims_scorecard.png](results/claims_scorecard.png) | every quantitative claim as measured ÷ claimed (log scale, both modes, red = not met), plus the qualitative claims with PASS/FAIL/N.A. |
| [improvement_security.png](results/improvement_security.png) | the 11 attacks × 2 modes (detected / not detected) and the keyless eavesdropper on M1–M12 (12 of 12 vs 0 of 12) |
| [improvement_cost.png](results/improvement_cost.png) | K size (2029 → 255 bit), point operations per K·P (≈3065 → ≈380), measured C time per operation, protocol computation per entity vs the 0.4/0.5 ms claim, bits on the wire (16 384 → 8 448 with compressed points), energy per entity |
| [performance_entities.png](results/performance_entities.png) | counted ECC multiplications, hashes, encryptions and decryptions per entity (same in both modes), and energy in both modes with ECC charged per 256 scalar bits, next to the paper's flat model and 48.8 µJ |
| [performance_latency.png](results/performance_latency.png) | transmission and propagation time per hop, end-to-end latency, fallback and mobile re-authentication times |
| [communication_cost.png](results/communication_cost.png) | paper counting model (handshakes + data) vs 2112 and the baselines; plaintext vs on-wire bits per message |
| [latency.png](results/latency.png) | latency vs depth (fan-out 3 and fixed 100 nodes) and vs node count |
| [scyther_claims.png](results/scyther_claims.png) | Scyther result per role and claim type (Secret, Alive, Weakagree, Niagree, Nisynch) |

**Reading the charts** (`results/communication_cost.png`, `results/latency.png`):
* **Communication cost, left panel.** This uses the paper's own counting model, which counts plaintext fields only.
  * Our 8 handshake messages are exactly the paper's 8 × 136 = 1088 bit.
  * Read as 4 × (136 + 136 + 256), the paper's 2112 leaves 4 × 256 = 1024 bit for the four data messages.
  * Ours carry 1632 bit, because M6, M9 and M12 contain real Alerts, GPS and LOGS payloads. The paper gives no
    sizes for those fields.

  So "our model > 2112" comes only from the data payloads, not from the protocol structure.
* **Communication cost, right panel.** This is what PEECC actually transmits. Every block is two curve points
  (C1, C2), even for a 136-bit plaintext.
  * With the paper's 512-bit points a block is 1024 bit, so a 17-byte M1 costs 1024 bit (7.5×) and the whole
    authentication is 16 blocks = 16 384 bit (6×).
  * With compressed points (hardened mode) a block is 528 bit, and the authentication is 8 448 bit (3.1×).

  This overhead is inherent to ElGamal-type encryption; the paper's 2112-bit figure never includes ciphertext
  expansion. The chart shows both modes side by side (from the saved results of each mode).
* **Energy.** The paper charges a flat 24 µJ per ECC operation, which would give the same energy in both modes.
  We charge 24 µJ per 256 scalar bits, because double-and-add work grows linearly with the length of K
  (2029 bits paper-exact, 256 hardened). The flat value is still reported (`energy_flat_uj`).
* **Latency vs depth.**
  * With a constant fan-out of 3, each extra level adds ≈ 4.9 s, which is linear.
  * With a fixed 100 nodes, shallow trees put up to 99 children on one parent's modem, so latency falls with depth.

  Both series are measured.

## 15. Assumptions and paper gaps

| # | Gap or conflict (quote) | Decision |
|---|---|---|
| 1 | IoT IV-A: "pentatope elliptic curve ψ … X³+Y³+Z³+W³+T³ = dXYZWT" with a 5-D generator, but no point arithmetic is given; [18] defines PEECC on an ordinary curve "with parameters a and b" | [18]'s 2-D construction on secp256r1; ψ is not implemented; the 1.3× 5-D overhead is not claimed |
| 2 | IoT VI-A: "512-bit representations for ECC points" | paper-exact: two 256-bit coordinates (uncompressed secp256r1). Hardened: compressed 264-bit points (02/03 ‖ x), a labelled deviation that halves the ciphertext |
| 3 | [18]: the message "has a point M", no mapping given | Koblitz encoding, 0x01 marker, κ = 256, 29 bytes per block; longer messages split into blocks |
| 4 | [18] Sec. 3.2: K from "the x value of generator point" → K is public | paper-exact is the default; `--hardened` randomises the pentatope input (labelled deviation) |
| 5 | IoT VI-A: "8-bit timestamps" | 50 ms ticks, wrap after 12.8 s; ΔT stays below the wrap. A delay of exactly one wrap is **not** detected (section 14) |
| 6 | IoT V: "an adaptive ΔT … rolling average of recent internode delays" (no formula) | ΔT = clamp(2·avg(last 8 accepted delays) + 1 s, 1 s, 6 s), initial 2 s |
| 7 | IoT IV-B Step 3: "If ϑj [?] ϑi, then Mi is INVALID" (the relation symbol is not legible in the PDF's text layer) | read as ϑj ≠ ϑi → INVALID |
| 8 | IoT IV-B: ϑi = H(RIDi‖PUi) uses no secret, so anyone can produce a valid registration | registrations are also checked against the BS-distributed directory (IV-E-3); without it a rogue registration is accepted |
| 9 | IoT IV-C: M3 = E{PU_SUB, **ID_SUB**‖…} carries the receiver's ID, and M1 carries nothing only the sender can make | implemented literally; consequence: initiator impersonation (attack table, Scyther) |
| 10 | IoT VI-A gives sizes only for ID, nonce, TS, hash and point; no sizes for ENV, Alerts, GPS, LOGS; 2112 bit given only as a total | ENV = 4 × float32, GPS = 2 × float32, Alerts/LOGS = length-prefixed text; derived candidate 4 × (136 + 136 + 256) = 2112 is flagged as derived |
| 11 | IoT IV-A: ID_i = H(PU_i‖E) vs IV-E-3: ID_i = H(PU_i‖E‖DeviceSerial) | the IV-E-3 form, truncated to the paper's 64-bit identity |
| 12 | IoT VI-A: "hierarchical tree topology with 10 to 200 nodes, spanning 2 to 5 depth levels" (no fan-out, no MAC model) | levels ending at BS (depth 2 = UWS–BS … depth 5 = full chain), one modem per parent serving children sequentially |
| 13 | IoT IV-E-2: RL "authenticated using a management key" | HMAC-SHA-256 under a shared management key |
| 14 | IoT VI-C energy: "1 ECC … 2 encryption and 2 decryption (AES-128)" while every message is PEECC-encrypted | same per-operation energies, applied to the operations actually counted |
