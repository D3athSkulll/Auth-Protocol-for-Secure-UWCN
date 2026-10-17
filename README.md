# PEECC: Pentatope-Based Elliptic Curve Cryptography in C

A small, self-contained C implementation of the **PEECC** public-key encryption scheme of

> D. Jayakumari, C. Rupa, V. Nikhila, *"Pentatope Based Elliptic Curve Encryption for Privacy and Protection of Multimedia Data"* (reference **[18]**, `PEECC Base.pdf`),

which is the cryptosystem used by the IEEE IoT-J paper *"A Novel and Robust Authentication Protocol for Secure Underwater Communication Systems"* (`A_Novel_and_Robust_...pdf`).
This repository currently contains **only the cryptographic core** (key generation, encryption, decryption, tests). The authentication protocol built on top of it is the next step.

---

## 1. Repository contents

| File | Purpose |
|---|---|
| [peecc.c](peecc.c) | The whole implementation (≈ 300 lines, GMP big integers) with a demo and self-tests |
| [Makefile](Makefile) | `make`, `make run`, `make test`, `make clean` |
| [PEECC_EXPLAINED.md](PEECC_EXPLAINED.md) | Beginner-level tutorial (maths from scratch) |
| `PEECC Base.pdf`, `A_Novel_and_Robust_...pdf` | The two source papers |
| `prompt.md`, `scyther/`, `uwc_protocol.spdl`, `launch_scyther_gui.bat` | Task description and Scyther material from the original repo (not used by the current code) |

`peecc.exe` is a build product (`make clean` removes it).

## 2. Build and run

Requirements: `gcc` and the GMP library (Windows: MSYS2 `mingw64`, `pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gmp make`).

```bash
make test                 # run the 13 self-tests
make run                  # encrypt + decrypt "hello PEECC", printing every intermediate value
./peecc.exe "my text"     # your own message (at most 29 bytes)
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

---

## 5. Code map: which part of `peecc.c` does what

| Lines | Function / block | What it does | Math / paper reference |
|---|---|---|---|
| 25-31 | constants, `Pt`, globals | `MAX_MSG=29`, `KAPPA=256`; `Pt` = point `(x,y)` + `inf` flag; globals `P, A, Bc, N, G` | §4.1-4.3 |
| 35 | `os_random` | Secure random bytes from the OS (`rand_s` / `/dev/urandom`) | needed for private keys |
| 50 | `random_private_key` | 384 random bits reduced into $[1,N-1]$ (extra bits ⇒ negligible bias) | [18] 3.1 Step 1 |
| 60-63 | `fp_add/sub/mul/inv` | $\mathbb F_p$ arithmetic; inverse by `mpz_invert` | §4.1 |
| 66-68 | `pt_init/clear/set` | allocate / free / copy a point (GMP needs explicit memory handling) | – |
| 71 | `pt_on_curve` | checks $y^2\equiv x^3+ax+b$ | §4.2 |
| 82 | `pt_double` | doubling formula, handles $y=0$ | §4.3 |
| 94 | `pt_add` | addition formula + special cases ($\mathcal O$, $P=Q$, $P=-Q$) | §4.3 |
| 110 | `pt_neg` | $(x,y)\mapsto(x,p-y)$ | §4.3 |
| 116 | `pt_mul` | double-and-add scalar multiplication | §4.4 |
| 125 | `pt_equal` | point comparison (used by tests) | – |
| 131 | `setup_curve` | loads secp256r1 constants, sets $a=p-3$ | §4.2 |
| 144 | `pentatope` | $S=x(x+1)(x+2)(x+3)/24$ with `mpz_divexact_ui` | [18] 3.2 Step 2 |
| 154 | `euler_K` | $K=S^2+S+41$ | [18] 3.2 Step 3 |
| 161 | `koblitz_encode` | bytes → point | §4.6a |
| 181 | `koblitz_decode` | point → bytes (returns −1 if invalid structure) | §4.6a |
| 193 | `keygen` | random $d$, $Pub=d\cdot B$ | [18] 3.1 |
| 196 | `encrypt` | $S,K$ from $B_x$; $C_1=K B$; $C_2=P_m+K\,Pub$ | [18] 3.2 |
| 207 | `decrypt` | $P_m=C_2-dC_1$ | [18] 3.3 |
| 215-250 | `show`, `show_pt`, `demo` | prints every step for one message | – |
| 253-311 | `CHECK`, `test` | self-tests (section 6) | – |
| 313 | `main` | `--test` → tests, otherwise demo | – |

**Layering** (each layer uses only the one above it in the list):

```
 field arithmetic (fp_*)  →  point group (pt_*)  →  scalar multiplication (pt_mul)
                                                        ↓
              Koblitz mapping + pentatope/K  →  keygen / encrypt / decrypt  →  demo / test
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

Current result: **all 13 checks pass**.

### Sample demo output (abridged, values vary per run except C1)
```
== Key generation (receiver) ==   private key d = 20e2e5...18d6 ;  Pub = d*B on curve: yes
== Encryption ==    message "hello PEECC" (11 bytes) -> Pm (Koblitz)
   S = Pentatope(Bx) (~1015 bits)   K = S^2+S+41 (2029 bits)
   C1 = K*B :  x = 681dc23639d030c4...      C2 = Pm + K*Pub
== Decryption ==    Pm' = C2 - d*C1   ->  decoded message: "hello PEECC"   result: MATCH
```

---

## 7. Design decisions and why

| Decision | Reason |
|---|---|
| Implement **[18]'s 2-D curve PEECC**, not the IoT paper's 5-D curve ψ | [18] gives usable formulas on an ordinary curve; the IoT paper only mentions a 5-D group without arithmetic (documented conflict) |
| secp256r1 | specified requirement; standard constants allow testing against published values |
| "512-bit ECC point" = two 256-bit coordinates | 2 × 256 = 512, consistent with the IoT paper's field size |
| Koblitz mapping | [18] says the message "has a point M" but never says how |
| `0x01` marker, $\kappa=256$, 29-byte limit | keeps leading zeros/length; failure probability $2^{-256}$; keeps $x<p$ |
| One block only | smallest verifiable unit; splitting into blocks is a later extension |
| $S,K$ kept as full big integers | literal to the paper ("as big integers"); speed difference is negligible here |
| GMP, affine coordinates, double-and-add | standard big-number library; textbook formulas that map directly to the maths above |
| OS randomness, 384 bits → $[1,N-1]$ | secure private keys, negligible modulo bias |
| Tests and demo inside the same file | one file, easy to verify and present |

---

## 8. Known limitations (important to state honestly)

1. **The weakness of PEECC [18].** $K$ is derived only from the *public* generator, so anyone can compute
   $$P_m = C_2 - K\cdot Pub$$
   **without the private key**, and $C_1=K\cdot B$ is identical for every message (visible: run the demo twice; $C_1$ never changes). This implementation is *paper-exact* on purpose. A secure variant replaces $K$ by a fresh random number $r$ per message (i.e. ElGamal); this is a possible next step.
2. Educational code: not constant-time, hence not side-channel safe.
3. Messages are limited to 29 bytes (one curve point).
4. Minor leftover: an unused variable `kp` in `encrypt` (harmless).

## 9. Next steps (not yet implemented)
Multi-block messages, an optional hardened mode, then the 5-entity authentication protocol (initialization, registration, mutual authentication M1-M12, fallback) and its Scyther verification.
