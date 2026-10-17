# PEECC explained from zero: every function, every decision

Everything here refers to [peecc.c](peecc.c). Read it top to bottom once; each section matches a part of the file.

---

## 1. What are we building, in one paragraph

We want **public-key encryption**: anyone can lock a message with my *public key*, only I can unlock it with my
*private key*. The paper [18] ("PEECC") does this with **elliptic curves**, with one special idea: the secret number
used while encrypting (`K`) is not random but is **calculated** from a "pentatope number". Our program
implements exactly that, nothing more: generate keys, encrypt, decrypt, and prove with tests that it works.

```
        receiver                                      sender
 private key d  --(d x B)-->  public key Pub  ------>  uses Pub + K to make (C1, C2)
        ^                                                    |
        |__________ decrypt: Pm = C2 - d x C1  <-------------+
```

---

## 2. The maths, slowly

### 2.1 Modular arithmetic ("clock arithmetic")
`a mod p` is the remainder after dividing by `p`. On a 12-hour clock, 10 + 5 = 3. We do all arithmetic modulo a
huge prime `p` (about 2^256, a 78-digit number), so numbers never grow unbounded.
* Add, subtract, multiply: do it, then take `mod p`.
* **Division** does not exist directly. Instead we multiply by the **modular inverse**: `a^-1` is the number with
  `a * a^-1 = 1 (mod p)`. Example mod 17: the inverse of 2 is 9, because 2*9 = 18 = 1.

### 2.2 The elliptic curve
A set of points `(x, y)` with `y^2 = x^3 + a*x + b (mod p)`. We use the standard curve **secp256r1**, which fixes
`p`, `a` (= -3), `b`, a starting point **B** (the "generator") and `N`, the number of times you can add B to itself
before you return to the start (the "order").

### 2.3 Adding points (a toy you can verify by hand)
Take the tiny curve `y^2 = x^3 + 2x + 2 (mod 17)` with `B = (5, 1)`.

*Doubling* `B + B`: slope `s = (3x^2 + a) / (2y) = (3*25+2)/2 = 77/2`. Mod 17: `77 = 9`, inverse of 2 is 9, so `s = 81 = 13`.
Then `x3 = s^2 - 2x = 169 - 10 = 159 = 6` and `y3 = s(x - x3) - y = 13(5-6) - 1 = -14 = 3`. So **2B = (6, 3)**.

*Adding different points* `B + 2B = (5,1) + (6,3)`: slope `s = (3-1)/(6-5) = 2`,
`x3 = 4 - 5 - 6 = -7 = 10`, `y3 = 2(5-10) - 1 = -11 = 6`. So **3B = (10, 6)**.

The real program does exactly these formulas, only with 256-bit numbers.

### 2.4 Scalar multiplication `k * P`
Add `P` to itself `k` times. With `k` around 2^256 we cannot loop that long, so we use **double-and-add**: read the
binary digits of `k` from the left; for each digit, *double* the running total, and if the digit is 1, *add* `P`.
Example `k = 13 = 1101` in binary: start 0 → bit 1: double(0)+P = P → bit 1: 2P+P = 3P → bit 0: 6P → bit 1: 12P+P = 13P.
About 256 doublings + 128 additions instead of 2^256 steps.

### 2.5 Why this is public-key crypto
* Private key `d` = a random big number.
* Public key `Pub = d * B`.
* Computing `Pub` from `d` is quick (double-and-add). Computing `d` back from `Pub` is believed to be impossible with
  today's computers (**discrete logarithm problem**). So publishing `Pub` is safe.

### 2.6 The PEECC formulas of [18]

| Step | Formula | Paper location |
|---|---|---|
| Key generation | `d` random in `[1, N-1]`, `Pub = d * B` | Sec. 3.1 |
| Pentatope number | `S = x(x+1)(x+2)(x+3) / 24`, with `x` = x-coordinate of B | Sec. 3.2 Step 2 |
| Euler key | `K = S^2 + S + 41` | Sec. 3.2 Step 3 |
| Ciphertext | `C1 = K * B`, `C2 = Pm + K * Pub` | Sec. 3.2 Step 4 |
| Decryption | `Pm = C2 - d * C1` | Sec. 3.3 |

Why decryption works: `d * C1 = d * (K * B) = K * (d * B) = K * Pub`. So `C2 - d*C1 = Pm + K*Pub - K*Pub = Pm`. ✔

*The pentatope number* is the 5th diagonal of Pascal's triangle. Hand check: `x = 2` gives `2*3*4*5/24 = 120/24 = 5`;
`x = 3` gives `3*4*5*6/24 = 15`; `x = 1` gives `1*2*3*4/24 = 1`. Then `K(S=5) = 25 + 5 + 41 = 71`.

### 2.7 Turning text into a point (Koblitz)
The formulas encrypt a **point** `Pm`, but we want to encrypt text. Koblitz's method:
1. Turn the message into a number `m`.
2. Try `x = m*256 + j` for `j = 0, 1, 2, ...`. About half of all x values have a matching `y` (when
   `x^3 + ax + b` is a perfect square mod p). The first `j` that works gives the point `(x, y)`.
3. To go back: `m = x divided by 256` (throw the remainder `j` away).

---

## 3. Walkthrough of `peecc.c`, function by function

### 3.1 Header, includes, constants

```c
#define _CRT_RAND_S        // Windows: enables the secure random function rand_s
#include <gmp.h>           // GMP: big-integer library
#define MAX_MSG 29
#define KAPPA 256
typedef struct { mpz_t x, y; int inf; } Pt;
```
* **GMP / `mpz_t`**: normal C integers are 64-bit; we need 256+ bits. `mpz_t` is GMP's arbitrary-size integer. Every `mpz_`
  variable must be `mpz_init`-ed before use and `mpz_clear`-ed after (otherwise memory leaks).
* **`Pt`** = a curve point. `inf = 1` means the **point at infinity**, the "zero" of point addition (`P + inf = P`). It is
  needed for cases like `P + (-P)`, which equals infinity.
* **`MAX_MSG = 29`**: the x-coordinate must stay below `p` (256 bits). We store `0x01 + message` (see 3.7) times 256, so
  `(1 + 29 bytes) * 8 + 8 = 248 bits < 256`. Thirty bytes could overflow, so 29 is the largest safe size.
* **`KAPPA = 256`**: Koblitz's trial count. Each `j` works with chance ~1/2, so failing all 256 tries has chance 2^-256 (never).

Globals: `P` (prime), `A`, `Bc` (curve `a` and `b`; named `Bc` so it does not clash with the generator `B`), `N` (order), `G` (generator B).

### 3.2 `os_random(buf, n)`: secure random bytes
Fills a buffer with random bytes from the operating system (`rand_s` on Windows, `/dev/urandom` on Linux/Mac).
**Why not C's `rand()`?** `rand()` is predictable; anyone who guesses its state recovers your private key. The OS generator is
designed for cryptography. If it fails, the program stops instead of continuing with a weak key.

### 3.3 `random_private_key(d)`: key in `[1, N-1]`
[18] Sec. 3.1 Step 1 requires a private key between 1 and N-1. Steps: take 48 random bytes (384 bits), convert to an integer,
reduce `mod (N-1)`, add 1 → range `[1, N-1]`. **Why 384 bits when N is 256 bits?** Reducing a number that is only slightly larger than N
would favor small values slightly ("modulo bias"). With 128 extra bits the bias is about 2^-128, negligible.

### 3.4 Field arithmetic: `fp_add`, `fp_sub`, `fp_mul`, `fp_inv`
Each does the GMP operation then `mod P` (`mpz_mod` always returns a non-negative result, so subtraction is safe).
`fp_inv` uses `mpz_invert`, the modular inverse from 2.1. These four are the only arithmetic every other function uses; keeping them tiny
makes the rest readable and easy to check.

### 3.5 Point functions

* **`pt_init / pt_clear / pt_set`**: allocate, free, copy a point.
* **`pt_on_curve(q)`**: checks `y^2 == x^3 + a*x + b (mod p)`. Used in tests to be sure our maths really produces curve points.
* **`pt_double(r, q)`**: the doubling formula of 2.3. Returns infinity if `q` is infinity or `y = 0` (the tangent is vertical).
* **`pt_add(r, a, b)`**: the addition formula of 2.3, with the special cases: either point is infinity (return the other);
  same `x` and same `y` (it is a doubling, call `pt_double`); same `x` but different `y` (`P + (-P)`, result infinity).
  *Why the special cases:* the slope formula divides by `x2 - x1`, which is 0 in those cases.
* **`pt_neg(r, q)`**: `(x, y) -> (x, p - y)`. Needed because subtraction is "add the negative" (decryption).
* **`pt_mul(r, k, q)`**: double-and-add from 2.4. It loops from the highest bit of `k` to the lowest (`mpz_sizeinbase`, `mpz_tstbit`).
  The accumulator starts as infinity so the first doubling is harmless.
* **`pt_equal`**: compares two points (used by tests).
* **`setup_curve()`**: loads the secp256r1 constants from hexadecimal strings: `p`, `b`, `N`, and B's coordinates; `a = p - 3`
  (the same as -3 mod p).

### 3.6 `pentatope(s, x)` and `euler_K(k, s)`
`pentatope` computes `x(x+1)(x+2)(x+3)/24`. Division by 24 is safe with `mpz_divexact_ui` because the product of 4 consecutive integers
is always divisible by 24 (it is 24 times a binomial coefficient). `euler_K` computes `s*s + s + 41`.
Both use full big-integer arithmetic **with no modulo**, exactly as the paper writes it ("as big integers").
Because `x` is B's 256-bit x-coordinate, `S` has about 1015 bits and `K` about 2029 bits.

### 3.7 `koblitz_encode` and `koblitz_decode`
`koblitz_encode(out, data, len)`:
1. Build the bytes `0x01, data...` (a marker byte first).
2. `m` = that as a number, times 256.
3. For `j = 0..255`: `x = m + j`; compute `rhs = x^3 + ax + b mod p`; compute a candidate `y = rhs^((p+1)/4) mod p`; if `y^2 == rhs`, we found a valid point.

*Why `(p+1)/4`?* For primes with `p ≡ 3 (mod 4)` (secp256r1 is one), the square root of a perfect square `rhs` is `rhs^((p+1)/4)`. It is one exponentiation
(`mpz_powm`) instead of a complicated algorithm. If `rhs` is not a perfect square, squaring the candidate does not give `rhs`, which is how we detect failure.

*Why the `0x01` marker byte?* Numbers forget leading zeros: the messages `"\0A"` and `"A"` would become the same number. With a leading 1 the
length is preserved, and decoding simply drops the first byte.

`koblitz_decode(data, q)`: `m = x / 256` (`mpz_fdiv_q_ui` drops `j`), export to bytes, check the first byte is `0x01` and the size is sane, return
the rest. It returns -1 for infinity or invalid structure. (A correct decryption always passes; a wrong key would give a random point that
almost never has this structure.)

### 3.8 The three PEECC operations

```c
static void keygen(mpz_t d, Pt *pub)                       // Sec. 3.1
static void encrypt(Pt *c1, Pt *c2, const Pt *pm, const Pt *pub)   // Sec. 3.2
static void decrypt(Pt *pm, const Pt *c1, const Pt *c2, const mpz_t d)  // Sec. 3.3
```
* **`keygen`**: random `d`, then `Pub = d * B` with `pt_mul`.
* **`encrypt`**: `S = pentatope(Bx)`, `K = euler_K(S)`, `C1 = K*B`, `t = K*Pub`, `C2 = Pm + t`. Two scalar multiplications.
* **`decrypt`**: `t = d*C1`, negate it, `Pm = C2 + (-t)`. One scalar multiplication.

Each is a few lines and mirrors the paper's steps so you can compare them line by line with the PDF.

### 3.9 Printing helpers and `demo(text)`
`show` / `show_pt` print numbers in hexadecimal (`gmp_printf` with `%Zx`). `demo` runs the whole story for one message:
make keys → Koblitz-encode text → compute S, K → encrypt → decrypt → decode → print `MATCH` or `MISMATCH`.
It exists so that **you can see** each intermediate value instead of just trusting a test result.

### 3.10 `test()`: how we verify correctness
| Test | What it proves |
|---|---|
| Generator is on the curve | constants typed correctly |
| `2*B` equals the published secp256r1 value | point doubling and scalar multiplication are right (an independent, outside reference) |
| `N * B = infinity` | the order `N` and the group arithmetic are consistent |
| 50 random public keys on the curve | keygen produces real curve points |
| `Pub = d * B` | the public key really equals private × B |
| `(a+b)*B = a*B + b*B` | scalar multiplication behaves like real multiplication |
| `S(1)=1, S(2)=5, S(3)=15` | the pentatope function matches hand calculation |
| `K(1)=43, K(5)=71, K(15)=281` | the Euler formula matches hand calculation |
| 1000 random messages round-trip | encrypt then decrypt returns the original (random lengths 0 to 29 bytes) |

The `CHECK` macro prints PASS/FAIL and counts failures; `main` returns a non-zero exit code if anything failed.

### 3.11 `main`
Calls `setup_curve()`. With `--test` it runs the tests; otherwise it runs the demo on the text you pass (default `"hello PEECC"`).

---

## 4. Decisions we took, and why

| # | Decision | Reason |
|---|---|---|
| 1 | Implement PEECC from **[18]** on an ordinary 2-D curve, not the IoT paper's 5-D curve ψ | [18] defines PEECC on a 2-D curve with `a, b, p, B(x,y)`; the IoT paper only *mentions* a 5-D curve without usable formulas. |
| 2 | Use **secp256r1** | You specified it. It is a well-studied standard curve with published constants, so we can test against known values. |
| 3 | A "512-bit point" = two 256-bit coordinates | The IoT paper counts 512 bits per point; 2 × 256 = 512, consistent. |
| 4 | **Koblitz** method for text → point | [18] says "the message has a point M" but never says how. Koblitz is the classical choice. |
| 5 | Marker byte `0x01`, `KAPPA = 256`, 29-byte limit | Keeps length and leading zeros; makes failure probability 2^-256; keeps `x < p`. |
| 6 | One block only (≤ 29 bytes) | You asked for the smallest thing you can verify. Longer messages can be split into blocks later. |
| 7 | `S` and `K` kept as full big integers, **not** reduced mod N | Literal to the paper ("as big integers"). (It would give the same point faster; we chose clarity over speed. 1 scalar multiplication costs about 1 ms either way.) |
| 8 | **Paper-exact** `K` only | You asked to implement the PEECC algorithm itself first. |
| 9 | GMP for big numbers; affine coordinates | GMP is the standard C big-number library. Affine coordinates need a modular inverse per step (slower than projective) but are the simplest and match the textbook formulas. |
| 10 | Double-and-add | Required by your spec; simple and correct. |
| 11 | OS randomness, 384 bits reduced into `[1, N-1]` | Security of the private key; avoids bias. |
| 12 | Tests inside `peecc.c` (`--test`) and a demo (`run`) | One file, minimal moving parts; you can verify everything yourself. |
| 13 | Link GMP statically on Windows | The `.exe` runs without extra DLLs. |

---

## 5. Important limits you should know (honest notes)

1. **The K weakness.** `K` comes only from the *public* generator `B`. Anyone can compute `K` and then `Pm = C2 - K*Pub`
   **without any private key**. Also `C1 = K*B` is identical for every message (run the demo twice: `C1` never changes).
   So paper-exact PEECC does **not** keep messages secret. We implemented it faithfully on purpose; a secure variant would use a fresh
   random number per message. We can add that later as a clearly labelled option.
2. **Educational code.** The arithmetic is not constant-time, so it is not safe against timing side-channel attacks. It is for learning and
   verification, not for production.
3. **29-byte messages.** Larger messages need splitting.
4. **Unused leftover:** in `encrypt`, the variable `kp` is created and freed but never used (harmless, can be removed).

---

## 6. How you can verify everything yourself

```
make test                     # 13 checks, all should say PASS
make run                      # shows every value of one encrypt/decrypt
./peecc.exe "any text"        # try your own message (max 29 bytes); run twice and watch C1 stay the same
```
Things to try:
1. Run `make run` twice: the keys change (random) but `C1` is **identical**; that is limit #1 in action.
2. Check by hand that `S(2) = 5` and `K(5) = 71` (section 2.6), then see the same values pass in `make test`.
3. Do the toy-curve example in 2.3 with a pencil; then read `pt_double` and `pt_add` and see the same formulas.
