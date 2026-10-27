/*
 * peecc.c - Pentatope-based Elliptic Curve Cryptography (PEECC), reference [18]:
 *   Jayakumari, Rupa, Nikhila, "Pentatope Based Elliptic Curve Encryption for Privacy
 *   and Protection of Multimedia Data" (PEECC Base.pdf).
 *
 * Curve: y^2 = x^3 + a x + b over F_p, secp256r1 parameters. GMP big integers.
 *
 *   [18] Sec. 3.1 key generation : private d in [1, N-1], public Pub = d * B
 *   [18] Sec. 3.2 encryption     : S  = Pentatope(x of B) = x(x+1)(x+2)(x+3)/24
 *                                  K  = S^2 + S + 41
 *                                  C1 = K * B,   C2 = Pm + K * Pub_receiver
 *   [18] Sec. 3.3 decryption     : Pm = C2 - d * C1
 *   Message -> curve point       : Koblitz method (the paper does not specify one)
 *
 * Two modes:
 *   paper-exact (default)        : x = Bx exactly as in [18]. K is public, so anyone can decrypt.
 *   hardened (DEVIATION from [18]): x = fresh secret random number per message, K = (S^2+S+41) mod N,
 *                                  and all received points are validated. Pentatope and Euler steps are kept.
 *
 * Usage:  peecc "my message"              paper-exact: encrypt + decrypt (<= 29 bytes), printing every step
 *         peecc --hardened "my message"   the same in hardened mode
 *         peecc --test                    run the self-tests (both modes)
 *
 * Built with -DPEECC_LIB as a shared library (make lib) it exports the peecc_* API at the end of the file,
 * used by protocol.py through ctypes. Messages longer than 29 bytes are split into blocks there.
 */
#define _CRT_RAND_S
#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#define MAX_MSG 29      /* message bytes that fit in one curve point */
#define KAPPA 256       /* Koblitz: x = m*KAPPA + j, j = 0..KAPPA-1  */

typedef struct { mpz_t x, y; int inf; } Pt;      /* inf = 1 means the point at infinity */

static mpz_t P, A, Bc, N;                         /* prime, curve a, curve b, group order */
static Pt G;                                      /* generator B(x, y) */

/* ---------------------------------------------------------------- randomness */
/* Fill buf with n secure random bytes from the operating system. */
static void os_random(uint8_t *buf, size_t n) {
#ifdef _WIN32
    for (size_t i = 0; i < n; i += 4) {
        unsigned int v;
        if (rand_s(&v)) { fprintf(stderr, "rand_s failed\n"); exit(1); }
        for (size_t j = 0; j < 4 && i + j < n; j++) buf[i + j] = (uint8_t)(v >> (8 * j));
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, n, f) != n) { fprintf(stderr, "urandom failed\n"); exit(1); }
    fclose(f);
#endif
}

/* [18] Sec. 3.1 Step 1: random private key in [1, N-1]. */
static void random_private_key(mpz_t d) {
    uint8_t buf[48];                              /* 384 bits -> negligible modulo bias */
    os_random(buf, sizeof buf);
    mpz_import(d, sizeof buf, 1, 1, 1, 0, buf);
    mpz_t nm1; mpz_init(nm1); mpz_sub_ui(nm1, N, 1);
    mpz_mod(d, d, nm1); mpz_add_ui(d, d, 1);
    mpz_clear(nm1);
}

/* ---------------------------------------------------------------- field arithmetic mod p */
static void fp_add(mpz_t r, const mpz_t a, const mpz_t b) { mpz_add(r, a, b); mpz_mod(r, r, P); }
static void fp_sub(mpz_t r, const mpz_t a, const mpz_t b) { mpz_sub(r, a, b); mpz_mod(r, r, P); }
static void fp_mul(mpz_t r, const mpz_t a, const mpz_t b) { mpz_mul(r, a, b); mpz_mod(r, r, P); }
static void fp_inv(mpz_t r, const mpz_t a)                { mpz_invert(r, a, P); }

/* ---------------------------------------------------------------- curve points */
static void pt_init(Pt *q)  { mpz_init(q->x); mpz_init(q->y); q->inf = 1; }
static void pt_clear(Pt *q) { mpz_clear(q->x); mpz_clear(q->y); }
static void pt_set(Pt *r, const Pt *q) { mpz_set(r->x, q->x); mpz_set(r->y, q->y); r->inf = q->inf; }

/* Is the point on the curve?  y^2 == x^3 + a x + b (mod p). */
static int pt_on_curve(const Pt *q) {
    if (q->inf) return 1;
    mpz_t l, r; mpz_init(l); mpz_init(r);
    fp_mul(l, q->y, q->y);
    fp_mul(r, q->x, q->x); fp_add(r, r, A); fp_mul(r, r, q->x); fp_add(r, r, Bc);
    int ok = mpz_cmp(l, r) == 0;
    mpz_clear(l); mpz_clear(r);
    return ok;
}

/* Point doubling: slope = (3x^2 + a) / (2y). */
static void pt_double(Pt *r, const Pt *q) {
    if (q->inf || mpz_sgn(q->y) == 0) { r->inf = 1; return; }
    mpz_t s, t, x3, y3; mpz_init(s); mpz_init(t); mpz_init(x3); mpz_init(y3);
    fp_mul(t, q->x, q->x); mpz_mul_ui(t, t, 3); fp_add(t, t, A);
    fp_add(s, q->y, q->y); fp_inv(s, s); fp_mul(s, s, t);
    fp_mul(x3, s, s); fp_sub(x3, x3, q->x); fp_sub(x3, x3, q->x);
    fp_sub(y3, q->x, x3); fp_mul(y3, y3, s); fp_sub(y3, y3, q->y);
    mpz_set(r->x, x3); mpz_set(r->y, y3); r->inf = 0;
    mpz_clear(s); mpz_clear(t); mpz_clear(x3); mpz_clear(y3);
}

/* Point addition: slope = (y2 - y1) / (x2 - x1); special cases for infinity, P+P and P+(-P). */
static void pt_add(Pt *r, const Pt *a, const Pt *b) {
    if (a->inf) { pt_set(r, b); return; }
    if (b->inf) { pt_set(r, a); return; }
    if (mpz_cmp(a->x, b->x) == 0) {
        if (mpz_cmp(a->y, b->y) == 0) { pt_double(r, a); return; }
        r->inf = 1; return;
    }
    mpz_t s, t, x3, y3; mpz_init(s); mpz_init(t); mpz_init(x3); mpz_init(y3);
    fp_sub(t, b->y, a->y); fp_sub(s, b->x, a->x); fp_inv(s, s); fp_mul(s, s, t);
    fp_mul(x3, s, s); fp_sub(x3, x3, a->x); fp_sub(x3, x3, b->x);
    fp_sub(y3, a->x, x3); fp_mul(y3, y3, s); fp_sub(y3, y3, a->y);
    mpz_set(r->x, x3); mpz_set(r->y, y3); r->inf = 0;
    mpz_clear(s); mpz_clear(t); mpz_clear(x3); mpz_clear(y3);
}

/* Negation: (x, y) -> (x, -y). */
static void pt_neg(Pt *r, const Pt *q) {
    pt_set(r, q);
    if (!r->inf && mpz_sgn(r->y)) mpz_sub(r->y, P, r->y);
}

/* Double-and-add scalar multiplication r = k * q (scan k from its top bit down). */
static void pt_mul(Pt *r, const mpz_t k, const Pt *q) {
    Pt acc, base; pt_init(&acc); pt_init(&base); pt_set(&base, q);
    for (long i = (long)mpz_sizeinbase(k, 2) - 1; i >= 0; i--) {
        pt_double(&acc, &acc);
        if (mpz_tstbit(k, i)) pt_add(&acc, &acc, &base);
    }
    pt_set(r, &acc); pt_clear(&acc); pt_clear(&base);
}

#ifndef PEECC_LIB                                 /* used by the self-tests only */
static int pt_equal(const Pt *a, const Pt *b) {
    if (a->inf || b->inf) return a->inf == b->inf;
    return mpz_cmp(a->x, b->x) == 0 && mpz_cmp(a->y, b->y) == 0;
}
#endif

/* Hardened mode (DEVIATION from [18]): a received point must be finite, have coordinates in [0, p-1]
 * and lie on the curve. secp256r1 has cofactor 1, so this also puts it in the group generated by B. */
static int pt_valid(const Pt *q) {
    return !q->inf && mpz_sgn(q->x) >= 0 && mpz_cmp(q->x, P) < 0
                   && mpz_sgn(q->y) >= 0 && mpz_cmp(q->y, P) < 0 && pt_on_curve(q);
}

/* Load the secp256r1 domain parameters and the generator B. */
static void setup_curve(void) {
    mpz_init_set_str(P,  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    mpz_init(A); mpz_sub_ui(A, P, 3);                                   /* a = -3 */
    mpz_init_set_str(Bc, "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    mpz_init_set_str(N,  "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    pt_init(&G);
    mpz_set_str(G.x, "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    mpz_set_str(G.y, "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
    G.inf = 0;
}

/* ---------------------------------------------------------------- pentatope number and K */
/* [18] Sec. 3.2 Step 2: S = x(x+1)(x+2)(x+3)/24 (the division is always exact). */
static void pentatope(mpz_t s, const mpz_t x) {
    mpz_t t; mpz_init(t);
    mpz_add_ui(t, x, 1); mpz_mul(s, x, t);
    mpz_add_ui(t, x, 2); mpz_mul(s, s, t);
    mpz_add_ui(t, x, 3); mpz_mul(s, s, t);
    mpz_divexact_ui(s, s, 24);
    mpz_clear(t);
}

/* [18] Sec. 3.2 Step 3: K = S^2 + S + 41. */
static void euler_K(mpz_t k, const mpz_t s) {
    mpz_mul(k, s, s); mpz_add(k, k, s); mpz_add_ui(k, k, 41);
}

/* ---------------------------------------------------------------- Koblitz message mapping */
/* Bytes -> point. m = 0x01||data (the 0x01 keeps the length and leading zeros),
 * x = m*KAPPA + j for the first j where x^3+ax+b has a square root (p = 3 mod 4: y = rhs^((p+1)/4)). */
static int koblitz_encode(Pt *out, const uint8_t *data, size_t len) {
    if (len > MAX_MSG) return 0;
    uint8_t buf[MAX_MSG + 1]; buf[0] = 1; memcpy(buf + 1, data, len);
    mpz_t m, x, rhs, y, e, chk; mpz_init(m); mpz_init(x); mpz_init(rhs); mpz_init(y); mpz_init(e); mpz_init(chk);
    mpz_import(m, len + 1, 1, 1, 1, 0, buf);
    mpz_mul_ui(m, m, KAPPA);
    mpz_add_ui(e, P, 1); mpz_fdiv_q_2exp(e, e, 2);
    int ok = 0;
    for (unsigned j = 0; j < KAPPA && !ok; j++) {
        mpz_add_ui(x, m, j);
        fp_mul(rhs, x, x); fp_add(rhs, rhs, A); fp_mul(rhs, rhs, x); fp_add(rhs, rhs, Bc);
        mpz_powm(y, rhs, e, P);
        fp_mul(chk, y, y);
        if (mpz_cmp(chk, rhs) == 0) { mpz_set(out->x, x); mpz_set(out->y, y); out->inf = 0; ok = 1; }
    }
    mpz_clear(m); mpz_clear(x); mpz_clear(rhs); mpz_clear(y); mpz_clear(e); mpz_clear(chk);
    return ok;
}

/* Point -> bytes: m = floor(x / KAPPA), drop the 0x01 marker. Returns the length, or -1 if invalid. */
static int koblitz_decode(uint8_t *data, const Pt *q) {
    if (q->inf) return -1;
    mpz_t m; mpz_init(m); mpz_fdiv_q_ui(m, q->x, KAPPA);
    uint8_t buf[64]; size_t cnt = 0; mpz_export(buf, &cnt, 1, 1, 1, 0, m);
    mpz_clear(m);
    if (cnt < 1 || cnt > MAX_MSG + 1 || buf[0] != 1) return -1;
    memcpy(data, buf + 1, cnt - 1);
    return (int)(cnt - 1);
}

/* ---------------------------------------------------------------- PEECC ([18] Sec. 3) */
/* Sec. 3.1: private key d (random), public key Pub = d * B. */
static void keygen(mpz_t d, Pt *pub) { random_private_key(d); pt_mul(pub, d, &G); }

/* Sec. 3.2 Steps 2-3: the multiplier K, returned together with the pentatope input x and S.
 *   paper-exact: x = Bx, K = S^2+S+41 as big integers (the same public value for every message)
 *   hardened   : DEVIATION from [18], x = fresh secret random in [1, N-1], K = (S^2+S+41) mod N */
static void make_K(mpz_t k, mpz_t x, mpz_t s, int hardened) {
    do {
        if (hardened) random_private_key(x); else mpz_set(x, G.x);
        pentatope(s, x); euler_K(k, s);
        if (hardened) mpz_mod(k, k, N);
    } while (mpz_sgn(k) == 0);                    /* K = 0 mod N only in hardened mode, probability ~2^-256 */
}

/* Sec. 3.2 Step 4: C1 = K*B, C2 = Pm + K*Pub. */
static void encrypt_K(Pt *c1, Pt *c2, const Pt *pm, const Pt *pub, const mpz_t k) {
    Pt t; pt_init(&t);
    pt_mul(c1, k, &G);
    pt_mul(&t, k, pub);
    pt_add(c2, pm, &t);
    pt_clear(&t);
}

/* Sec. 3.2: K from the pentatope number, then C1, C2. Hardened mode first validates the receiver's
 * public key. Returns 0 if it is rejected. */
static int encrypt(Pt *c1, Pt *c2, const Pt *pm, const Pt *pub, int hardened) {
    if (hardened && !pt_valid(pub)) return 0;
    mpz_t k, x, s; mpz_init(k); mpz_init(x); mpz_init(s);
    make_K(k, x, s, hardened);
    encrypt_K(c1, c2, pm, pub, k);
    mpz_clear(k); mpz_clear(x); mpz_clear(s);
    return 1;
}

/* Sec. 3.3: Pm = C2 - d * C1. Hardened mode first validates C1 and C2. Returns 0 if they are rejected. */
static int decrypt(Pt *pm, const Pt *c1, const Pt *c2, const mpz_t d, int hardened) {
    if (hardened && !(pt_valid(c1) && pt_valid(c2))) return 0;
    Pt t; pt_init(&t);
    pt_mul(&t, d, c1); pt_neg(&t, &t);
    pt_add(pm, c2, &t);
    pt_clear(&t);
    return 1;
}

/* Keyless eavesdropper: assumes the paper's public K and computes Pm = C2 - K*Pub without any private key.
 * Returns the decoded length (as koblitz_decode), or -1 if the result is not a valid message. */
static int eve_attack(uint8_t *data, const Pt *c2, const Pt *pub) {
    mpz_t k, x, s; mpz_init(k); mpz_init(x); mpz_init(s);
    Pt t, pm; pt_init(&t); pt_init(&pm);
    make_K(k, x, s, 0);
    pt_mul(&t, k, pub); pt_neg(&t, &t);
    pt_add(&pm, c2, &t);
    int n = koblitz_decode(data, &pm);
    mpz_clear(k); mpz_clear(x); mpz_clear(s); pt_clear(&t); pt_clear(&pm);
    return n;
}

/* ---------------------------------------------------------------- library API (ctypes, protocol.py) */
/* Wire format: scalar = 32 bytes, big-endian. A point is either uncompressed, x || y (64 bytes, as the paper's
 * "512-bit ECC point"), or compressed, 0x02/0x03 || x (33 bytes, the prefix gives the parity of y; SEC 1 2.3.3).
 * All zero bytes = point at infinity (never on the curve, since b != 0). One ciphertext block = C1 || C2:
 * 128 bytes uncompressed, 66 bytes compressed, carrying <= 29 message bytes.
 * mode flags: PEECC_HARDENED (bit 0) = hardened K and point validation, PEECC_COMPRESSED (bit 1) = compressed points.
 * Compression is a DEVIATION from [18] / the IoT paper's 512-bit points; it halves the ciphertext. */
#define PT_BYTES 64
#define CPT_BYTES 33
#define BLOCK_BYTES 128
#define PEECC_HARDENED 1
#define PEECC_COMPRESSED 2

static int g_ready = 0;
static void lib_init(void) { if (!g_ready) { setup_curve(); g_ready = 1; } }

static void int_to_32(uint8_t *out, const mpz_t v) {          /* v < 2^256 */
    uint8_t buf[32]; size_t n = 0;
    mpz_export(buf, &n, 1, 1, 1, 0, v);
    memset(out, 0, 32 - n); memcpy(out + 32 - n, buf, n);
}
static void pt_to_bytes(uint8_t *out, const Pt *q) {
    if (q->inf) { memset(out, 0, PT_BYTES); return; }
    int_to_32(out, q->x); int_to_32(out + 32, q->y);
}
static void pt_from_bytes(Pt *q, const uint8_t *in) {
    mpz_import(q->x, 32, 1, 1, 1, 0, in); mpz_import(q->y, 32, 1, 1, 1, 0, in + 32);
    q->inf = mpz_sgn(q->x) == 0 && mpz_sgn(q->y) == 0;
}

/* Compressed point: parity byte 0x02 (y even) / 0x03 (y odd), then x. */
static void pt_to_cbytes(uint8_t *out, const Pt *q) {
    if (q->inf) { memset(out, 0, CPT_BYTES); return; }
    out[0] = mpz_odd_p(q->y) ? 3 : 2;
    int_to_32(out + 1, q->x);
}

/* Decompression: y = sqrt(x^3 + ax + b) = rhs^((p+1)/4) (p = 3 mod 4), then the root with the given parity.
 * Returns 0 if the bytes are not a valid point (bad prefix, x >= p, or no square root). */
static int pt_from_cbytes(Pt *q, const uint8_t *in) {
    int zero = 1;
    for (int i = 0; i < CPT_BYTES; i++) zero &= in[i] == 0;
    if (zero) { q->inf = 1; return 1; }
    if (in[0] != 2 && in[0] != 3) return 0;
    mpz_import(q->x, 32, 1, 1, 1, 0, in + 1);
    if (mpz_cmp(q->x, P) >= 0) return 0;
    mpz_t rhs, e, chk; mpz_init(rhs); mpz_init(e); mpz_init(chk);
    fp_mul(rhs, q->x, q->x); fp_add(rhs, rhs, A); fp_mul(rhs, rhs, q->x); fp_add(rhs, rhs, Bc);
    mpz_add_ui(e, P, 1); mpz_fdiv_q_2exp(e, e, 2);
    mpz_powm(q->y, rhs, e, P);
    fp_mul(chk, q->y, q->y);
    int ok = mpz_cmp(chk, rhs) == 0;
    if (ok && (mpz_odd_p(q->y) != 0) != (in[0] == 3)) mpz_sub(q->y, P, q->y);
    q->inf = 0;
    mpz_clear(rhs); mpz_clear(e); mpz_clear(chk);
    return ok;
}

static double now_ms(void) {
#ifdef _WIN32
    LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return 1000.0 * (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
#endif
}

/* Bytes of one ciphertext block (C1 || C2) in the given mode: 128, or 66 with compressed points. */
int peecc_block_bytes(int mode) { return mode & PEECC_COMPRESSED ? 2 * CPT_BYTES : BLOCK_BYTES; }

/* Ciphertext size for a len-byte message: one block per started 29 bytes (an empty message is one block). */
size_t peecc_ct_size(size_t len, int mode) {
    return (size_t)peecc_block_bytes(mode) * (len ? (len + MAX_MSG - 1) / MAX_MSG : 1);
}
int peecc_max_block(void) { return MAX_MSG; }

static void block_out(uint8_t *out, const Pt *c1, const Pt *c2, int mode) {
    if (mode & PEECC_COMPRESSED) { pt_to_cbytes(out, c1); pt_to_cbytes(out + CPT_BYTES, c2); }
    else { pt_to_bytes(out, c1); pt_to_bytes(out + PT_BYTES, c2); }
}
static int block_in(Pt *c1, Pt *c2, const uint8_t *in, int mode) {
    if (mode & PEECC_COMPRESSED) return pt_from_cbytes(c1, in) && pt_from_cbytes(c2, in + CPT_BYTES);
    pt_from_bytes(c1, in); pt_from_bytes(c2, in + PT_BYTES);
    return 1;
}

/* [18] Sec. 3.1: private key d (32 bytes) and public key Pub = d*B (64 bytes). */
int peecc_keygen(uint8_t *d_out, uint8_t *pub_out) {
    lib_init();
    mpz_t d; Pt pub; mpz_init(d); pt_init(&pub);
    keygen(d, &pub);
    int_to_32(d_out, d); pt_to_bytes(pub_out, &pub);
    mpz_clear(d); pt_clear(&pub);
    return 1;
}

/* [18] Sec. 3.2 for a message of any length: split into 29-byte blocks, Koblitz-encode and encrypt each one.
 * out must hold peecc_ct_size(len, mode) bytes. Returns 0 if the public key is rejected (hardened mode). */
int peecc_encrypt(const uint8_t *msg, size_t len, const uint8_t *pub_in, int mode, uint8_t *out) {
    lib_init();
    Pt pub, pm, c1, c2; pt_init(&pub); pt_init(&pm); pt_init(&c1); pt_init(&c2);
    pt_from_bytes(&pub, pub_in);
    int ok = 1, bb = peecc_block_bytes(mode);
    size_t nb = peecc_ct_size(len, mode) / bb;
    for (size_t b = 0; b < nb && ok; b++) {
        size_t off = b * MAX_MSG, n = len - off < MAX_MSG ? len - off : MAX_MSG;
        ok = koblitz_encode(&pm, msg + off, n) && encrypt(&c1, &c2, &pm, &pub, mode & PEECC_HARDENED);
        if (ok) block_out(out + b * bb, &c1, &c2, mode);
    }
    pt_clear(&pub); pt_clear(&pm); pt_clear(&c1); pt_clear(&c2);
    return ok;
}

/* [18] Sec. 3.3 block by block. out must hold (ctlen / block bytes) * 29 bytes. Returns the plaintext length, or -1
 * if the ciphertext is malformed, a point is rejected (hardened mode) or a block does not decode. */
int peecc_decrypt(const uint8_t *ct, size_t ctlen, const uint8_t *d_in, int mode, uint8_t *out) {
    lib_init();
    size_t bb = peecc_block_bytes(mode);
    if (ctlen == 0 || ctlen % bb) return -1;
    mpz_t d; Pt c1, c2, pm; mpz_init(d); pt_init(&c1); pt_init(&c2); pt_init(&pm);
    mpz_import(d, 32, 1, 1, 1, 0, d_in);
    int total = 0;
    for (size_t b = 0; b < ctlen / bb && total >= 0; b++) {
        int n = block_in(&c1, &c2, ct + b * bb, mode) && decrypt(&pm, &c1, &c2, d, mode & PEECC_HARDENED)
                ? koblitz_decode(out + total, &pm) : -1;
        total = n < 0 ? -1 : total + n;
    }
    mpz_clear(d); pt_clear(&c1); pt_clear(&c2); pt_clear(&pm);
    return total;
}

/* Keyless eavesdropper on a whole ciphertext (C2 - K_paper*Pub per block). Same return value as peecc_decrypt. */
int peecc_eavesdrop(const uint8_t *ct, size_t ctlen, const uint8_t *pub_in, int mode, uint8_t *out) {
    lib_init();
    size_t bb = peecc_block_bytes(mode);
    if (ctlen == 0 || ctlen % bb) return -1;
    Pt pub, c1, c2; pt_init(&pub); pt_init(&c1); pt_init(&c2);
    pt_from_bytes(&pub, pub_in);
    int total = 0;
    for (size_t b = 0; b < ctlen / bb && total >= 0; b++) {
        int n = block_in(&c1, &c2, ct + b * bb, mode) ? eve_attack(out + total, &c2, &pub) : -1;
        total = n < 0 ? -1 : total + n;
    }
    pt_clear(&pub); pt_clear(&c1); pt_clear(&c2);
    return total;
}

/* [18] Sec. 3.2 Steps 2-3 helpers: S = Pentatope(x) and K = S^2+S+41 for a decimal x, as decimal strings.
 * Returns 0 if x is not a decimal number or outsz is too small. */
int peecc_pentatope_K(const char *x_dec, char *s_out, char *k_out, size_t outsz) {
    mpz_t x, s, k; mpz_init(x); mpz_init(s); mpz_init(k);
    int ok = mpz_set_str(x, x_dec, 10) == 0 && mpz_sgn(x) >= 0;
    if (ok) {
        pentatope(s, x); euler_K(k, s);
        ok = mpz_sizeinbase(k, 10) + 2 <= outsz;
        if (ok) { mpz_get_str(s_out, 10, s); mpz_get_str(k_out, 10, k); }
    }
    mpz_clear(x); mpz_clear(s); mpz_clear(k);
    return ok;
}

/* Measured mean milliseconds of keygen, encrypt and decrypt (one 11-byte block) over iters runs:
 * ms_out[0] = keygen, ms_out[1] = encrypt, ms_out[2] = decrypt. */
void peecc_bench(int iters, int mode, double *ms_out) {
    lib_init();
    uint8_t d[32], pub[PT_BYTES], ct[BLOCK_BYTES], back[MAX_MSG];
    const uint8_t msg[] = "hello world";
    double t[3] = {0, 0, 0};
    for (int i = 0; i < iters; i++) {
        double t0 = now_ms(); peecc_keygen(d, pub);
        double t1 = now_ms(); peecc_encrypt(msg, 11, pub, mode, ct);
        double t2 = now_ms(); peecc_decrypt(ct, peecc_block_bytes(mode), d, mode, back);
        double t3 = now_ms();
        t[0] += t1 - t0; t[1] += t2 - t1; t[2] += t3 - t2;
    }
    for (int j = 0; j < 3; j++) ms_out[j] = iters > 0 ? t[j] / iters : 0;
}

#ifndef PEECC_LIB

/* ---------------------------------------------------------------- printing helpers */
static void show(const char *label, const mpz_t v) { gmp_printf("  %-22s %Zx\n", label, v); }
static void show_pt(const char *label, const Pt *q) {
    gmp_printf("  %s\n      x = %Zx\n      y = %Zx\n", label, q->x, q->y);
}

/* ---------------------------------------------------------------- demo: one message, every step */
static const char *mode_name(int hardened) {
    return hardened ? "HARDENED (deviation from [18]: random pentatope input x per message, K mod N, point validation)"
                    : "paper-exact [18] (x = Bx, K is public)";
}

static int demo(const char *text, int hardened) {
    size_t len = strlen(text);
    if (len > MAX_MSG) { fprintf(stderr, "message must be at most %d bytes\n", MAX_MSG); return 1; }
    mpz_t d, x, s, k; mpz_init(d); mpz_init(x); mpz_init(s); mpz_init(k);
    Pt pub, pm, c1, c2, out; pt_init(&pub); pt_init(&pm); pt_init(&c1); pt_init(&c2); pt_init(&out);
    printf("mode: %s\n\n", mode_name(hardened));

    printf("== Key generation (receiver) [18] Sec. 3.1 ==\n");
    keygen(d, &pub);
    show("private key d", d); show_pt("public key Pub = d*B", &pub);
    printf("  Pub on curve: %s\n\n", pt_on_curve(&pub) ? "yes" : "NO");

    printf("== Encryption [18] Sec. 3.2 ==\n");
    printf("  message: \"%s\" (%zu bytes)\n", text, len);
    if (!koblitz_encode(&pm, (const uint8_t *)text, len)) { fprintf(stderr, "Koblitz encoding failed\n"); return 1; }
    show_pt("message point Pm (Koblitz)", &pm);
    make_K(k, x, s, hardened);
    show(hardened ? "x = random (secret)" : "x = Bx (public)", x);
    show("S = Pentatope(x)", s);
    gmp_printf("  K = %-18s (%lu bits)\n", hardened ? "(S^2+S+41) mod N" : "S^2+S+41", (unsigned long)mpz_sizeinbase(k, 2));
    encrypt_K(&c1, &c2, &pm, &pub, k);
    show_pt("C1 = K*B", &c1); show_pt("C2 = Pm + K*Pub", &c2);

    printf("\n== Decryption [18] Sec. 3.3 ==\n");
    uint8_t back[MAX_MSG + 1];
    int n = decrypt(&out, &c1, &c2, d, hardened) ? koblitz_decode(back, &out) : -1;
    if (n >= 0) show_pt("Pm' = C2 - d*C1", &out);
    back[n < 0 ? 0 : n] = 0;
    printf("  decoded message: \"%s\"\n  result: %s\n", n < 0 ? "?" : (char *)back,
           (n == (int)len && memcmp(back, text, len) == 0) ? "MATCH" : "MISMATCH");

    printf("\n== Keyless eavesdropper: C2 - K_paper*Pub, no private key ==\n");
    n = eve_attack(back, &c2, &pub);
    int read = n == (int)len && memcmp(back, text, len) == 0;
    back[n < 0 ? 0 : n] = 0;
    printf("  eavesdropper reads: %s\n  attack: %s\n", read ? (char *)back : "(garbage, decoding fails)",
           read ? "SUCCEEDS (message not confidential)" : "FAILS");
    return 0;
}

/* ---------------------------------------------------------------- self-tests */
static int g_fail = 0;
#define CHECK(cond, name) do { int ok_ = (cond); printf("  [%s] %s\n", ok_ ? "PASS" : "FAIL", name); if (!ok_) g_fail++; } while (0)

/* Random message of 0..MAX_MSG bytes and its Koblitz point. Returns the length. */
static size_t random_message(uint8_t *msg, Pt *pm) {
    uint8_t lb; os_random(&lb, 1);
    size_t len = lb % (MAX_MSG + 1); os_random(msg, len);
    koblitz_encode(pm, msg, len);
    return len;
}

/* The K-public break and the hardened mode, against one receiver key pair (d, Pub). */
static void test_hardened(const mpz_t d, const Pt *pub) {
    uint8_t msg[MAX_MSG], back[MAX_MSG + 1];
    Pt pm, c1, c2, o, first; pt_init(&pm); pt_init(&c1); pt_init(&c2); pt_init(&o); pt_init(&first);

    printf("test_K_is_public: paper-exact mode, keyless eavesdropper\n");
    int eve_all = 1, same_c1 = 1;
    for (int i = 0; i < 100; i++) {
        size_t len = random_message(msg, &pm);
        encrypt(&c1, &c2, &pm, pub, 0);
        if (i == 0) pt_set(&first, &c1); else same_c1 &= pt_equal(&first, &c1);
        int n = eve_attack(back, &c2, pub);
        if (n != (int)len || memcmp(back, msg, len)) eve_all = 0;
    }
    CHECK(eve_all, "paper-exact: eavesdropper decrypts 100/100 messages without a private key");
    CHECK(same_c1, "paper-exact: C1 is identical for every message");

    printf("hardened mode (deviation from [18])\n");
    int rt = 1, eve_none = 1, fresh = 1;
    for (int i = 0; i < 1000; i++) {
        size_t len = random_message(msg, &pm);
        encrypt(&c1, &c2, &pm, pub, 1);
        if (i == 0) pt_set(&first, &c1); else fresh &= !pt_equal(&first, &c1);
        int n = decrypt(&o, &c1, &c2, d, 1) ? koblitz_decode(back, &o) : -1;
        if (n != (int)len || memcmp(back, msg, len)) rt = 0;
        n = eve_attack(back, &c2, pub);
        if (n == (int)len && memcmp(back, msg, len) == 0) eve_none = 0;
    }
    CHECK(rt, "hardened: decrypt(encrypt(m)) == m for 1000 random messages");
    CHECK(eve_none, "hardened: eavesdropper decrypts 0/1000 messages");
    CHECK(fresh, "hardened: C1 differs from the first one in all 999 later encryptions");

    size_t len = random_message(msg, &pm);
    encrypt(&c1, &c2, &pm, pub, 1);
    Pt bad; pt_init(&bad);
    pt_set(&bad, &c1); mpz_add_ui(bad.y, bad.y, 1); mpz_mod(bad.y, bad.y, P);
    int rej = !decrypt(&o, &bad, &c2, d, 1) && !decrypt(&o, &c1, &bad, d, 1);
    pt_set(&bad, &c1); mpz_add(bad.x, bad.x, P);                                  /* x out of range [0, p-1] */
    rej &= !decrypt(&o, &bad, &c2, d, 1);
    bad.inf = 1; rej &= !decrypt(&o, &bad, &c2, d, 1);
    CHECK(rej, "hardened: decrypt rejects off-curve, out-of-range and infinity points");
    pt_set(&bad, pub); mpz_add_ui(bad.y, bad.y, 1); mpz_mod(bad.y, bad.y, P);
    CHECK(!encrypt(&c1, &c2, &pm, &bad, 1), "hardened: encrypt rejects an off-curve public key");
    int n = decrypt(&o, &c1, &c2, d, 1) ? koblitz_decode(back, &o) : -1;          /* valid input still accepted */
    CHECK(n == (int)len && memcmp(back, msg, len) == 0, "hardened: valid ciphertext still decrypts after the checks");

    pt_clear(&bad); pt_clear(&pm); pt_clear(&c1); pt_clear(&c2); pt_clear(&o); pt_clear(&first);
}

/* Multi-block library API in all four modes (paper-exact / hardened, uncompressed / compressed points): round trips
 * of 0..120 bytes, sizes, the eavesdropper on whole messages, and rejection of malformed input. */
static void test_blocks(void) {
    printf("multi-block API (peecc_encrypt / peecc_decrypt), uncompressed and compressed points\n");
    uint8_t d[32], pub[PT_BYTES], msg[120], back[5 * MAX_MSG], ct[5 * BLOCK_BYTES];
    peecc_keygen(d, pub);
    int rt = 1, size = 1, eve_p = 1, eve_h = 1;
    for (int mode = 0; mode <= 3; mode++)
        for (size_t len = 0; len <= 120; len += mode & PEECC_HARDENED ? 1 : 13) {   /* paper-exact is slow */
            size_t ctl = peecc_ct_size(len, mode);
            os_random(msg, len);
            size &= ctl == (size_t)(mode & PEECC_COMPRESSED ? 66 : 128) * (len ? (len + 28) / 29 : 1);
            peecc_encrypt(msg, len, pub, mode, ct);
            int n = peecc_decrypt(ct, ctl, d, mode, back);
            rt &= n == (int)len && memcmp(back, msg, len) == 0;
            n = peecc_eavesdrop(ct, ctl, pub, mode, back);
            int read = n == (int)len && memcmp(back, msg, len) == 0;
            if (mode & PEECC_HARDENED) eve_h &= !read; else eve_p &= read;
        }
    CHECK(rt, "blocks: decrypt(encrypt(m)) == m for 0-120 bytes, all 4 modes");
    CHECK(size, "blocks: 128 bytes (uncompressed) / 66 bytes (compressed) per started 29-byte block");
    CHECK(eve_p, "blocks: paper-exact eavesdropper reads whole messages, both point formats");
    CHECK(eve_h, "blocks: hardened eavesdropper reads no message, both point formats");
    peecc_encrypt(msg, 40, pub, PEECC_HARDENED, ct);
    ct[BLOCK_BYTES + 5] ^= 1;                                       /* corrupt C1 of the 2nd block of a 2-block message */
    CHECK(peecc_decrypt(ct, 2 * BLOCK_BYTES, d, PEECC_HARDENED, back) < 0 && peecc_decrypt(ct, 100, d, PEECC_HARDENED, back) < 0,
          "blocks: hardened decrypt rejects a corrupted block and a truncated ciphertext");
    int m3 = PEECC_HARDENED | PEECC_COMPRESSED, bad = 1;
    peecc_encrypt(msg, 20, pub, m3, ct);
    ct[0] = 4;                                                      /* invalid prefix */
    bad &= peecc_decrypt(ct, 66, d, m3, back) < 0;
    peecc_encrypt(msg, 20, pub, m3, ct);
    for (int k = 0; k < 64 && bad; k++) {                           /* x with no square root: not a point */
        ct[1 + 31] ^= 1 + k;
        Pt q; pt_init(&q);
        int valid = pt_from_cbytes(&q, ct);
        pt_clear(&q);
        if (!valid) { bad &= peecc_decrypt(ct, 66, d, m3, back) < 0; break; }
    }
    CHECK(bad, "blocks: compressed points with a bad prefix or an x off the curve are rejected");
}

static int test(void) {
    mpz_t a, b, s, k, d; mpz_init(a); mpz_init(b); mpz_init(s); mpz_init(k); mpz_init(d);
    Pt q, r, r2, pub; pt_init(&q); pt_init(&r); pt_init(&r2); pt_init(&pub);

    printf("curve and keys\n");
    CHECK(pt_on_curve(&G), "generator B is on the curve");
    mpz_set_ui(a, 2); pt_mul(&r, a, &G);                      /* known 2*G of secp256r1 */
    mpz_t ex, ey; mpz_init_set_str(ex, "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978", 16);
    mpz_init_set_str(ey, "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1", 16);
    CHECK(mpz_cmp(r.x, ex) == 0 && mpz_cmp(r.y, ey) == 0, "2*B equals the published secp256r1 value");
    pt_mul(&r, N, &G);
    CHECK(r.inf, "N*B = point at infinity");
    int on = 1, pubok = 1;
    for (int i = 0; i < 50; i++) {
        keygen(d, &pub); on &= pt_on_curve(&pub);
        pt_mul(&r, d, &G); pubok &= pt_equal(&r, &pub);
    }
    CHECK(on, "50 random public keys lie on the curve");
    CHECK(pubok, "public key == private * B (50 keys)");

    printf("scalar multiplication\n");
    int hom = 1;
    for (int i = 0; i < 20; i++) {
        random_private_key(a); random_private_key(b); mpz_add(s, a, b);
        pt_mul(&q, s, &G);
        pt_mul(&r, a, &G); pt_mul(&r2, b, &G); pt_add(&r, &r, &r2);
        hom &= pt_equal(&q, &r);
    }
    CHECK(hom, "(a+b)*B == a*B + b*B (20 pairs)");

    printf("pentatope number and K (hand-computed values)\n");
    mpz_set_ui(a, 1); pentatope(s, a); CHECK(mpz_cmp_ui(s, 1) == 0,  "S(1) = 1");
    mpz_set_ui(a, 2); pentatope(s, a); CHECK(mpz_cmp_ui(s, 5) == 0,  "S(2) = 5");
    mpz_set_ui(a, 3); pentatope(s, a); CHECK(mpz_cmp_ui(s, 15) == 0, "S(3) = 15");
    mpz_set_ui(s, 1);  euler_K(k, s); CHECK(mpz_cmp_ui(k, 43) == 0,  "K(S=1)  = 43");
    mpz_set_ui(s, 5);  euler_K(k, s); CHECK(mpz_cmp_ui(k, 71) == 0,  "K(S=5)  = 71");
    mpz_set_ui(s, 15); euler_K(k, s); CHECK(mpz_cmp_ui(k, 281) == 0, "K(S=15) = 281");

    printf("encrypt / decrypt\n");
    keygen(d, &pub);
    int rt = 1;
    for (int i = 0; i < 1000; i++) {
        uint8_t msg[MAX_MSG], back[MAX_MSG], lb;
        os_random(&lb, 1); size_t len = lb % (MAX_MSG + 1); os_random(msg, len);
        Pt pm, c1, c2, o; pt_init(&pm); pt_init(&c1); pt_init(&c2); pt_init(&o);
        koblitz_encode(&pm, msg, len);
        encrypt(&c1, &c2, &pm, &pub, 0); decrypt(&o, &c1, &c2, d, 0);
        int n = koblitz_decode(back, &o);
        if (n != (int)len || memcmp(back, msg, len)) rt = 0;
        pt_clear(&pm); pt_clear(&c1); pt_clear(&c2); pt_clear(&o);
    }
    CHECK(rt, "decrypt(encrypt(m)) == m for 1000 random messages");

    test_hardened(d, &pub);
    test_blocks();

    printf(g_fail ? "\n%d TEST(S) FAILED\n" : "\nALL TESTS PASSED\n", g_fail);
    return g_fail != 0;
}

int main(int argc, char **argv) {
    lib_init();
    int hardened = 0;
    const char *text = "hello PEECC";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0) return test();
        else if (strcmp(argv[i], "--hardened") == 0) hardened = 1;
        else text = argv[i];
    }
    return demo(text, hardened);
}
#endif /* PEECC_LIB */
