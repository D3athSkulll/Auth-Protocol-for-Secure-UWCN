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
 * Usage:  peecc "my message"   encrypt + decrypt a message (<= 29 bytes), printing every step
 *         peecc --test         run the self-tests
 */
#define _CRT_RAND_S
#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int pt_equal(const Pt *a, const Pt *b) {
    if (a->inf || b->inf) return a->inf == b->inf;
    return mpz_cmp(a->x, b->x) == 0 && mpz_cmp(a->y, b->y) == 0;
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

/* Sec. 3.2: S = Pentatope(Bx), K = S^2+S+41, C1 = K*B, C2 = Pm + K*Pub. */
static void encrypt(Pt *c1, Pt *c2, const Pt *pm, const Pt *pub) {
    mpz_t s, k, kp; mpz_init(s); mpz_init(k); mpz_init(kp);
    Pt t; pt_init(&t);
    pentatope(s, G.x); euler_K(k, s);
    pt_mul(c1, k, &G);
    pt_mul(&t, k, pub);
    pt_add(c2, pm, &t);
    mpz_clear(s); mpz_clear(k); mpz_clear(kp); pt_clear(&t);
}

/* Sec. 3.3: Pm = C2 - d * C1. */
static void decrypt(Pt *pm, const Pt *c1, const Pt *c2, const mpz_t d) {
    Pt t; pt_init(&t);
    pt_mul(&t, d, c1); pt_neg(&t, &t);
    pt_add(pm, c2, &t);
    pt_clear(&t);
}

/* ---------------------------------------------------------------- printing helpers */
static void show(const char *label, const mpz_t v) { gmp_printf("  %-22s %Zx\n", label, v); }
static void show_pt(const char *label, const Pt *q) {
    gmp_printf("  %s\n      x = %Zx\n      y = %Zx\n", label, q->x, q->y);
}

/* ---------------------------------------------------------------- demo: one message, every step */
static int demo(const char *text) {
    size_t len = strlen(text);
    if (len > MAX_MSG) { fprintf(stderr, "message must be at most %d bytes\n", MAX_MSG); return 1; }
    mpz_t d, s, k; mpz_init(d); mpz_init(s); mpz_init(k);
    Pt pub, pm, c1, c2, out; pt_init(&pub); pt_init(&pm); pt_init(&c1); pt_init(&c2); pt_init(&out);

    printf("== Key generation (receiver) [18] Sec. 3.1 ==\n");
    keygen(d, &pub);
    show("private key d", d); show_pt("public key Pub = d*B", &pub);
    printf("  Pub on curve: %s\n\n", pt_on_curve(&pub) ? "yes" : "NO");

    printf("== Encryption [18] Sec. 3.2 ==\n");
    printf("  message: \"%s\" (%zu bytes)\n", text, len);
    koblitz_encode(&pm, (const uint8_t *)text, len);
    show_pt("message point Pm (Koblitz)", &pm);
    pentatope(s, G.x); euler_K(k, s);
    show("S = Pentatope(Bx)", s);
    gmp_printf("  K = S^2+S+41           (%lu bits)\n", (unsigned long)mpz_sizeinbase(k, 2));
    encrypt(&c1, &c2, &pm, &pub);
    show_pt("C1 = K*B", &c1); show_pt("C2 = Pm + K*Pub", &c2);

    printf("\n== Decryption [18] Sec. 3.3 ==\n");
    decrypt(&out, &c1, &c2, d);
    show_pt("Pm' = C2 - d*C1", &out);
    uint8_t back[MAX_MSG + 1]; int n = koblitz_decode(back, &out);
    back[n < 0 ? 0 : n] = 0;
    printf("  decoded message: \"%s\"\n  result: %s\n", n < 0 ? "?" : (char *)back,
           (n == (int)len && memcmp(back, text, len) == 0) ? "MATCH" : "MISMATCH");
    return 0;
}

/* ---------------------------------------------------------------- self-tests */
static int g_fail = 0;
#define CHECK(cond, name) do { int ok_ = (cond); printf("  [%s] %s\n", ok_ ? "PASS" : "FAIL", name); if (!ok_) g_fail++; } while (0)

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
        encrypt(&c1, &c2, &pm, &pub); decrypt(&o, &c1, &c2, d);
        int n = koblitz_decode(back, &o);
        if (n != (int)len || memcmp(back, msg, len)) rt = 0;
        pt_clear(&pm); pt_clear(&c1); pt_clear(&c2); pt_clear(&o);
    }
    CHECK(rt, "decrypt(encrypt(m)) == m for 1000 random messages");

    printf(g_fail ? "\n%d TEST(S) FAILED\n" : "\nALL TESTS PASSED\n", g_fail);
    return g_fail != 0;
}

int main(int argc, char **argv) {
    setup_curve();
    if (argc > 1 && strcmp(argv[1], "--test") == 0) return test();
    return demo(argc > 1 ? argv[1] : "hello PEECC");
}
