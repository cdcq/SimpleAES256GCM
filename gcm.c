#include "gcm.h"
#include "aes.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void XorState(uint8_t *x, const uint8_t *y) {
    uint32_t i;

    for (i = 0; i < 16; i++) {
        x[i] ^= y[i];
    }
}

static void ShiftRightState(uint8_t *x) {
    uint32_t i;

    for (i = 15; i >= 1; i--) {
        x[i] >>= 1;
        x[i] |= (x[i - 1] & 1) << 7;
    }
    x[0] >>= 1;
}

static void MSB(uint8_t *x, uint32_t y) {
    uint32_t i;

    for (i = 0; i < 128 - y; i++) {
        ShiftRightState(x);
    }
}

static void GFMultiplication(uint8_t *x, const uint8_t *y) {
    uint32_t i, j;
    uint8_t z[16];
    uint8_t v[16];

    memset(z, 0, sizeof(uint8_t) * 16);
    memcpy(v, y, sizeof(uint8_t) * 16);

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & 1 << (7 - j)) {
                XorState(z, v);
            }
            if (v[15] & 1) {
                ShiftRightState(v);
                v[0] ^= 0xe1;
            } else {
                ShiftRightState(v);
            }
        }
    }

    memcpy(x, z, sizeof(uint8_t) * 16);
}

static uint32_t Ceil128(uint32_t n) {
    return (n + 127) / 128 * 128;
}

static uint32_t Division128(uint32_t n) {
    return (n + 127) / 128;
}

static uint32_t Ceil8(uint32_t n) {
    return (n + 7) / 8 * 8;
}

static uint32_t Division8(uint32_t n) {
    return (n + 7) / 8;
}

/* Turn 4 continuous bytes to a 32bit unsigned int in big endian.
 * The bytes order of big endian is same as the memory's, which is contrary to x86 default (little endian). */
static uint32_t GetBE32(const uint8_t *x) {
    return ((uint32_t) x[0] << 24) | ((uint32_t) x[1] << 16) |
           ((uint32_t) x[2] << 8) | (uint32_t) x[3];
}

/*  Turn a 32bit unsigned int to 4 continuous bytes in big endian. */
static void PutBE32(uint8_t *x, uint32_t y) {
    x[0] = (y >> 24) & 0xff;
    x[1] = (y >> 16) & 0xff;
    x[2] = (y >> 8) & 0xff;
    x[3] = y & 0xff;
}

static void Inc32(uint8_t *x) {
    PutBE32(x + 12, GetBE32(x + 12) + 1);
}

static void LogData(const uint8_t *a, uint32_t len, char end) {
    uint32_t i;

    for (i = 0; i < len / 8; i++) {
        printf("%02X", a[i]);
    }
    putchar(end);
}

static void GHASH(const uint8_t *x, uint32_t len, const uint8_t *h, uint8_t *y) {
    uint32_t i;
    uint32_t m = Division128(len);

    memset(y, 0, sizeof(uint8_t) * 16);

    for (i = 0; i < m; i++) {
        XorState(y, x + i * 16);
        GFMultiplication(y, h);
#if GCM_LOG == 1
        if (i < m - 1) {
            printf("X[%d]: ", i + 1);
            LogData(y, 128, '\n');
        }
#endif
    }
}

static void GCTR(const uint8_t *x, uint32_t len, const uint8_t *key, const uint8_t *icb, uint8_t *y) {
    uint32_t i;
    uint32_t n;
    uint8_t cb[16];
    uint8_t temp[16];

    if (len == 0)
        return;

    n = Division128(len);
    memcpy(cb, icb, sizeof(uint8_t) * 16);
    for (i = 0; i < n - 1; i++) {
        AESEnc(cb, key, y + i * 16);
#if GCM_LOG == 1
        printf("Y[%d]: ", i + 1);
        LogData(cb, 128, '\n');
        printf("E(K,Y[%d]): ", i + 1);
        LogData(y + i * 16, 128, '\n');
#endif
        XorState(y + i * 16, x + i * 16);
#if GCM_LOG == 1
        printf("C[%d]: ", i + 1);
        LogData(y + i * 16, 128, '\n');
#endif
        Inc32(cb);
    }

    AESEnc(cb, key, temp);
#if GCM_LOG == 1
    printf("Y[%d]: ", n);
    LogData(cb, 128, '\n');
    printf("E(K,Y[%d]): ", n);
    LogData(temp, 128, '\n');
#endif
    if (len % 128 != 0) {
//        MSB(temp, len % 128);
        for (i = 0; i < Division8(len % 128); i++) {
            (y + (n - 1) * 16)[i] = temp[i] ^ (x + (n - 1) * 16)[i];
        }
#if GCM_LOG == 1
        printf("C[%d]: ", n);
        LogData(y + (n - 1) * 16, len % 128, '\n');
#endif
    } else {
        memcpy(y + (n - 1) * 16, temp, sizeof(uint8_t) * 16);
        XorState(y + (n - 1) * 16, x + (n - 1) * 16);
#if GCM_LOG == 1
        printf("C[%d]: ", n);
        LogData(y + (n - 1) * 16, 128, '\n');
#endif
    }
}

void CalculateJ0(const uint8_t *iv, uint32_t len_iv, const uint8_t *h, uint8_t *j0) {
    uint32_t j0_len;
    uint8_t *j0_data = NULL;
    if (len_iv == 96) {
        memset(j0, 0, sizeof(uint8_t) * 16);
        memcpy(j0, iv, sizeof(uint8_t) * 12);
        j0[15] = 1;
    } else {
        j0_len = Ceil128(len_iv) + 128;
        j0_data = malloc(sizeof(uint8_t) * (j0_len / 8));
        memset(j0_data, 0, sizeof(uint8_t) * (j0_len / 8));
        memcpy(j0_data, iv, sizeof(uint8_t) * Division8(len_iv));
        PutBE32(j0_data + j0_len / 8 - 4, len_iv);

        GHASH(j0_data, j0_len, h, j0);
    }

    free(j0_data);
}

static void CalculateTag(
        const uint8_t *c, uint32_t len_c, const uint8_t *key, const uint8_t *a, uint32_t len_a,
        const uint8_t *h, const uint8_t *j0, uint32_t len_t, uint8_t *t) {
    uint32_t u;
    uint32_t v;
    uint8_t *s_data;
    uint8_t s[16];

    u = Ceil128(len_c);
    v = Ceil128(len_a);
    s_data = malloc(sizeof(uint8_t) * (v / 8 + u / 8 + 16));
    memset(s_data, 0, sizeof(uint8_t) * (v / 8 + u / 8 + 16));
    memcpy(s_data, a, sizeof(uint8_t) * Division8(len_a));
    memcpy(s_data + v / 8, c, sizeof(uint8_t) * Division8(len_c));
    PutBE32(s_data + v / 8 + u / 8 + 4, len_a);
    PutBE32(s_data + v / 8 + u / 8 + 12, len_c);
    GHASH(s_data, u + v + 128, h, s);
#if GCM_LOG == 1
    printf("GHASH(H,A,C): ");
    LogData(s, 128, '\n');
#endif
    GCTR(s, 128, key, j0, t);
    MSB(t, len_t);

    free(s_data);
}

#if USE_IV_DIRECTLY == 0

void GCM_AE(
        const uint8_t *p, uint32_t len_p, const uint8_t *key, const uint8_t *iv, uint32_t len_iv,
        const uint8_t *a, uint32_t len_a, uint32_t len_t,
        uint8_t *c, uint8_t *t) {
#else

void GCM_AE(
        const uint8_t *p, uint32_t len_p, const uint8_t *key, const uint8_t *iv,
        const uint8_t *a, uint32_t len_a, uint32_t len_t,
        uint8_t *c, uint8_t *t) {
#endif
    uint8_t h[16];
    uint8_t temp[16];
    uint8_t j0[16];
    uint8_t ibc[16];

    memset(temp, 0, sizeof(uint8_t) * 16);
    AESEnc(temp, key, h);
#if GCM_LOG == 1
    printf("H: ");
    LogData(h, 128, '\n');
#endif

#if USE_IV_DIRECTLY == 1
    memcpy(j0, iv, sizeof(uint8_t) * 16);
#else
    CalculateJ0(iv, len_iv, h, j0);
#endif
#if GCM_LOG == 1
    printf("Y[0]: ");
    LogData(j0, 128, '\n');
#endif
    memcpy(ibc, j0, sizeof(uint8_t) * 16);
    Inc32(ibc);
    GCTR(p, len_p, key, ibc, c);

    CalculateTag(c, len_p, key, a, len_a, h, j0, len_t, t);
}

#if USE_IV_DIRECTLY == 0

void GCM_AD(
        const uint8_t *c, uint32_t len_c, const uint8_t *key, const uint8_t *iv, uint32_t len_iv,
        const uint8_t *a, uint32_t len_a, const uint8_t *t, uint32_t len_t,
        uint8_t *p, uint32_t *access) {
#else

void GCM_AD(
        const uint8_t *c, uint32_t len_c, const uint8_t *key, const uint8_t *iv,
        const uint8_t *a, uint32_t len_a, const uint8_t *t, uint32_t len_t,
        uint8_t *p, uint32_t *access) {
#endif
    uint32_t i;
    uint8_t h[16];
    uint8_t temp[16];
    uint8_t j0[16];
    uint8_t ibc[16];
    uint8_t t2[16];

    memset(temp, 0, sizeof(uint8_t) * 16);
    AESEnc(temp, key, h);

#if USE_IV_DIRECTLY == 1
    memcpy(j0, iv, sizeof(uint8_t) * 16);
#else
    CalculateJ0(iv, len_iv, h, j0);
#endif
    memcpy(ibc, j0, sizeof(uint8_t) * 16);
    Inc32(ibc);
    GCTR(c, len_c, key, ibc, p);

    CalculateTag(c, len_c, key, a, len_a, h, j0, len_t, t2);

    *access = memcmp(t, t2, sizeof(t2)) == 0;
}
