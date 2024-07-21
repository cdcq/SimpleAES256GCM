#include "aes.h"
#include <stdlib.h>
#include <stdio.h>

#if AES_STD == 256
#define Nk 8
#define Nr 14
#elif AES_STD == 192
#define Nk 6
#define Nr 12
#elif AES_STD == 128
#define Nk 4
#define Nr 10
#endif

static const uint8_t S_box[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t Rcon[11] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void SubBytes(uint8_t *state) {
    uint8_t i;

    for (i = 0; i < 16; i++)
        state[i] = S_box[state[i]];
}

static void ShiftRows(uint8_t *state) {
    uint8_t temp;

    temp = state[4];
    state[4] = state[5];
    state[5] = state[6];
    state[6] = state[7];
    state[7] = temp;

    temp = state[8];
    state[8] = state[10];
    state[10] = temp;
    temp = state[9];
    state[9] = state[11];
    state[11] = temp;

    temp = state[12];
    state[12] = state[15];
    state[15] = state[14];
    state[14] = state[13];
    state[13] = temp;
}

static void MixColumns(uint8_t *state) {
    uint8_t i, j;
    uint8_t temp[4], column[4];

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++)
            column[j] = state[j * 4 + i];

        temp[0] =
                GFMultiplication(column[0], 2) ^
                GFMultiplication(column[1], 3) ^
                GFMultiplication(column[2], 1) ^
                GFMultiplication(column[3], 1);
        temp[1] =
                GFMultiplication(column[0], 1) ^
                GFMultiplication(column[1], 2) ^
                GFMultiplication(column[2], 3) ^
                GFMultiplication(column[3], 1);
        temp[2] =
                GFMultiplication(column[0], 1) ^
                GFMultiplication(column[1], 1) ^
                GFMultiplication(column[2], 2) ^
                GFMultiplication(column[3], 3);
        temp[3] =
                GFMultiplication(column[0], 3) ^
                GFMultiplication(column[1], 1) ^
                GFMultiplication(column[2], 1) ^
                GFMultiplication(column[3], 2);

        for (j = 0; j < 4; j++)
            state[j * 4 + i] = temp[j];
    }
}

static void AddRoundKey(uint8_t *state, const uint8_t *round_key) {
    int i, j;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j * 4 + i] ^= round_key[i * 4 + j];
        }
    }
}

static void RotWord(uint8_t *word) {
    uint8_t temp;

    temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

static void SubWord(uint8_t *word) {
    word[0] = S_box[word[0]];
    word[1] = S_box[word[1]];
    word[2] = S_box[word[2]];
    word[3] = S_box[word[3]];
}

static void KeyExpansion(const uint8_t *key, uint8_t *w) {
    int i, j;
    uint8_t temp[4];

    for (i = 0; i < Nk * 4; i++) {
        w[i] = key[i];
    }

    for (i = Nk; i < 4 * (Nr + 1); i++) {
        for (j = 0; j < 4; j++)
            temp[j] = w[(i - 1) * 4 + j];
        if (i % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            SubWord(temp);
        }
        for (j = 0; j < 4; j++) {
            w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}

void log_state(int round, const char *stage, const uint8_t *state) {
    int i;

    printf("round[%2d].%s \t", round, stage);
    for (i = 0; i < 16; i++) {
        printf("%02x", state[i]);
    }
    putchar('\n');
}

void aes_enc(const uint8_t *in, const uint8_t *key, uint8_t *out) {
    int i, j;
    uint8_t state[16];
    uint8_t w[(Nr + 1) * 16];

    KeyExpansion(key, w);
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++)
            state[j * 4 + i] = in[i * 4 + j];
    }

#if AES_LOG == 1
    log_state(0, "input", state);
    log_state(0, "k_sch", w + 0);
#endif
    AddRoundKey(state, w + 0);

    for (i = 1; i < Nr; i++) {
#if AES_LOG == 1
        log_state(i, "start", state);
#endif
        SubBytes(state);
#if AES_LOG == 1
        log_state(i, "s_box", state);
#endif
        ShiftRows(state);
#if AES_LOG == 1
        log_state(i, "s_row", state);
#endif
        MixColumns(state);
#if AES_LOG == 1
        log_state(i, "m_col", state);
#endif
        AddRoundKey(state, w + i * 16);
#if AES_LOG == 1
        log_state(i, "k_sch", w + i * 16);
#endif
    }


#if AES_LOG == 1
    log_state(Nr, "start", state);
#endif
    SubBytes(state);
#if AES_LOG == 1
    log_state(Nr, "s_box", state);
#endif
    ShiftRows(state);
#if AES_LOG == 1
    log_state(Nr, "s_row", state);
#endif
    AddRoundKey(state, w + Nr * 16);
#if AES_LOG == 1
    log_state(Nr, "k_sch", w + Nr * 16);
    log_state(Nr, "output", state);
#endif

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++)
            out[i * 4 + j] = state[j * 4 + i];
    }
}

uint8_t GFMultiplication(uint8_t a, uint8_t b) {
    uint8_t c = 0;
    for (uint8_t i = 0; i < 8; i++) {
        if ((b & 1) == 1)
            c ^= a;
        if (a & 0x80) {
            a <<= 1;
            a ^= 0x1b;
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    return c;
}