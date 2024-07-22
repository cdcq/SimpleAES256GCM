#ifndef SIMPLEAES256GCM_GCM_H
#define SIMPLEAES256GCM_GCM_H

#include <stdint.h>

/* If you want to use iv for ctr enc directly instead of turn it to j0, you can turn this setting on.
 * This approach is not allowed in standard file but can be found in a popular FPGA implement. */
#define USE_IV_DIRECTLY 0

/* This setting is to open a log output on stdout.
 * The format of this log is same as the example vectors by IEEE. */
#define GCM_LOG 0

#if USE_IV_DIRECTLY == 0

/* GCM Authentication Encryption.
 * All the lengths (len_p, len_iv, len_a, len_t) are measured in bits.
 * The length of the key must confirm to the standard.
 * The ciphertext pointer "c" must have the same length with the plaintext pointer.
 * The tag pointer "t" must have length 16 (128bit). The length of tag cannot exceed 128. */
void GCM_AE(
        const uint8_t *p, uint32_t len_p, const uint8_t *key, const uint8_t *iv, uint32_t len_iv,
        const uint8_t *a, uint32_t len_a, uint32_t len_t,
        uint8_t *c, uint8_t *t);

/* GCM Authentication Decryption.
 * All the lengths (len_p, len_iv, len_a, len_t) are measured in bits.
 * The length of the key must confirm to the standard.
 * The length of tag cannot exceed 128.
 * The plaintext pointer "p" must have the same length with the ciphertext pointer.
 * If the tag is match with the ciphertext, additional message and key, the value of access is 1 and 0 otherwise. */
void GCM_AD(
        const uint8_t *c, uint32_t len_c, const uint8_t *key, const uint8_t *iv, uint32_t len_iv,
        const uint8_t *a, uint32_t len_a, const uint8_t *t, uint32_t len_t,
        uint8_t *p, uint32_t *access);

#else

/* GCM Authentication Encryption.
 * All the lengths (len_p, len_iv, len_a, len_t) are measured in bits.
 * The length of the key must confirm to the standard.
 * If you use iv directly, the length of iv will be fiexd to 128 and you don't need to offer the length of it.
 * The ciphertext pointer "c" must have the same length with the plaintext pointer.
 * The tag pointer "t" must have length 16 (128bit). The length of tag cannot exceed 128. */
void GCM_AE(
        const uint8_t *p, uint32_t len_p, const uint8_t *key, const uint8_t *iv,
        const uint8_t *a, uint32_t len_a, uint32_t len_t,
        uint8_t *c, uint8_t *t);

/* GCM Authentication Decryption.
 * All the lengths (len_p, len_iv, len_a, len_t) are measured in bits.
 * The length of the key must confirm to the standard.
 * If you use iv directly, the length of iv will be fiexd to 128 and you don't need to offer the length of it.
 * The length of tag cannot exceed 128.
 * The plaintext pointer "p" must have the same length with the ciphertext pointer.
 * If the tag is match with the ciphertext, additional message and key, the value of access is 1 and 0 otherwise. */
void GCM_AD(
        const uint8_t *c, uint32_t len_c, const uint8_t *key, const uint8_t *iv,
        const uint8_t *a, uint32_t len_a, const uint8_t *t, uint32_t len_t,
        uint8_t *p, uint32_t *access);

#endif

#endif //SIMPLEAES256GCM_GCM_H
