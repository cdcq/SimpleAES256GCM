#ifndef SIMPLEAES256GCM_GCM_H
#define SIMPLEAES256GCM_GCM_H

#include <stdint.h>

#define USE_IV_DIRECTLY 1

#define GCM_LOG 0

#if USE_IV_DIRECTLY == 0

void GCMAE(
        const uint8_t *p, uint32_t len_p, const uint8_t *key, const uint8_t *iv, uint32_t len_iv,
        const uint8_t *a, uint32_t len_a, uint32_t len_t,
        uint8_t *c, uint8_t *t);

void GCMAD(
        const uint8_t *c, uint32_t len_c, const uint8_t *key, const uint8_t *iv, uint32_t len_iv,
        const uint8_t *a, uint32_t len_a, const uint8_t *t, uint32_t len_t,
        uint8_t *p, uint32_t *access);

#else

void GCMAE(
        const uint8_t *p, uint32_t len_p, const uint8_t *key, const uint8_t *iv,
        const uint8_t *a, uint32_t len_a, uint32_t len_t,
        uint8_t *c, uint8_t *t);

void GCMAD(
        const uint8_t *c, uint32_t len_c, const uint8_t *key, const uint8_t *iv,
        const uint8_t *a, uint32_t len_a, const uint8_t *t, uint32_t len_t,
        uint8_t *p, uint32_t *access);

#endif

#endif //SIMPLEAES256GCM_GCM_H
