#ifndef SIMPLEAES256GCM_AES_H
#define SIMPLEAES256GCM_AES_H

#include <stdint.h>

#define AES_STD 256

#define AES_LOG 0

void aes_enc(const uint8_t *in, const uint8_t *key, uint8_t *out);

uint8_t GFMultiplication(uint8_t a, uint8_t b);

#endif //SIMPLEAES256GCM_AES_H
