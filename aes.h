#ifndef SIMPLEAES256GCM_AES_H
#define SIMPLEAES256GCM_AES_H

#include <stdint.h>

#define AES_STD 256

#define AES_LOG 0

void AESEnc(const uint8_t *in, const uint8_t *key, uint8_t *out);

#endif //SIMPLEAES256GCM_AES_H
