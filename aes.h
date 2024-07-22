#ifndef SIMPLEAES256GCM_AES_H
#define SIMPLEAES256GCM_AES_H

#include <stdint.h>

/* This setting is to control the standard of the AES.
 * Remind: don't forget to check your key length is correct or not. */
#define AES_STD 256

/* This setting is to open a log output on stdout.
 * The format of this log is same as the example vectors in the standard file by FIPS. */
#define AES_LOG 0

/* AES Encryption.
 * The input must has length 16 (128bit) so do the output.
 * The key must has length 10/12/14 at standard 128/192/256. */
void AESEnc(const uint8_t *in, const uint8_t *key, uint8_t *out);

#endif //SIMPLEAES256GCM_AES_H
