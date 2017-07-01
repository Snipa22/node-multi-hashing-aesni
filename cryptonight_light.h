#ifndef CRYPTONIGHT_LIGHT_H
#define CRYPTONIGHT_LIGHT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void cryptonight_light_hash(const char* input, char* output, uint32_t len);
void cryptonight_light_fast_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
