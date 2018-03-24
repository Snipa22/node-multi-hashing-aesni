#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void cn_slow_hash(const void *data, size_t length, char *hash, int variant, int prehashed = 0);

#ifdef __cplusplus
}
#endif