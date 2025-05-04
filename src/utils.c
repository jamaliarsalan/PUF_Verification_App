#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "utils.h"


void sha256_hash(const unsigned char *input, size_t ilen, unsigned char output[32]) {
    mbedtls_sha256(input, ilen, output, 0);
}

int hex_string_to_bytes(const char *hex, unsigned char *out, size_t out_size) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > out_size) {
        return -1;
    }

    for (size_t i = 0; i < len / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &out[i]);
    }
    return 0;
}

int rand_function(void *rng_state, unsigned char *output, size_t len) {

    size_t use_len;
	int rnd;
    
	if (rng_state != NULL)
		rng_state = NULL;

	while (len > 0) {
		use_len = len;
		if (use_len > sizeof(int))
			use_len = sizeof(int);

		rnd = rand();
		memcpy(output, &rnd, use_len);
		output += use_len;
		len -= use_len;
	}

    
	return (0);
}
