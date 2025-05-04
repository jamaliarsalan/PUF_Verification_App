#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Computes the SHA-256 hash of the given input.
 *
 * @param input Pointer to the input data.
 * @param ilen Length of the input data.
 * @param output Pointer to a 32-byte buffer where the hash will be written.
 */
void sha256_hash(const unsigned char *input, size_t ilen, unsigned char output[32]);

/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * @param hex Null-terminated hexadecimal string.
 * @param out Output buffer for the converted bytes.
 * @param out_size Maximum number of bytes to write to the output buffer.
 * @return 0 on success, -1 on invalid input or if the buffer is too small.
 */
int hex_string_to_bytes(const char *hex, unsigned char *out, size_t out_size);

/**
 * @brief A simple random number generator function for use with mbedTLS.
 *
 * @param rng_state Pointer to the RNG state (unused).
 * @param output Buffer to write random bytes into.
 * @param len Number of random bytes to generate.
 * @return 0 on success.
 */
int rand_function(void *rng_state, unsigned char *output, size_t len);

#ifdef __cplusplus
}
#endif

#endif // UTILS_H
