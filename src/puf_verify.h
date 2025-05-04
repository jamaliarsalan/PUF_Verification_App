#ifndef PUF_VERIFY_H
#define PUF_VERIFY_H

#include <stdint.h>
#include <stddef.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"

/* Constant used for generating point h */
#define CONSTANT_FOR_H_GENERATOR 123456789

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Imports a commitment point from binary data.
 *
 * @param grp Pointer to initialized elliptic curve group.
 * @param commitment Binary data of the commitment.
 * @param C Output point to store the imported commitment.
 * @param commitment_buffer_size Size of the binary buffer.
 * @return 0 on success, non-zero on failure.
 */
int import_commitment(mbedtls_ecp_group *grp, const uint8_t *commitment, mbedtls_ecp_point *C, size_t commitment_buffer_size);

/**
 * @brief Initializes ECC group and points (G, h, and C).
 *
 * @param grp Pointer to elliptic curve group structure.
 * @param h Output point h = G * CONSTANT.
 * @param C Output point to be initialized.
 * @return 0 on success, 1 on failure.
 */
int init_ECC(mbedtls_ecp_group *grp, mbedtls_ecp_point *h, mbedtls_ecp_point *C);

/**
 * @brief Verifies ECC proof using the verifier equation.
 *
 * @param grp ECC group.
 * @param g Base point g.
 * @param h Generator point h.
 * @param proof Commitment proof point.
 * @param C Commitment point.
 * @param result_v ECC scalar response v.
 * @param result_w ECC scalar response w.
 * @param nonce Nonce used in the challenge.
 * @return 0 if verification is successful, 1 otherwise.
 */
int verify_ECC(mbedtls_ecp_group *grp, mbedtls_ecp_point *g, mbedtls_ecp_point *h,
               mbedtls_ecp_point *proof, mbedtls_ecp_point *C,
               mbedtls_mpi *result_v, mbedtls_mpi *result_w, mbedtls_mpi *nonce);

#ifdef __cplusplus
}
#endif

#endif // PUF_VERIFY_H
