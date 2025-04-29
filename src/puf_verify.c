#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "puf_verify.h"
#include "utils.h"


int importCommitment(mbedtls_ecp_group *grp, const uint8_t *commitment, mbedtls_ecp_point *C, size_t commitment_buffer_size) {
    return mbedtls_ecp_point_read_binary(grp, C, commitment, commitment_buffer_size);
}

int initECC(mbedtls_ecp_group *grp, mbedtls_ecp_point *h, mbedtls_ecp_point *C ){
    mbedtls_ecp_group_init(grp);
	mbedtls_ecp_point_init(h);
	mbedtls_ecp_point_init(C);
	int res;
	res = mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);

    if (res != 0) {
        printf("Failed to load EC group: -0x%04X\n", -res);
        return 1;
    }
    
    mbedtls_mpi x;
	mbedtls_mpi_init(&x);
	res = mbedtls_mpi_lset(&x, CONSTANT_FOR_H_GENERATOR);  
	
    if (res != 0) {
        printf("Failed to set X");
        return 1;
    }
    
    res = mbedtls_ecp_mul(grp, h, &x, &grp->G, randFunction, NULL);
    
    if (res != 0) {
        printf("Failed to generate h point: %d\n", res);
        return 1;
    }

    return 0;
}



int verify_ECC(mbedtls_ecp_group *grp, mbedtls_ecp_point *g, mbedtls_ecp_point *h, mbedtls_ecp_point *proof, mbedtls_ecp_point *C, mbedtls_mpi *result_v, mbedtls_mpi *result_w, mbedtls_mpi *nonce) {

	unsigned char sha256_result[32];
	mbedtls_ecp_point gh, result; //g^v * h^w
	mbedtls_ecp_point_init(&gh);
	mbedtls_ecp_point_init(&result);
	mbedtls_mpi helper, result_c;
	mbedtls_mpi_init(&helper);
	mbedtls_mpi_init(&result_c);
	mbedtls_mpi_lset(&helper, 1);

	
	int res;
	size_t olen;
	unsigned char buff[100];
	mbedtls_ecp_point_write_binary(grp, C, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buff, sizeof(buff));
	unsigned char buff2[olen + mbedtls_mpi_size(nonce)];
	memcpy(buff2, buff, olen);
	mbedtls_mpi_write_binary(nonce, buff2 + olen, sizeof(buff2) - olen);
	sha256Hash(buff2, sizeof(buff2), sha256_result);
	mbedtls_mpi_read_string(&result_c, 16, sha256_result);

	res = mbedtls_ecp_muladd(grp, &gh, result_v, g, result_w, h);  //  g * v + h * w
	res = mbedtls_ecp_muladd(grp, &result, &helper, proof, &result_c, C); // d * 1 + c * e
    res = mbedtls_ecp_point_cmp(&gh, &result);
    if (res != 0) {
		return 1;
	}
	return 0;
}

