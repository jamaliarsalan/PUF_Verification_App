#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "puf_verify.h"
#include "utils.h"

#define COMMITMENT_BUFFER_SIZE 65
const char *input_hex = "0485F5F442C45F70C22FC5E94C25732B5F7FB7971C1A69322752D3B637986A61DB610B4595A59586B09212DC369FC094172BBD3B509048EDC3FC7951452EDAF831";  // Paste your commitment string here

const char *v_hex = "751778E137647B477FDB1475E1CAC33155CCB65795EAC294C12B479B13DA9E29"; // Fill V
const char *w_hex = "49C89569BC3C1E72E0C3FEA80F069A7A2F3A171E261FA3ACA1B623995DBF7EA0";  // Fill w
const char *nonce_hex = "10FBFBFBFBFBFB4CFBFB2CFBFB10FBFBF5FBFBFBFBFBFBB3FBFBCFFBFBF5FBFB"; // Fill nonce
const char *proof_hex = "04FC26F95D147D8C16B730D6D0561710C0BFF54C90BF738D7B01259DDF3E2FF808593EFE0C0D83B9542986413A26E2C8101CF6729E35C8B69CC8B1D573F8C955FA"; // Fill Proof


int main() {
    int ret;

    mbedtls_ecp_group grp;
	mbedtls_ecp_point h, C;
	
    ret = init_ECC(&grp,&h,&C);
    if(ret!=0)
    {
        printf("ECC couldn't be initiliased\r\n");
        return ret;
    }

    mbedtls_ecp_point proof;
    mbedtls_ecp_point_init(&proof);
    mbedtls_mpi v, w, nonce;
    mbedtls_mpi_init(&v);
    mbedtls_mpi_init(&w);
    mbedtls_mpi_init(&nonce);


    // Import Commitment into C
    unsigned char commitment[COMMITMENT_BUFFER_SIZE];
    hex_string_to_bytes(input_hex, commitment, sizeof(commitment));
    import_commitment(&grp, commitment, &C,COMMITMENT_BUFFER_SIZE);

    // Read v, w, nonce
    unsigned char temp_buf[100];
    hex_string_to_bytes(v_hex, temp_buf, sizeof(temp_buf));
    mbedtls_mpi_read_binary(&v, temp_buf, 32);

    hex_string_to_bytes(w_hex, temp_buf, sizeof(temp_buf));
    mbedtls_mpi_read_binary(&w, temp_buf, 32);

    hex_string_to_bytes(nonce_hex, temp_buf, sizeof(temp_buf));
    mbedtls_mpi_read_binary(&nonce, temp_buf, 16); // or 32 depending on your nonce size

    // Import proof
    hex_string_to_bytes(proof_hex, temp_buf, sizeof(temp_buf));
    mbedtls_ecp_point_read_binary(&grp, &proof, temp_buf, 65);

    // Verify
    ret = verify_ECC(&grp, &grp.G, &h, &proof, &C, &v, &w, &nonce);

    if (ret == 0) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed\n");
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&h);
    mbedtls_ecp_point_free(&proof);
    mbedtls_ecp_point_free(&C);
    mbedtls_mpi_free(&v);
    mbedtls_mpi_free(&w);
    mbedtls_mpi_free(&nonce);

    return ret;
}
