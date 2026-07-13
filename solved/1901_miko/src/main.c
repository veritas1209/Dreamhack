#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include "rng.h"
#include "crypt.h"

void printBstr(char *S, unsigned char *A, unsigned long long L);

extern const size_t pubkey_size;
extern const size_t privkey_size;
extern const size_t plaintext_size;
extern const size_t ciphertext_size;

int main()
{
    unsigned char       pt[plaintext_size];
    unsigned char       pt_recovered[plaintext_size];
    unsigned char       ct[ciphertext_size];
    unsigned char       entropy_input[48];
    unsigned char       pk[pubkey_size], sk[privkey_size];
    int                 ret_val;

    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, entropy_input, 48);
    close(fd);

    randombytes_init(entropy_input, NULL, 48);
    randombytes(pt, plaintext_size);

    if ( (ret_val = crypto_encrypt_keypair(pk, sk)) != 0) {
        printf("crypto_encrypt_keypair returned <%d>\n", ret_val);
        return 1;
    }

    encrypt_one_block(ct, pt, pk);
    
    if ( (ret_val = decrypt_one_block(pt_recovered, ct, sk)) != 0) {
        printf("decrypt_one_block returned <%d>\n", ret_val);
        return 1;
    }

    if ( memcmp(pt, pt_recovered, plaintext_size) ) {
        printf("decrypt_one_block returned bad 'm' value\n");
        return 1;
    }

    printBstr("pk = ", pk, pubkey_size);
    printBstr("sk = ", sk, privkey_size);
    printBstr("pt = ", pt, plaintext_size);
    printBstr("ct = ", ct, ciphertext_size);

    return 0;
}

void
printBstr(char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	printf("%s", S);

	for ( i=0; i<L; i++ )
		printf("%02X", A[i]);

	if ( L == 0 )
		printf("00");

	printf("\n");
}

