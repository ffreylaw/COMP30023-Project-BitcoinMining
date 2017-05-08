#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "uint256.h"
#include "sha256.h"

#define MASK_ALPHA  0b11111111000000000000000000000000
#define MASK_BETA   0b00000000111111111111111111111111

int main(int argc, char const *argv[]) {
    char buf[] ="SOLN 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 10000000232123a2\r\n";
    int i = 0;
    char *p = strtok (buf, " \r\n");
    char **array = (char**)malloc(sizeof(char*));

    while (p != NULL) {
        i++;
        array = (char**)realloc(array, i*sizeof(char*));
        array[i-1] = p;
        p = strtok (NULL, " \r\n");
    }

    int n = i;
    printf("%d\n", n);

    for (i = 0; i < n; ++i)
        printf("%s\n", array[i]);


    uint32_t difficulty;
    difficulty = strtoull(array[1], NULL, 16);
    printf("0x%x\n", difficulty);

    uint64_t solution;
    solution = strtoull(array[3], NULL, 16);
    printf("0x%llx\n", solution);

    BYTE seed[32];
    char buf2[2];
    for (i = 0; i < 64; i+=2) {
        buf2[0] = array[2][i];
        buf2[1] = array[2][i+1];
        seed[i/2] = strtoull(buf2, NULL, 16);
    }

    printf("0x");
    for (i = 0; i < 32; i++) {
        printf("%02x", seed[i]);
    }

    printf("\n%d\n", 0b1 << 10);

    uint32_t b = difficulty;
    printf("difficulty: %u\n", b);

    uint32_t alpha = (MASK_ALPHA & difficulty) >> 24;
    uint32_t beta = MASK_BETA & difficulty;
    printf("alpha: %u\n", alpha);
    printf("beta: %u\n", beta);

    // int x = 0x01c0ffee;
    //
    // printf("Size: %d\n", sizeof(int));
    // printf("1.) %x\n", x);
    // printf("2.) %x\n", x >> 7);
    // printf("3.) %x\n", x >> 8);
    // printf("4.) %x\n", x >> 8 & 0xFF);


    BYTE base[32], coefficient[32], target[32];
    BYTE clean[32];
    uint256_init(base);
    uint256_init(coefficient);
    uint256_init(target);
    uint256_init(clean);

    base[31] = 0x02;
    uint32_t temp_beta = beta;
    for (i = 0; i < 32; i++) {
        coefficient[31-i] = temp_beta & 0xff;
        temp_beta >>= 8;
    }

    print_uint256(coefficient);

    uint256_exp(clean, base, (8 * (alpha - 3)));
    print_uint256(clean);

    uint256_mul(target, coefficient, clean);
    print_uint256(target);



    BYTE buf4[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	int idx;

	// sha256_init(&ctx);
	// sha256_update(&ctx, text1, strlen(text1));
	// sha256_final(&ctx, buf4);

    return 0;
}
