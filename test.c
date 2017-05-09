#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "uint256.h"
#include "sha256.h"

#define MASK_ALPHA  0b11111111000000000000000000000000
#define MASK_BETA   0b00000000111111111111111111111111

int main(int argc, char const *argv[]) {
    char buf[] ="SOLN 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212147\r\n";
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
    uint256_init(seed);
    char buf0[2];
    for (i = 0; i < 64; i+=2) {
        buf0[0] = array[2][i];
        buf0[1] = array[2][i+1];
        seed[i/2] = strtoull(buf0, NULL, 16);
    }
    print_uint256(seed);

    printf("\n%d\n", 0b1 << 10);

    uint32_t b = difficulty;
    printf("difficulty: %x\n", b);

    uint32_t alpha = (MASK_ALPHA & difficulty) >> 24;
    uint32_t beta = MASK_BETA & difficulty;
    printf("alpha: %x\n", alpha);
    printf("beta: %x\n", beta);

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

    printf("coefficient: ");
    print_uint256(coefficient);

    uint256_exp(clean, base, (8 * (alpha - 3)));
    printf("exp: ");
    print_uint256(clean);

    uint256_mul(target, coefficient, clean);
    printf("target: ");
    print_uint256(target);

    BYTE nonce[8];
    char buf1[2];
    for (i = 0; i < 16; i+=2) {
        buf1[0] = array[3][i];
        buf1[1] = array[3][i+1];
        nonce[i/2] = strtoull(buf1, NULL, 16);
    }
    printf("nonce: ");
    for (i = 0; i < 8; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\n");

	SHA256_CTX ctx;
    BYTE soln[SHA256_BLOCK_SIZE];
    uint256_init(soln);
    //while (true) {
        BYTE text[40];
        int count = 0;
        for (i = 0; i < 32; i++) {
            text[count++] = seed[i];
        }
        for (i = 0; i < 8; i++) {
            text[count++] = nonce[i];
        }
        printf("text: ");
        for (i = 0; i < 40; i++) {
            printf("%02x", text[i]);
        }
        printf("\n");

        uint256_init(clean);
    	sha256_init(&ctx);
    	sha256_update(&ctx, text, 40);
    	sha256_final(&ctx, clean);
        printf("first hash: ");
        print_uint256(clean);

        sha256_init(&ctx);
    	sha256_update(&ctx, clean, SHA256_BLOCK_SIZE);
    	sha256_final(&ctx, soln);
        printf("second hash: ");
        print_uint256(soln);

        if (sha256_compare(soln, target) < 0) {
            printf("OKAY: ");
            print_uint256(soln);
        } else {
            printf("NOT OKAY!\n");
        }
    //}

    return 0;
}
