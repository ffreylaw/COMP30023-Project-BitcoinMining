#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "uint256.h"
#include "sha256.h"

BYTE *byte_converter(char*);

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

    uint64_t a;
    a = strtoull(array[3], NULL, 16);
        printf("%llx\n", a);

    return 0;
}

BYTE *byte_converter(char *str) {

}
