#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    system(argv[1]);
    char buffer[16];
    strcpy(buffer, argv[2]);
    return 0;
}
