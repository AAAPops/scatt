/*
 * Tiny partial "socat" replacement from scratch
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#define BUF_SZ 1024

int core_redirect(int fdin, int fdout) {
    int ret;
    size_t nbytes;

    uint8_t buffer[BUF_SZ];

    while (1)  {
        nbytes = read(fdin, buffer, BUF_SZ);
        if (nbytes == 0)
            break;

        printf("Read  %zu bytes \n", nbytes);
        write(fdout, buffer, nbytes);
        printf("Write %zu\n\n", nbytes);
    }
    if (ferror(stdin))
        printf("There was an error reading from stdin");

    return 0;
}

int main(int argc, char* argv[])
{
    if (feof(stdin))
        printf("stdin reached eof\n");

    FILE *fp = fopen("/tmp/mimail", "w");
    if (fp == 0)
        printf("...something went wrong opening file...\n");

    printf("About to write\n");

    core_redirect(STDIN_FILENO, fp->_fileno);

    printf("Done writing\n");

    fclose(fp);

    return 0;
}
