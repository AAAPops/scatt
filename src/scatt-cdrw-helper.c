/*
 * Tiny partial "socat" replacement from scratch
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>

#include "tcp_connection.h"
#include "log.h"
#include "version.h"


#define BUFF_SZ  1024 * 100

#define POLL_TIMEOUT  5 * 1000  // 5 sec.
#define POLL_FD_MAX   2 // Unix socket fd + stdin fd

#define SOCK_LEN_MAX  128
#define SLEEP_SEC   3


char * parse_usock_path(const char *socket_path) {

    char *tmp_str = strdup(socket_path);

    char *colon_ptr = strchr(tmp_str, ':');
    if (!colon_ptr) {
        log_fatal("A problem with parameter unix:/sock/path");
        free(tmp_str);
        return NULL;
    }

    *colon_ptr = '\0';
    if (strncmp(tmp_str, "unix", 4) != 0) {
        log_fatal("A problem with parameter unix:/sock/path");
        free(tmp_str);

        return NULL;
    }

    if( strlen(colon_ptr + 1) >= SOCK_LEN_MAX ) {
        log_fatal("A problem with parameter unix:/sock/path");
        free(tmp_str);

        return NULL;
    }

    char *clean_sockpath = (char*)calloc(SOCK_LEN_MAX, sizeof(char));
    strcpy(clean_sockpath, colon_ptr + 1);
    free(tmp_str);

    return clean_sockpath;
}


void print_usage(char *util_name) {
    fprintf(stderr, "Ver.%s \n", VERSION);
    fprintf(stderr, "Usage: %s [-D] unix:/path/to/cdrw.sock \n", util_name);
    fprintf(stderr, "\t -d - Debug level [0..5] \n");
}


int main(int argc, char **argv) {
    //int retcode = 0;
    int ret;
    int usock_fd;

    uint8_t buff[BUFF_SZ];
    ssize_t nbytes;
    //char usock_str[128];

    struct pollfd pfds[POLL_FD_MAX];

    // Set default
    int debug_level = -1;

    if( argc == 1) {
        print_usage(argv[0]);
        return -1;
    }

    int c;
    opterr = 0;
    while ((c = getopt (argc, argv, "h:d:")) != -1) {
        switch (c) {
            case 'h':
                print_usage(argv[0]);
                return -1;
            case 'd':
                debug_level = (int) strtol(optarg, NULL, 10);
                break;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }


    log_set_quiet(1);
    if( debug_level >= 0 ) {
        log_set_quiet(0);
        log_set_level(debug_level);
    }
    //FILE *fp;
    //fp = fopen("/tmp/cdrw.log", "w");
    //log_set_fp(fp);


    char *usock_path =  parse_usock_path(argv[argc-1]);

    while(1)
    {
        usock_fd = connect_to_unix_socket(usock_path);
        if (usock_fd < 0) {
            log_fatal("Not able to connect to unix socket '%s'", usock_path);
            sleep(SLEEP_SEC);
            continue;
        }


        while (1) {
            memset(pfds, 0, sizeof(pfds));
            pfds[0].fd = usock_fd;
            pfds[0].events = POLLIN;

            pfds[1].fd = STDIN_FILENO;
            pfds[1].events = POLLIN;

            ret = poll(pfds, POLL_FD_MAX, -1);
            if (ret == -1) {
                log_fatal("poll: [%m]");
                break;
            }

            if (ret == 0) {
                log_warn("poll: Time out");
                break;
            }

            log_trace("");
            for (int i = 0; i < POLL_FD_MAX; i++) {
                log_trace("pfds[%d].fd; events: %s%s%s%s", pfds[i].fd,
                          (pfds[i].revents & POLLIN) ? "POLLIN " : "",
                          (pfds[i].revents & POLLHUP) ? "POLLHUP " : "",
                          (pfds[i].revents & POLLHUP) ? "POLLRDHUP " : "",
                          (pfds[i].revents & POLLERR) ? "POLLERR " : "");
            }


            // Unix socket ---> stdout
            if (pfds[0].revents & POLLIN) {
                nbytes = recv(usock_fd, buff, BUFF_SZ, 0);
                if (nbytes < 0) {
                    log_fatal("recv(): [%m]");
                    break;
                }
                if (nbytes == 0) {
                    log_warn("peer closed connection");
                    break;
                }

                // if nbytes > 0 !!!
                nbytes = write(STDOUT_FILENO, buff, nbytes);
                if( nbytes < 0 ) {
                    log_fatal("recv(): [%m]");
                    break;
                }
                log_debug("Write %zu to 'stdout'", nbytes);
            }


            //stdin --->  Unix socket
            if (pfds[1].revents & POLLIN) {
                nbytes = read(STDIN_FILENO, buff, BUFF_SZ);
                if (nbytes < 0) {
                    log_fatal("read(): [%m]");
                    break;
                }
                if (nbytes == 0) {
                    log_warn("peer closed connection");
                    break;
                }

                // if nbytes > 0 !!!
                nbytes = write(usock_fd, buff, nbytes);
                if( nbytes < 0 ) {
                    log_fatal("recv(): [%m]");
                    break;
                }
                log_debug("Write %zu to 'Unix socket'", nbytes);
            }
        } // End of get/out loop


        close(usock_fd);
        sleep(SLEEP_SEC);
    } // End of outer loop


/*
err:
    retcode = -1;
out:
    if (usock_fd > 0)
        close(usock_fd);

    return retcode;
*/
}


