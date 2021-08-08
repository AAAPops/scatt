/*
 * Tiny partial "socat" replacement from scratch
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>

#include "tcp_connection.h"
#include "log.h"
#include "version.h"


#define IN_BUFF_SZ  1024
#define OUT_BUFF_SZ 1024

#define TIMEOUT_SEC  5 * 1000


void print_usage(char *util_name) {
    fprintf(stderr, "Ver.%s \n", VERSION);
    fprintf(stderr, "Usage: %s [-t] [-D] ip:port \n", util_name);
    fprintf(stderr, "\t -t - timeout in sec. Default 5s \n");
    fprintf(stderr, "\t -d - Debug level [0..5] \n");
    fprintf(stderr, "\t ip:port - address to connect to \n");
}


int main(int argc, char **argv) {
    int retcode = -1;
    int ret;

    char *ipaddr;
    char *ipport;

    uint8_t in_buff[IN_BUFF_SZ];
    uint8_t out_buff[OUT_BUFF_SZ];
    size_t nbytes;

    // Set default
    int timeout = TIMEOUT_SEC;
    int debug_level = -1;

    if( argc == 1) {
        print_usage(argv[0]);
        return -1;
    }

    int c;
    opterr = 0;
    while ((c = getopt (argc, argv, "ht:d:")) != -1) {
        switch (c) {
            case 'h':
                print_usage(argv[0]);
                return -1;
            case 't':
                timeout = (int) strtol(optarg, NULL, 10) * 1000;
                break;
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


    ret = argToIpAddr(argv[argc-1], &ipaddr, &ipport);
    if( ret != 0) {
        print_usage(argv[0]);
        return -1;
    }
    log_trace("ipaddr = '%s',  ipport = '%s'", ipaddr, ipport);


    int srv_fd = connect_to_srv(ipaddr, ipport);
    if (srv_fd < 0) {
        log_fatal("Error to connect to server %s:%s", ipaddr, ipport);
        goto err;
    }

    log_trace("...............Read from stdin...............");
    while (1) {
        nbytes = read(STDIN_FILENO, in_buff, IN_BUFF_SZ);
        if (nbytes == 0)
            break;
        log_trace("Read  %zu bytes from stdin", nbytes);

        ret = write_tcp_data(srv_fd, in_buff, nbytes);
        if (ret < 0) {
            log_fatal("Error write data to server");
            goto err;
        }
        log_trace("Write %zu to server", nbytes);
    }


    log_trace("...............Write to stdout...............");

    struct pollfd pfds;
    pfds.fd = srv_fd;
    pfds.events = POLLIN;

    while (1)
    {
        ret = poll(&pfds, 1, timeout);
        if (ret == -1) {
            log_fatal("poll: [%m]");
            break;

        } else if (ret == 0) {
            log_warn("poll: Time out");
            break;
        }

        log_trace("  fd=%d; events: %s%s%s%s", pfds.fd,
               (pfds.revents & POLLIN)  ? "POLLIN "  : "",
               (pfds.revents & POLLHUP) ? "POLLHUP " : "",
               (pfds.revents & POLLHUP) ? "POLLRDHUP " : "",
               (pfds.revents & POLLERR) ? "POLLERR " : "");

        if (pfds.revents & POLLIN) {
            nbytes = recv(srv_fd, out_buff, OUT_BUFF_SZ, 0);
            if( nbytes < 0 ) {
                log_fatal("recv(): [%m]");
                break;
            }
            if( nbytes == 0 ) {
                log_warn("peer closed connection");
                break;
            }
            // if nbytes > 0 !!!
            write(STDOUT_FILENO, out_buff, nbytes);
            log_trace("Write %zu to stdout", nbytes);
            break;

        } else {  // POLLERR | POLLHUP | etc.
            log_warn("peer closed connection");
            break;
        }
    }


    retcode = 0;
err:
    if (srv_fd > 0)
        close(srv_fd);

    return retcode;
}


/*
while (1) {
    nbytes = read(srv_fd, out_buff, OUT_BUFF_SZ);
    if (nbytes < 0) {
        log_fatal("Error read data from server");
        goto err;
    }
    if( nbytes == 0 )
        break;
    log_trace("Read  %zu bytes from server", nbytes);

    write(STDOUT_FILENO, out_buff, nbytes);
    log_trace("Write %zu to stdout", nbytes);
}
*/