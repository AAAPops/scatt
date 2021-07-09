#ifndef INCLUDE_SERVER_H
#define INCLUDE_SERVER_H

#include <stdio.h>
#include <stdint.h>
#include <getopt.h>

struct Srv_inst {
    char       string[128];
    uint32_t   addr;
    int        port;
    int        srv_fd;
    int        peer_fd;

    int        run_mode;

    uint8_t    read_buff[128];
};


// Server
int srv_start(const char *addr_str, int port);
int srv_client_accept(int srv_fd, const char *addr_str, int port);
void srv_close(int srv_fd);

// Send/Receive TCP data
int write_tcp_data(int peer_fd, void* buff_ptr, size_t buff_len);
int read_tcp_data(int peer_fd, void *buffer, size_t count);


// Client
int connect_to_srv(const char *addr_str, const char *port_str);
int connect_to_unix_socket(const char *socket_path);
void client_close(int client_fd);

// Misc
int argToIpAddr(const char *argument, char **ipaddr, char **ipport);

#endif