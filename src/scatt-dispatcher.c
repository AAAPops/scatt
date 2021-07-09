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
#include <sys/un.h>
#include <sys/wait.h>

#include "tcp_connection.h"
#include "remap_pipe.h"
#include "log.h"

/*  Temporary defines!!!  */
#define EXEC_1       "/home/urv/CLionProjects/scatt/test.sh"
#define SOCKET_PATH  "/tmp/dispatcher.sock"


#define VERSION    "0.1a"

#define MEMZERO(x)	memset(&(x), 0, sizeof (x));

#define IN_BUFF_SZ  1024
#define OUT_BUFF_SZ 1024

#define TIMEOUT_SEC  10 * 1000
#define MAX_CLIENTS  10

/*
struct _client {
    int fd;
    int parent_stdin;
    int parent_stdout;
    int child_stdin;
    int child_stdout;
    int busy_flag;

} client[MAX_CLIENTS];
*/

void print_usage(char *util_name) {
    fprintf(stderr, "Ver.%s \n", VERSION);
    fprintf(stderr, "Usage: %s [-t] [-D]  unix:/path/to/socket \n", util_name);
    fprintf(stderr, "\t -t - timeout to get answer from bash script \n");
    fprintf(stderr, "\t -D - Debug level [-1,0..5]. -1 quiet mode \n");
    fprintf(stderr, "\t /path/to/socket - Unix socket to listen on \n");
}

int unix_sock_server (char *socket_path);
int parse_argv(int argc, char **argv, int *timeout, int *debug_level);
void do_child_process(int, int);


int main(int argc, char **argv)
{
    int retcode = -1;
    int ret;
    pid_t child_pid[10] = {-1};
    pid_t wpid;
    int wstatus;
    int server_fd;
    int newsockfd;
    int readn;

    struct sockaddr_un client_sockaddr;
    unsigned int len = sizeof(client_sockaddr);

    uint8_t ibuff[IN_BUFF_SZ];
    uint8_t obuff[OUT_BUFF_SZ];
    size_t  nbytes;

    int tmp_fds[2];


    /************************************/
    /* Set defaults                     */
    /************************************/
    int timeout = TIMEOUT_SEC;
    int debug_level = LOG_INFO;
    //MEMZERO(client);

    if( argc == 1) {
        print_usage(argv[0]);
        return -1;
    }

    parse_argv(argc, argv, &timeout, &debug_level);

    if( debug_level == -1 )
        log_set_quiet(1);
    else
        log_set_level(debug_level);


    server_fd = unix_sock_server(SOCKET_PATH);
    if( server_fd < 0 ){
        goto err;
    }


    /*********************************/
    /*           Main loop           */
    /*********************************/
    int flag = 0;
    while (1) {
        newsockfd = accept(server_fd, (struct sockaddr *) &client_sockaddr, &len);
        if (newsockfd == -1) {
            log_warn("accept(): {%m]");
            close(newsockfd);
            continue;
        }
        log_info("accept new client (fd = %d)", newsockfd);

        /* Create child process */
        pid_t pid = fork();

        if (pid < 0) {
            log_warn("fork() [%m]");
            continue;
        }

        if (pid == 0) {
            /* Child process */
            close(server_fd);

            do_child_process(newsockfd, flag);

            exit(0);
        } else {
            /* Parent process continue*/
            close(newsockfd);
            printf("Check now!\n");
            flag = 1;

            pid_t returnStatus;
            waitpid(-1, &returnStatus, WNOHANG);  // Parent process waits here for child to terminate.
        }
    }


    retcode = 0;
err:
    close(server_fd);

    return retcode;
}


void do_child_process(int client_fd, int flag) {

    pid_t pid = getpid();
    log_info("do_child_process(#%d): fd = %d", pid, client_fd);
    log_info("   flag = %d", flag);

    int ret;
    int tmp_fds[2];

    //if( flag == 0 ) sleep(10);

    ret = pipe(tmp_fds);
    if( ret == -1  ) {
        log_fatal("pipe() [%m]");
        exit(-1);
    }
    int parent_stdin = tmp_fds[0];
    int child_stdout = tmp_fds[1];

    ret = pipe(tmp_fds);
    if( ret == -1  ) {
        log_fatal("pipe() [%m]");
        exit(-1);
    }
    int parent_stdout = tmp_fds[1];
    int child_stdin = tmp_fds[0];

    pid = fork();
    if (pid == -1) {      /* fork() failed */
        log_fatal("fork() [%m]");
        exit(-1);
    }

    if( pid == 0 ) {
        printf( "Child Child process starts...\n" );

        char *argv_local[3] = {EXEC_1, "1st_arg", NULL};

        close(parent_stdin);
        close(parent_stdout);

        remap_pipe_stdin_stdout(child_stdin, child_stdout);

        execvp( EXEC_1, argv_local );
        exit(0);

    } else {
        printf( "Child Parent process continues... child child's pid is %d\n", pid);

        char buff[1024] = {0};

        close(child_stdin);
        close(child_stdout);

        int nread = read(client_fd, buff, sizeof(buff));
        log_debug("Get from client [%d]: %s \n", nread, buff);

        write(parent_stdout, buff, nread);
        close(parent_stdout);

        nread = read(parent_stdin, buff, sizeof(buff));
        log_debug("Get from bash script [%d]: %s \n", nread, buff);
        close(parent_stdin);

        write(client_fd, buff, nread);
        close(client_fd);

        waitpid(pid, &ret, WUNTRACED | WCONTINUED);
    }

    exit(0);
}


#if 0
    /*********************************/
    /*           Main loop           */
    /*********************************/
    int pollResult;
    struct pollfd pollfds[MAX_CLIENTS + 1];
    MEMZERO(pollfds);
    pollfds[0].fd = server_fd;
    pollfds[0].events = POLLIN;
    int useClient = 0;

    while (1)
    {
        pollResult = poll(pollfds, useClient + 1, TIMEOUT_SEC);
        log_trace("pollResult = %d", pollResult);
        if( pollResult > 0 )
        {
            /*********************************/
            /* Accept an incoming connection */
            /*********************************/
            if ( pollfds[0].revents & POLLIN )
            {
                log_trace("Event in pollfds[0]");
                pollfds[0].revents = 0;

                client_tmp_fd = accept(server_fd, (struct sockaddr *)&client_sockaddr, &len);
                if (client_tmp_fd == -1){
                    log_warn("accept(): {%m]");
                    close(client_tmp_fd);
                    continue;
                }
                log_info("accept success (fd = %d)", client_tmp_fd);

                for (int i = 1; i < MAX_CLIENTS; i++)
                {
                    if (pollfds[i].fd == 0)
                    {
                        pollfds[i].fd = client_tmp_fd;
                        pollfds[i].events = POLLIN;
                        useClient++;
                        log_trace("useClient = %d, i = %d", useClient, i);
                        break;
                    }
                }
            }
            sleep(1);

            /*****************************************************/
            /* Check All poll_fds and make decision what's happen*/
            /*****************************************************/
            for (int i = 1; i < MAX_CLIENTS; i++)
            {
                if (pollfds[i].fd > 0 && pollfds[i].revents & POLLIN)
                {
                    log_trace("Event in pollfds[%d]", i);

                    readn = read(pollfds[i].fd, ibuff, IN_BUFF_SZ - 1);
                    log_trace("readn = %d for fd = %d", readn, i);
                    if (readn == -1)
                    {
                        pollfds[i].fd = 0;
                        pollfds[i].events = 0;
                        pollfds[i].revents = 0;
                        useClient--;
                    }
                    else if (readn == 0)
                    {
                        pollfds[i].fd = 0;
                        pollfds[i].events = 0;
                        pollfds[i].revents = 0;
                        useClient--;
                    }
                    else
                    {
                        ibuff[IN_BUFF_SZ] = '\0';
                        log_trace("Get from client: %s", ibuff);
                    }
                }
            }
        }
    }
#endif


int unix_sock_server (char *socket_path)
{
    int server_sock, ret;
    int backlog = 10;
    struct sockaddr_un server_sockaddr;

    /**************************************/
    /* Create a UNIX domain stream socket */
    /**************************************/
    server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock == -1){
        log_fatal("socket(): [%m]");
        return -1;
    }

    /***************************************/
    /* Set up the UNIX sockaddr structure  */
    /* by using AF_UNIX for the family and */
    /* giving it a filepath to bind to.    */
    /*                                     */
    /* Unlink the file so the bind will    */
    /* succeed, then bind to that file.    */
    /***************************************/
    server_sockaddr.sun_family = AF_UNIX;
    strcpy(server_sockaddr.sun_path, socket_path);
    unsigned int len = sizeof(server_sockaddr);

    unlink(socket_path);
    ret = bind(server_sock, (struct sockaddr *) &server_sockaddr, len);
    if (ret == -1){
        log_fatal("bind(): [%m]");
        return -1;
    }

    /*********************************/
    /* Listen for any client sockets */
    /*********************************/
    ret = listen(server_sock, backlog);
    if (ret == -1){
        log_fatal("bind(): [%m]");
        close(server_sock);
        return -1;
    }
    log_info("Server waiting for a client...");

    return server_sock;
}

int parse_argv(int argc, char **argv, int *timeout, int *debug_level) {
    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "ht:D:")) != -1) {
        switch (c) {
            case 'h':
                print_usage(argv[0]);
                return -1;
            case 't':
                *timeout = (int) strtol(optarg, NULL, 10) * 1000;
                break;
            case 'D':
                *debug_level = (int) strtol(optarg, NULL, 10);
                break;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    return 0;
}


#if 0
ret = pipe(tmp_fds);
    if( ret == -1  ) {
        /* an error occurred */
        //...
    }
    client[0].parent_stdin = tmp_fds[0];
    client[0].child_stdout = tmp_fds[1];

    ret = pipe(tmp_fds);
    if( ret == -1  ) {
        /* an error occurred */
        //...
    }
    client[0].parent_stdout = tmp_fds[1];
    client[0].child_stdin = tmp_fds[0];

    child_pid[0] = fork();
    if (child_pid[0] == -1) {      /* fork() failed */
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if ( child_pid[0] == 0 ) {
        sleep(1);
        printf( "Child process print...\n" );

        char buf[128];
        char *argv_local[3] = {EXEC_1, "1st_arg", NULL};

        close(client[0].parent_stdin);
        close(client[0].parent_stdout);

        remap_pipe_stdin_stdout(client[0].child_stdin, client[0].child_stdout);

        execvp( EXEC_1, argv_local );

    } else {
        printf( "Parent process print... child's pid is %d\n", child_pid[0] );

        char buf[128] = {0};

        close(client[0].child_stdin);
        close(client[0].child_stdout);

        write(client[0].parent_stdout, "Hello world\n", 12);
        close(client[0].parent_stdout);

        nbytes = read(client[0].parent_stdin, buf, sizeof(buf));
        printf("Parent process print... %s \n", buf);

        wpid = waitpid(child_pid[0], &ret, WUNTRACED | WCONTINUED);
    }

#endif