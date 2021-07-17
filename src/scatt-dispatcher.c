/*
 * Front-end for Polisy Server that takes request
 * ( echo "get-srv-time.sh aaa bbb ccc" | socat -t 10 - UNIX:/tmp/dispatcher.sock )
 * from Thin Client firmware and runs apropriaete Bash script
 * which  return answer to the requester.
 * ( 2021-07-17 07:36:03 )
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/time.h>


#include "tcp_connection.h"
#include "remap_pipe.h"
#include "log.h"
#include "version.h"

/*  Temporary defines!!!  */
#define SOCKET_PATH  "/tmp/dispatcher.sock"


#define MEMZERO(x)	memset(&(x), 0, sizeof (x));

#define BUFF_SZ  4096

#define TIMEOUT_SEC  10
#define MAX_CONCURRENT_CLIENTS  32
#define SOCK_LEN_MAX  128

#define EXEC_MAX_ARGS 64
#define EXEC_ARGS_LEN 1024
#define EXEC_CONST_PATH "/opt/swemel/Psrv/"

const char *script_list[] = {"get-device-perm.sh",
                             "get-srv-time.sh",
                             "get-user-resolution.sh",
                             "sshfs-run.sh",
                             "aux1", NULL};

struct new_client {
    int fd;
    int parent_stdin;
    int child_stdout;
    pid_t child_pid;
    time_t start_at;

    int one_time_exec_flag;
} client[MAX_CONCURRENT_CLIENTS];


void print_usage(char *util_name) {
    fprintf(stderr, "Ver.%s \n", VERSION);
    fprintf(stderr, "Usage: %s [-t] [-d]  unix:/path/to/socket \n", util_name);
    fprintf(stderr, "\t -t - timeout to get answer from bash script \n");
    fprintf(stderr, "\t -d - Debug level [0..5] \n");
    fprintf(stderr, "\t /path/to/socket - Unix socket to listen on \n");
}


int parse_argv(int argc, char **argv, int *timeout,
               int *debug_level, char *sockpath);
int prepare_exec_datum(char *tmp_str, int *argc, char **argv);
void free_client(int idx);
void free_clients_by_timeout(int timeout);


int main(int argc, char **argv)
{
    int ret;
    int idx;
    int nbytes;
    int server_fd;
    struct timeval tv;

    char exec_arg_str[EXEC_ARGS_LEN];
    int  exec_argc;
    char *exec_argv[EXEC_MAX_ARGS];
    char exec_name[FILENAME_MAX] = {0};

    struct sockaddr_un client_sockaddr;
    unsigned int len = sizeof(client_sockaddr);

    /************************************/
    /*     Set defaults                 */
    /************************************/
    int timeout = TIMEOUT_SEC;
    int debug_level = -1;
    char sock_path[SOCK_LEN_MAX] = {0};


    ret = parse_argv(argc, argv, &timeout, &debug_level, sock_path);
    if( ret != 0 )
        exit(-1);

    log_set_quiet(1);
    if( debug_level >= 0 ) {
        log_set_quiet(0);
        log_set_level(debug_level);
    }


    server_fd = unix_sock_server(sock_path);
    if( server_fd < 0 ){
        return -1;
    }


    int pollResult;
    struct pollfd pollfds[2 * MAX_CONCURRENT_CLIENTS + 1];  // 2x means every client will have 2 fd
                                                            // +1 means all time present Server fd
    MEMZERO(pollfds);
    MEMZERO(client);

    pollfds[0].fd = server_fd;
    pollfds[0].events = POLLIN;

    /*********************************/
    /*           Main loop           */
    /*********************************/
    while (1)
    {
        free_clients_by_timeout(timeout);

        int fds_count = 1;
        for (idx = 1; idx < MAX_CONCURRENT_CLIENTS; idx++) {
            if (client[idx].fd > 0) {
                pollfds[2*idx - 1].fd = client[idx].fd;
                pollfds[2*idx - 1].events = POLLIN;

                if( client[idx].parent_stdin > 0 ) {
                    pollfds[2 * idx].fd = client[idx].parent_stdin;
                } else {
                    pollfds[2 * idx].fd = -1;
                }
                pollfds[2*idx].events = POLLIN;

                fds_count += 2;
            }
        }
        log_trace("fds_count = %d", fds_count);

        pollResult = poll(pollfds, fds_count, 1 * 1000);    // == 1 sec.
        log_trace("pollResult = %d", pollResult);

        // ----------- Error case -----------
        if (pollResult < 0) {
            log_warn("poll(%m)");
            continue;
        }

        // ----------- Timeout case -----------
        if (pollResult == 0) {
            log_trace("poll(timeout = %d)", timeout);
            continue;
        }


        // ----------- New client come -----------
        if (pollfds[0].revents & POLLIN) {
            pollfds[0].revents = 0;

            int newsockfd = accept(server_fd, (struct sockaddr *) &client_sockaddr, &len);
            if (newsockfd <= 0) {
                log_warn("accept(): {%m]");
            } else {
                log_info("Accept new client (fd = %d)", newsockfd);

                for (idx = 1; idx < MAX_CONCURRENT_CLIENTS; idx++) {
                    if (client[idx].fd == 0) {
                        log_trace("Client[%d] is free. Work with them.", idx);

                        int tmp_fds[2];
                        ret = pipe(tmp_fds);
                        if (ret == -1) {
                            log_fatal("%s[#%d]: pipe()", __func__);
                            break;
                        }
                        client[idx].parent_stdin = tmp_fds[0];
                        client[idx].child_stdout = tmp_fds[1];

                        client[idx].fd = newsockfd;

                        gettimeofday(&tv, NULL);
                        client[idx].start_at = tv.tv_sec;

                        log_trace("client[%d].client_fd = %d", idx, client[idx].fd);
                        log_trace("client[%d].parent_stdin = %d", idx, client[idx].parent_stdin);
                        log_trace("client[%d].child_stdout = %d", idx, client[idx].child_stdout);
                        log_trace("client[%d].start_at = %lu", idx, client[idx].start_at);

                        break;
                    }
                }
            }
        }


        // ----------- Client connection closed by peer -----------
        for (idx = 1; idx < MAX_CONCURRENT_CLIENTS; idx++) {
            if( pollfds[2*idx - 1].revents & POLLHUP ) {
                log_info("Client #%d closed connection oneself ", idx);

                pollfds[2*idx - 1].revents = 0;
                free_client(idx);
            }
        }


        // ----------- Get data from client and exec bash script -----------
        for (idx = 1; idx < MAX_CONCURRENT_CLIENTS; idx++) {
            if( pollfds[2*idx - 1].revents & POLLIN ) {
                log_debug("Client #%d has data. Read it", idx);
                pollfds[2*idx - 1].revents = 0;

                /*
                 * Work around of 'socat' utility strange behavior
                 * which send the same data meny times.
                 * So I run new Bash script only once!
                 */
                if( client[idx].one_time_exec_flag != 0 )
                    continue;
                client[idx].one_time_exec_flag = 1;

                nbytes = read(client[idx].fd, exec_arg_str, sizeof(exec_arg_str) - 1);
                if (nbytes < 0) {
                    log_fatal("Client #%d connection closed by peer ", idx);
                    free_client(idx);
                    continue;
                }
                exec_arg_str[nbytes - 1] = '\0';
                log_debug("exec_arg_str: '%s'", exec_arg_str);

                ret = prepare_exec_datum(exec_arg_str, &exec_argc, exec_argv);
                if( ret != 0 ) {
                    free_client(idx);
                    continue;
                } else {
                    // Exec bash script
                    sprintf(exec_name, "%s%s", EXEC_CONST_PATH, exec_argv[0]);
                    log_debug("..................");
                    log_debug("   Exec name: '%s'", exec_name);
                    log_debug("   exec_argc = %d", exec_argc);
                    for (int i = 0; i <= exec_argc; i++)
                        log_debug("   argv[%d] = '%s'", i, exec_argv[i]);


                    pid_t pid = fork();
                    if( pid  == -1 ) {      /* fork() failed */
                        log_fatal("fork() [%m]");
                        free_client(idx);
                        continue;
                    }

                    if( pid == 0 ) {
                        log_trace("Child (bash script) process starts for client #%d", idx);

                        close(client[idx].parent_stdin);
                        close(0);
                        dup2(client[idx].child_stdout, 1);
                        //remap_pipe_stdin_stdout(child_stdin, child_stdout);

                        execvp(exec_name, exec_argv);
                        free_client(idx);
                        continue;

                    } else {
                        log_debug("Main process continues... child's pid is #%d", pid);
                        client[idx].child_pid = pid;

                        close(client[idx].child_stdout);
                    }
                }

            }
        }


        // ----------- Get data from Bash script and redirect to client -----------
        for (idx = 1; idx < MAX_CONCURRENT_CLIENTS; idx++) {
            if (pollfds[2 * idx].revents & POLLIN) {
                log_debug("Bash script #%d send data. Read it", idx);
                pollfds[2 * idx].revents = 0;

                char buff[BUFF_SZ] = {0};

                nbytes = read(client[idx].parent_stdin, buff, sizeof(buff));
                if (nbytes < 0) {
                    log_fatal("Bash script #%d send wrong data ", idx);
                    free_client(idx);
                    continue;
                }
                //exec_arg_str[nbytes - 1] = '\0';
                log_debug("Bash data: '%s'", buff);

                log_debug("Send this data to client #%d", idx);
                int nwrite = write(client[idx].fd, buff, nbytes);
                if( nwrite == nbytes )
                    log_info("Client #%d get data from Bash script", idx);
                else
                    log_info("Client #%d NOT get data from Bash script", idx);

                free_client(idx);
            }
        }
    } // End while(1)

}   // End main()




void free_client(int idx) {
    int ret;

    close(client[idx].fd);
    close(client[idx].parent_stdin);
    close(client[idx].child_stdout);


    // Kill child if exist
    if( client[idx].child_pid > 0 ) {
        log_debug("SIGKILL process #%d", client[idx].child_pid);
        ret = kill(client[idx].child_pid, SIGKILL);
        //ret = kill(client[idx].child_pid, SIGTERM);
        //log_trace("Kill result: %d", ret);
    }


    pid_t returnStatus;
    pid_t waitpid_ret = waitpid(client[idx].child_pid, &returnStatus, 0);
    if( waitpid_ret == client[idx].child_pid)
        log_debug("Process #%d killed successful", waitpid_ret);
    else
        log_debug("Process #%d NOT killed successful!!! Alarm!!!", waitpid_ret);

    memset(&client[idx], 0, sizeof(client[idx]));
}


void free_clients_by_timeout(int timeout) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    time_t curr_time = tv.tv_sec;

    for( int idx = 1; idx < MAX_CONCURRENT_CLIENTS; idx++ ) {
        if( client[idx].fd > 0  &&
            curr_time - client[idx].start_at >= timeout)
        {
            log_debug("It's time to kill client #%d by timeout", idx);

            free_client(idx);
        }
    }

    pid_t returnStatus;
    waitpid(-1, &returnStatus, WNOHANG); // Just for any case =)
}


int prepare_exec_datum(char *tmp_str, int *argc, char **argv) {
    int idx = 0;

    char *token = strtok(tmp_str, " ");
    while (token != NULL && idx < EXEC_MAX_ARGS - 1) {
        argv[idx] = token;
        idx++;
        token = strtok(NULL, " ");
    }
    argv[idx] = NULL;
    *argc = idx;

    for ( int i = 0;; i++ ) {
        if ( script_list[i] == NULL ) {
            log_warn("Not support script to execute: '%s'", argv[0]);
            return -1;
        }

        if ( strcmp(argv[0], script_list[i]) == 0 ) {
            log_debug("Support script to execute: '%s'", argv[0]);

            //for (int ii = 0; ii <= *argc; ii++)
            //    log_trace("   argv[%d] = '%s'", ii, argv[ii]);

            return 0;
        }
    }
}





int parse_argv(int argc, char **argv, int *timeout,
               int *debug_level, char *sockpath)
{
    if( argc == 1) {
        print_usage(argv[0]);
        return -1;
    }


    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "ht:d:")) != -1) {
        switch (c) {
            case 'h':
                print_usage(argv[0]);
                return -1;
            case 't':
                *timeout = (int) strtol(optarg, NULL, 10);
                if( *timeout < 0 || *timeout > 1000) {
                    fprintf(stderr, "A problem with parameter 'timeout'\n");
                    return -1;
                }
                break;
            case 'd':
                *debug_level = (int) strtol(optarg, NULL, 10);
                if( *debug_level < LOG_TRACE || *debug_level > LOG_FATAL ) {
                    fprintf(stderr, "A problem with parameter 'Debug level'\n");
                    return -1;
                }
                break;
            default:
                print_usage(argv[0]);
                fprintf(stderr, "\n Unknown parametr '%c' \n", (char)c);
                return -1;
        }
    }

    // Parse Unix-sock path
    char *addr_str = strdup(argv[argc-1]);

    char *colon_ptr = strchr(addr_str, ':');
    if (!colon_ptr) {
        fprintf(stderr, "A problem with parameter unix:/sock/path\n");
        free(addr_str);
        return -1;
    }

    *colon_ptr = '\0';


    if (strncmp(addr_str, "unix", 4) != 0) {
        fprintf(stderr, "A problem with parameter unix:/sock/path\n");
        free(addr_str);
        return -1;
    }

    if( strlen(colon_ptr + 1) >= SOCK_LEN_MAX ) {
        fprintf(stderr, "A problem with parameter unix:/sock/path\n");
        free(addr_str);
        return -1;
    }

    strcpy(sockpath, colon_ptr + 1);
    free(addr_str);

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