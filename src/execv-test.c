/*
 * Tiny partial "socat" replacement from scratch
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

#define EXEC_MAX_ARGS 64
#define EXEC_CONST_PATH "/opt/swemel/Psrv/"

const char *script_list[] = {"get-device-perm.sh", "get-srv-time.sh", "get-user-resolution.sh", "sshfs-run.sh", "aux1", NULL};

int get_bash_script_to_exec(int client_fd, char *tmp_str, int *argc, char **argv) {
    int idx = 0;

    char *token = strtok(tmp_str, " ");
    while (token != NULL && idx < EXEC_MAX_ARGS - 1) {
        argv[idx] = token;
        log_trace("argv[%d] = '%s'", idx, argv[idx]);
        idx++;
        token = strtok(NULL, " ");
    }
    argv[idx] = NULL;
    *argc = idx;

    for ( int i = 0;; i++ ) {
        if ( script_list[i] == NULL ) {
            log_warn("Not supported script to execute: '%s'", argv[0]);
            return -1;
        }

        if ( strcmp(argv[0], script_list[i]) == 0 ) {
            log_debug("Supported script to execute: '%s'", argv[0]);
            return 0;
        }
    }
}

int main(int argc, char **argv)
{
    char tmp_str[] = "get-device-perm.sh  00000 username=a1 mac=10:15:20:25:30 dev_class=usb-storage dev_id=AAA:9001";

    int exec_argc = 0;
    char *exec_argv[EXEC_MAX_ARGS];
    char exec_name[FILENAME_MAX] = {0};
    int ret;


    ret = get_bash_script_to_exec(7, tmp_str, &exec_argc, exec_argv);
    if( ret != 0 )
        return -1;

    sprintf(exec_name, "%s%s", EXEC_CONST_PATH, exec_argv[0]);

    log_trace("..................");
    log_trace("Exec name: '%s'", exec_name);
    for (int i = 0; i <= exec_argc; i++)
        log_trace("argv[%d] = '%s'", i, exec_argv[i]);


    return 0;
}
