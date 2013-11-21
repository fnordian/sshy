#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include "log.h"

static void log_init(void) __attribute__((constructor));


static FILE *logfile;

static int semid;

static void log_init() {
    char *logfilename;
    logfile = NULL;
    
    logfilename = getenv("SSHY_LOGFILE");
    
    if (logfilename != NULL && strlen(logfilename) > 0) {
        key_t semkey;
        logfile = fopen(logfilename, "w");
        semkey = ftok(logfilename, 0);
        semid = semget(semkey, 1, IPC_CREAT | 0666);
        semctl(semid,0,SETVAL,1);
    }
}    


static void get_mutex() {
    
    struct sembuf sb;
    
    sb.sem_num=0;
    sb.sem_op=-1; //Allocate resources
    sb.sem_flg=0;
    semop(semid, &sb, 1);
}

static void release_mutex() {
    
    struct sembuf sb;
    
    sb.sem_num=0;
    sb.sem_op=1; //Allocate resources
    sb.sem_flg=0;
    semop(semid, &sb, 1);
}

int sshy_log(const char *format, ...) {
    va_list ap;
    int ret;
    va_start(ap, format);    
    
    if (logfile != NULL) {
        get_mutex();
        fprintf(logfile,"[%d] - ", getpid());
        ret = vfprintf(logfile, format, ap);
        release_mutex();
    }
    
    va_end(ap); /* Cleanup the va_list */
    
    return ret;
}