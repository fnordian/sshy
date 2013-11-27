#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <unistd.h>

#include "log.h"
#include "mutex.h"

static void log_init(void) __attribute__((constructor));


static FILE *logfile;

static int semid;
static int initialized = 0;

static void log_init() {
    char *logfilename;
    
    volatile int _initialized;
    
    _initialized = __sync_fetch_and_add(&initialized, 1);
    
    logfile = NULL;
    
    if (_initialized) {
        return;
    }
    
    logfilename = getenv("SSHY_LOGFILE");
    
    if (logfilename != NULL && strlen(logfilename) > 0) {
        logfile = fopen(logfilename, "a");
    }
    
    semid = createMutex();
}    

int sshy_log(const char *format, ...) {
    va_list ap;
    int ret;
    
    get_mutex(semid);
    va_start(ap, format);    
    
    if (logfile != NULL) {
        fprintf(logfile,"[%d] - ", getpid());
        ret = vfprintf(logfile, format, ap);
    }
    
    va_end(ap); /* Cleanup the va_list */
    
    release_mutex(semid);
    return ret;
}