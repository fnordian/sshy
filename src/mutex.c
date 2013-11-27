#include <stdio.h>

#include <sys/sem.h>
#include "mutex.h"

  #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>

#define MAXMUTEX 10
int volatile mutexes[MAXMUTEX] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };

int createMutex() {
    int i;
    
    for (i = 0; i < MAXMUTEX; i++) {
        if (mutexes[i] == -1) {
            mutexes[i] = 1;
            return i;
        }
    }
    
    return -1;
}

void get_mutex(int semid) {
    volatile int ret;
    
    while (!(ret = __sync_bool_compare_and_swap(&mutexes[semid], 1, 0) )) {
    
    }
}
       
void release_mutex(int semid)
{
    mutexes[semid] = 1;
}
       
       
/*int createMutex() {
    key_t semkey;
    int mutex;
    
    mutex = semget(IPC_PRIVATE, 1, 0777);
    
    
    if (mutex >= 0) {
        fprintf(stderr, "created mutex %d\n", mutex);
    } else {
        perror("semget");
    }
    
    semctl(mutex,0,SETVAL,1);
    
    return mutex;
}

void get_mutex(int semid) {
        
    struct sembuf sb;
    
    sb.sem_num=0;
    sb.sem_op=-1;
    sb.sem_flg=0;
    semop(semid, &sb, 1);
}

void release_mutex(int semid) {
    
    struct sembuf sb;
    
    sb.sem_num=0;
    sb.sem_op=1;
    sb.sem_flg=0;
    semop(semid, &sb, 1);
}*/