#ifndef H_MUTEX
#define H_MUTEX

int createMutex();
void get_mutex(int semid);
void release_mutex(int semid);
#endif