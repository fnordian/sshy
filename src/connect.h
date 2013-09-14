#ifndef H_CONNECT
#define H_CONNECT


int findFreeFdSlot();
int wrapFd(int fd);
int findFdWrapSlot(int fd);
char *hostnameFromAddress(char *buf, int buflen, const void *addr, int addrlen, int type);

#endif