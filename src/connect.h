#ifndef H_CONNECT
#define H_CONNECT


int findFreeFdSlot();
int wrapFd(int fd);
int findFdWrapSlot(int fd);
const char *hostnameFromAddress(char *buf, int buflen, const void *addr, int addrlen, int type);

int(* real_connect)(int, const struct sockaddr *, socklen_t);

int(* real_socket)(int domain, int type, int protocol);

int(* real_close)(int fd);


#endif
