#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>

#include <stdio.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <alloca.h>
#include <stdarg.h>
#include <sys/select.h>

#include "connect.h"
#include "ssh.h"
#include "log.h"
#include "tunnelservice.h"
#include "mutex.h"

typedef  int f_connect;
#define MAXFD 100


#define UNUSED_FD -1

typedef struct wrappedFd {
    int fd;

} fd_t;

fd_t wrappedFds[MAXFD];

static int initialized = 0;
static int mutex;

static void wrap_init(void) __attribute__((constructor));
int portFromAddress(void *addr, int addrlen, int type);

static void wrap_init(void) {
    int i;
    volatile int _initialized;
    
    _initialized = __sync_fetch_and_add(&initialized, 1);
    
    if (_initialized) {
        return;
    }
    
    mutex = createMutex();
    
    real_connect = dlsym(RTLD_NEXT, "connect");
	real_socket = dlsym(RTLD_NEXT, "socket");
	real_close= dlsym(RTLD_NEXT, "close");
    
    for (i = 0; i < MAXFD; i++) {
        wrappedFds[i].fd = UNUSED_FD;
    }
}
int wrapFd(int fd) {
    int idx;

    get_mutex(mutex);
    
    idx = findFreeFdSlot();
    
    if (idx >= 0) {
        wrappedFds[idx].fd = fd;
        release_mutex(mutex);
        return idx;
    } else {
        release_mutex(mutex);
        return -1;
    }
}



int findFdWrapSlot(int fd) {
    int i;

    get_mutex(mutex);
    
    for (i = 0; i < MAXFD; i++) {
        if (wrappedFds[i].fd == fd) {
            release_mutex(mutex);
            return i;
        }
    }

    release_mutex(mutex);
    
    return -1;
}


int findFreeFdSlot() {
    int i;

    for (i = 0; i < MAXFD; i++) {
        if (wrappedFds[i].fd == UNUSED_FD) {
            return i;
        }
    }

    return -1;
}

int socket(int domain, int type, int protocol) {
	int fd;
	int idx;
	
    fd = real_socket(domain, type, protocol);
    
	if (type & SOCK_STREAM) {
        idx = wrapFd(fd);
	} 
        
	return fd;
	
}

void destroySshSession(struct sshSession *sshSession) {
    ssh_free(sshSession);
}


int close(int fd) {
    int idx;
    
    idx = findFdWrapSlot(fd);

    if (idx >= 0) {
        wrappedFds[idx].fd = UNUSED_FD;
    }
    return real_close(fd);
}

static void setTunnelPortAndHost(const struct sockaddr *addr, int port) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *inaddr = (struct sockaddr_in *) addr;
        inaddr->sin_port = port;
        inaddr->sin_addr.s_addr = 0x0100007F; // localhost
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *inaddr6 = (struct sockaddr_in6 *) addr;
        inaddr6->sin6_port = port;
        memcpy(&inaddr6->sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback));
    }
}

int connect(int sockfd, const struct sockaddr *_addr, socklen_t addrlen) {
	int ret;
    struct sockaddr *addr = alloca(addrlen);
    
    memcpy(addr, _addr, addrlen);
	
	if (findFdWrapSlot(sockfd) >= 0 && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        int localTunnelEntryPort;
        
        localTunnelEntryPort = requestTunnel(_addr, addrlen);
        
        setTunnelPortAndHost(addr, localTunnelEntryPort);
        
        ret = real_connect(sockfd, addr, addrlen);
	} else {
		ret = real_connect(sockfd, addr, addrlen);
	}
	
	return ret;
}


