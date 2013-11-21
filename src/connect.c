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

typedef  int f_connect;
#define MAXFD 100


#define UNUSED_FD -1

typedef struct wrappedFd {
    int fd;

} fd_t;

fd_t wrappedFds[MAXFD];

static void wrap_init(void) __attribute__((constructor));
int portFromAddress(void *addr, int addrlen, int type);

static void wrap_init(void) {
    int i;
    real_connect = dlsym(RTLD_NEXT, "connect");
	real_socket = dlsym(RTLD_NEXT, "socket");
	real_close= dlsym(RTLD_NEXT, "close");
    
    for (i = 0; i < MAXFD; i++) {
        wrappedFds[i].fd = UNUSED_FD;
    }
}
int wrapFd(int fd) {
    int idx;

    idx = findFreeFdSlot();
    
    sshy_log( "wrapping %d, idx: %d\n", fd, idx);

    if (idx >= 0) {
        wrappedFds[idx].fd = fd;
        return idx;
    } else {
        return -1;
    }
}



int findFdWrapSlot(int fd) {
    int i;

     for (i = 0; i < MAXFD; i++) {
        if (wrappedFds[i].fd == fd) {
            return i;
        }
    }

    sshy_log( "findFdWrapSlot didnt find slot\n");
    
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
	int wrapperFd;
	int idx;
	
    fd = real_socket(domain, type, protocol);
    
	if (type & SOCK_STREAM) {
        idx = wrapFd(fd);
        sshy_log( "socket idx: %d\n", idx);
	} 
        
	return fd;
	
}

void destroySshSession(struct sshSession *sshSession) {
    ssh_free(sshSession);
}


int close(int fd) {
    int idx;
    
    sshy_log("close %d\n", fd);
    
    idx = findFdWrapSlot(fd);

    if (idx >= 0) {
        sshy_log( "closing tunneld socket %d\n", fd);
        wrappedFds[idx].fd = UNUSED_FD;
    }
    return real_close(fd);
}

static setTunnelPortAndHost(const struct sockaddr *addr, int port) {
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
    int wrappedFd;
	struct sshSession *sshSession;
    int ret;
    struct sockaddr *addr = alloca(addrlen);
    
    memcpy(addr, _addr, addrlen);
	
	sshy_log( "connect begin %d\n", sockfd);
    fflush(stderr);
	
	
	
	if (findFdWrapSlot(sockfd) >= 0) {
        
        char hostnamebuf[1024];
        const char *hostname;
        int port;
        void *addrptr;
        int idx;
        int localTunnelEntryPort;
        
        
        
        sshy_log( "connect %d with having sshsession\n", sockfd);
        
        addrptr = addr->sa_family == AF_INET ? (void *)  &((struct sockaddr_in *) addr)->sin_addr.s_addr : (void *) &((struct sockaddr_in6 *) addr)->sin6_addr;
        
        hostname = hostnameFromAddress(hostnamebuf, sizeof(hostnamebuf), addrptr, addrlen, addr->sa_family);
        port = portFromAddress((void*) addr, addrlen, addr->sa_family);
		
		localTunnelEntryPort = tunnelPort(hostname, port);
        
        setTunnelPortAndHost(addr, localTunnelEntryPort);
        
        sshy_log("about to connect to tunnelport %d\n", localTunnelEntryPort);
        
        ret = real_connect(sockfd, addr, addrlen);
        
        sshy_log("connect to tunnelport %d returned %d\n", localTunnelEntryPort, ret);
        
	} else {
		ret = real_connect(sockfd, addr, addrlen);
	}
	
	sshy_log( "connect end %d, returned %d\n", sockfd, ret);
    fflush(stderr);
    
	
	return ret;
}

const char *hostnameFromAddress(char *buf, int buflen, const void *addr, int addrlen, int type) {
    sshy_log( "hostnameFromAddress, type: %d\n", type);
    return inet_ntop(type, addr, buf, buflen);
}

int portFromAddress(void *addr, int addrlen, int type) {
    struct sockaddr_in *inetAddress = (struct sockaddr_in *) addr;
    
    return ntohs(inetAddress->sin_port);
}

