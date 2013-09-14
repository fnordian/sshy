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
#include <netdb.h>
#include <alloca.h>
#include <stdarg.h>
#include <sys/select.h>

#include "connect.h"
#include "ssh.h"

typedef  int f_connect;
#define MAXFD 100

int(* real_connect)(int, const struct sockaddr *, socklen_t);

ssize_t(* real_read)(int fd, void *buf, size_t count);

ssize_t(* real_write)(int fd, const void *buf, size_t count);

int(* real_socket)(int domain, int type, int protocol);

int(* real_poll)(struct pollfd *fds, nfds_t nfds, int timeout);

int(* real_shutdown)(int sockfd, int how);

int(* real_close)(int fd);

ssize_t(* real_sendto)(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t(* real_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t(* real_send)(int sockfd, const void *buf, size_t len, int flags);

ssize_t(* real_recv)(int sockfd, void *buf, size_t len, int flags);


int(* real_getsockopt)(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);

int(* real_fcntl) (int fd, int cmd, ... /* arg */ );

int(* real_select) (int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);


typedef struct wrappedFd {
    int fd;
    int wrappedFd;
	struct sshSession *sshSession;
    int blocking;
} fd_t;

fd_t wrappedFds[MAXFD];

static void wrap_init(void) __attribute__((constructor));
int portFromAddress(void *addr, int addrlen, int type);

static void wrap_init(void) {
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_read = dlsym(RTLD_NEXT, "read");
    real_write = dlsym(RTLD_NEXT, "write");
	real_socket = dlsym(RTLD_NEXT, "socket");
	real_poll = dlsym(RTLD_NEXT, "poll");
	real_shutdown = dlsym(RTLD_NEXT, "shutdown");
	real_close= dlsym(RTLD_NEXT, "close");
	real_sendto = dlsym(RTLD_NEXT, "sendto");
	real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	real_send = dlsym(RTLD_NEXT, "send");
	real_recv = dlsym(RTLD_NEXT, "recv");
    real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    real_fcntl = dlsym(RTLD_NEXT, "fcntl");
    real_select = dlsym(RTLD_NEXT, "select");
}

int findFreeFdSlot() {
    int i;

    for (i = 0; i < MAXFD; i++) {
        if (wrappedFds[i].wrappedFd == 0) {
            return i;
        }
    }

    return -1;
}

int generateWrapperFd() {
    return open("/dev/null", O_RDONLY);
}

int wrapFd(int fd) {
    int idx;

    idx = findFreeFdSlot();

    if (idx >= 0) {
        wrappedFds[idx].wrappedFd = fd;
        wrappedFds[idx].blocking = 1;
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

    fprintf(stderr, "findFdWrapSlot didnt find slot\n");
    
    return -1;
}

int findFdWrappedSlot(int fd) {
    int i;

    for (i = 0; i < MAXFD; i++) {
        if (wrappedFds[i].wrappedFd == fd) {
            return i;
        }
    }

    fprintf(stderr, "findFdWrappedSlot didnt find slot\n");
    
    return -1;
}

int wrappedFdForWrapperFd(int wrappedFd) {
	int idx;
	
	idx = findFdWrapSlot(wrappedFd);
	
	if (idx < 0) {
		return wrappedFd;
	} else {
		return wrappedFds[idx].wrappedFd;		
	}
}

struct sshSession *sshSessionForWrapperFd(wrappedFd) {
	int idx;
	
	idx = findFdWrapSlot(wrappedFd);
	
	if (idx < 0) {
		return NULL;
	} else {
        fprintf(stderr, "sshsession for idx: %d\n", idx);
		return wrappedFds[idx].sshSession;		
	}
}

int wrapperFdForWrappedFd(int wrapperFd) {
	int idx;
	
	idx = findFdWrappedSlot(wrapperFd);
	
	if (idx < 0) {
		return wrapperFd;
	} else {
		return wrappedFds[idx].fd;		
	}
}

int connectToServer(const char *hostname, int port) {
	struct sockaddr_in serveraddr;
    struct hostent *server;
	int sockfd;
    
	server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        return -1;
    }

    sockfd = real_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        return -1;
    
    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(port);
	
    /* connect: create a connection with the server */
    if (real_connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
      return -1;
	
	return sockfd;
}

struct sshSession *createSshSession() {
	struct sshSession *sshSession = calloc(1, sizeof(struct sshSession));
    
	
	strncpy(sshSession->username, getenv("SSHY_USER"), sizeof(sshSession->username));
	strncpy(sshSession->password, getenv("SSHY_PASS"), sizeof(sshSession->password));
	
	sshSession->fd = connectToServer(getenv("SSHY_HOST"), 22);
    
	
	return sshSession;
}

int socket(int domain, int type, int protocol) {
	int fd;
	int wrapperFd;
	int idx;

	
	
	if (type & SOCK_STREAM) {
        struct sshSession *sshSession = createSshSession();
        
        fd = sshSession->fd;
	
		idx = wrapFd(fd);
        
        fprintf(stderr, "socket idx: %d\n", idx);
        
		wrapperFd = generateWrapperFd();
		
		wrappedFds[idx].fd = wrapperFd;
				
		wrappedFds[idx].sshSession = sshSession;
		
		
		return wrapperFd;
	} else {
        fd = real_socket(domain, type, protocol);
		return fd;
	}
}

void destroySshSession(struct sshSession *sshSession) {
    real_close(sshSession->fd);
    ssh_free(sshSession);
}

int shutdown(int sockfd, int how) {
	fprintf(stderr, "foo shutdown %d!!!!!!!!!\n", sockfd);    
	return real_shutdown(wrappedFdForWrapperFd(sockfd), how);
}

int close(int fd) {
    int idx;
    
	fprintf(stderr, "foo close!!!!!!!!!\n");
    
    idx = findFdWrapSlot(fd);
    
    if (idx >= 0) {
        fprintf(stderr, "foo ssh close!!!!!!!!!\n");
        destroySshSession(wrappedFds[idx].sshSession);
        wrappedFds[idx].fd = 0;
        wrappedFds[idx].sshSession = NULL;
        wrappedFds[idx].wrappedFd = 0;
        
        return 0;
    }
    return real_close(fd);
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int wrappedFd;
	struct sshSession *sshSession;
    int ret;
	
	fprintf(stderr, "connect begin %d\n", sockfd);
    fflush(stderr);
	
	wrappedFd = wrappedFdForWrapperFd(sockfd);
	
	sshSession = sshSessionForWrapperFd(sockfd);
	
	if (sshSession) {
        
        char hostnamebuf[1024];
        const char *hostname;
        int port;
        void *addrptr;
        int idx;
        
        idx = findFdWrapSlot(sockfd);
        
        fprintf(stderr, "connect %d with having sshsession\n", sockfd);
        
        addrptr = addr->sa_family == AF_INET ? (void *)  &((struct sockaddr_in *) addr)->sin_addr.s_addr : (void *) &((struct sockaddr_in6 *) addr)->sin6_addr;
        
        hostname = hostnameFromAddress(hostnamebuf, sizeof(hostnamebuf), addrptr, addrlen, addr->sa_family);
        port = portFromAddress((void*) addr, addrlen, addr->sa_family);
		
		ret = ssh_connect(sshSession, sshSession->fd, hostname, port);
        ssh_set_block(sshSession, wrappedFds[idx].blocking);
	} else {
		ret = real_connect(wrappedFd, addr, addrlen);
	}
	
	fprintf(stderr, "connect end %d\n", sockfd);
    fflush(stderr);
    
	
	return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
	
	struct sshSession *sshSession;
    fprintf(stderr, "read wrapper (%d)\n", fd);
	
	
	sshSession = sshSessionForWrapperFd(fd);
	
	if (sshSession != NULL) {
        int ret;
		ret = ssh_read(sshSession, buf, count);
        
        fprintf(stderr, "wrapped read about to return %d\n", ret);
        
        return ret;
	} else {
		return real_read(fd, buf, count);
	}
}

ssize_t write(int fd, const void *buf, size_t count) {
	
	struct sshSession *sshSession;
	
    fprintf(stderr, "write wrapper (%d)\n", fd);
	
	
	sshSession = sshSessionForWrapperFd(fd);
	
	if (sshSession != NULL) {
		return ssh_write(sshSession, buf, count);
	} else {
		return real_write(fd, buf, count);
	}
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
	
	nfds_t i;
	int ret;

	fprintf(stderr, "polllll!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	
	for (i = 0; i < nfds; i++) {
        int idx;
        int fdback= fds[i].fd;
      
        idx = findFdWrapSlot(fds[i].fd);
        
		fds[i].fd = wrappedFdForWrapperFd(fds[i].fd);
        
        
        
        if (idx >= 0 && wrappedFds[idx].sshSession && fds[i].events & POLLIN) {
            fprintf(stderr, "%d is wrapped into %d. special  poll...........\n", fds[i].fd, fdback);
            if (ssh_read_poll(wrappedFds[idx].sshSession, wrappedFds[idx].blocking)) {
                fds[i].revents = POLLIN;
                return 1;
            }
        } else {
            fprintf(stderr, "%d is not wrapped. default poll...........\n", fds[i].fd);
        }
	}
	
	ret = real_poll(fds, nfds, timeout);
	
	for (i = 0; i < nfds; i++) {
		fds[i].fd = wrapperFdForWrappedFd(fds[i].fd);
	}
    fprintf(stderr, "poll returns %d\n", ret);
	return ret;
}
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
    
    struct sshSession *sshSession;
    
	sshSession = sshSessionForWrapperFd(sockfd);
    
    if (sshSession != NULL) {
        return ssh_write(sshSession, buf, len);
    } else {
        return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen) {
	
    struct sshSession *sshSession;
	fprintf(stderr, "recvfrom!!!!!!!!!!!!!!!!\n");
	
	sshSession = sshSessionForWrapperFd(sockfd);

    if (sshSession != NULL) {
            return ssh_read(sshSession, buf, len);
    } else {
        return real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    }
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    
    struct sshSession *sshSession;
    
    fprintf(stderr, "send wrapper (%d)\n", sockfd);
    
    
    sshSession = sshSessionForWrapperFd(sockfd);
    
    if (sshSession != NULL) {
        return ssh_write(sshSession, buf, len);
    } else {
        return real_send(sockfd, buf, len, flags);
    }
	
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    
    struct sshSession *sshSession;
    
    
    
    sshSession = sshSessionForWrapperFd(sockfd);
    
    fprintf(stderr, "recv wrapper (%d) %p\n", sockfd, sshSession);
    
    if (sshSession != NULL) {
        if (flags & MSG_PEEK) {
            return ssh_read_peek(sshSession, buf, len);
        } else {
            return ssh_read(sshSession, buf, len);
        }
    } else {
        return real_recv(sockfd, buf, len, flags);
    }
	
	
}


const char *hostnameFromAddress(char *buf, int buflen, const void *addr, int addrlen, int type) {
    fprintf(stderr, "hostnameFromAddress, type: %d\n", type);
    return inet_ntop(type, addr, buf, buflen);
}

int portFromAddress(void *addr, int addrlen, int type) {
    struct sockaddr_in *inetAddress = (struct sockaddr_in *) addr;
    
    return ntohs(inetAddress->sin_port);
}

int getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen) {
    
    int idx;
    
    idx = findFdWrapSlot(sockfd);
    
    fprintf(stderr, "getsockopt %d %d!!!!\n", sockfd, idx);
    
    if (idx >= 0) {
        
        if (level == SOL_SOCKET && optname == SO_ERROR) {
            bzero(optval, *optlen);
            return 0;
        } else {
            return real_getsockopt(sockfd, level, optname, optval, optlen);
        }
        
    } else {
        return real_getsockopt(sockfd, level, optname, optval, optlen);
    }
}

int fcntl (int fd, int cmd, ... /* arg */ ) {
    va_list argp;
    long longarg;
    void *ptrarg;
    int ret;
    int idx;
    
    va_start(argp, cmd);
    
    fprintf(stderr, "fcntl for %d\n", fd);
    
    switch(cmd) {
        case F_SETFL:
            idx = findFdWrapSlot(fd);
            longarg = va_arg(argp, long);
            if (idx >= 0) {
                
                
                fprintf(stderr, "fcntl for idx %d\n", idx);
                
                if (longarg & O_NONBLOCK) {
                    wrappedFds[idx].blocking = 0;
                } else {
                    wrappedFds[idx].blocking = 1;
                }
                if (wrappedFds[idx].sshSession) {
                    fprintf(stderr, "setting block on fd %d, which should be wrapped\n", fd);
                    ssh_set_block(wrappedFds[idx].sshSession, wrappedFds[idx].blocking);
                }
                ret = 0;
            } else {
                ret = real_fcntl(fd, cmd, longarg);
            }
            
            break;
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
        case F_SETFD:
        case F_SETOWN:
        case F_SETSIG:
        case F_SETLEASE:
        case F_NOTIFY:
        case F_SETPIPE_SZ:
            // long            
            longarg = va_arg(argp, long);
            ret = real_fcntl(fd, cmd, longarg);
            break;
        case F_GETFD:
        case F_GETFL:
        case F_GETOWN:
        case F_GETSIG:
        case F_GETLEASE:
        case F_GETPIPE_SZ:
            // void
            ret = real_fcntl(fd, cmd);
            break;
        case F_SETLK:
        case F_SETLKW:
        case F_GETLK:
        case F_GETOWN_EX:
        case F_SETOWN_EX:
            // ptr
            ptrarg = va_arg(argp, void*);
            ret = real_fcntl(fd, cmd, ptrarg);
            break;
        default:
            fprintf(stderr, "fcntln with unknown command %d\n", cmd);
            ret = -1;
            break;
    }
            
    va_end(argp);
            
    return ret;
}


int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout) {
    int idx;
    int ret;
    
    // readfds
    
    for (idx = 0; readfds && idx < MAXFD; idx++) {
        if (wrappedFds[idx].fd > 0) {
            if (FD_ISSET(wrappedFds[idx].fd, readfds)) {
                if (ssh_read_poll(wrappedFds[idx].sshSession, wrappedFds[idx].blocking)) {
                    FD_ZERO(readfds);
                    if (writefds) FD_ZERO(writefds);
                    if (exceptfds) FD_ZERO(exceptfds);
                    FD_SET(wrappedFds[idx].fd, readfds);
                    return 1;
                } else {
                    FD_CLR(wrappedFds[idx].fd, readfds);
                    FD_SET(wrappedFds[idx].sshSession->fd, readfds);
                }
            }
        }
    }
    
    for (idx = 0; writefds && idx < MAXFD; idx++) {
        if (wrappedFds[idx].fd > 0) {
            if (FD_ISSET(wrappedFds[idx].fd, writefds)) {
                fprintf(stderr, "a wrapped fd %d is selected for write, fd %d\n", wrappedFds[idx].fd, wrappedFds[idx].sshSession->fd);
                
                FD_CLR(wrappedFds[idx].fd, writefds);
                FD_SET(wrappedFds[idx].sshSession->fd, writefds);
            } else {
                fprintf(stderr, "a non wrapped fd %d is selected for write, fd %d\n", wrappedFds[idx].wrappedFd, wrappedFds[idx].fd);

            }
            
        }
    }
    
    for (idx = 0; exceptfds && idx < MAXFD; idx++) {
        if (wrappedFds[idx].fd > 0) {
            if (FD_ISSET(wrappedFds[idx].fd, exceptfds)) {
                fprintf(stderr, "a wrapped fd %d is selected for except, fd %d\n", wrappedFds[idx].fd, wrappedFds[idx].sshSession->fd);
                
                FD_CLR(wrappedFds[idx].fd, exceptfds);
                FD_SET(wrappedFds[idx].sshSession->fd, exceptfds);
            } else {
                fprintf(stderr, "a non wrapped fd %d is selected for except, fd %d\n", wrappedFds[idx].wrappedFd, wrappedFds[idx].fd);

            }
            
        }
    }
    
    ret = real_select(nfds, readfds, writefds, exceptfds, timeout);
    
    
    for (idx = 0; readfds && idx < MAXFD; idx++) {
        if (wrappedFds[idx].fd  > 0) {
            if (FD_ISSET(wrappedFds[idx].sshSession->fd, readfds)) {
                fprintf(stderr, "a wrapped fd %d was selected for read %d\n", wrappedFds[idx].fd, wrappedFds[idx].sshSession->fd);
                FD_CLR(wrappedFds[idx].sshSession->fd, readfds);
                FD_SET(wrappedFds[idx].fd, readfds);
            }
        }
    }
    
    for (idx = 0; writefds && idx < MAXFD; idx++) {
        if (wrappedFds[idx].fd  > 0) {
            if (FD_ISSET(wrappedFds[idx].sshSession->fd, writefds)) {
                fprintf(stderr, "a wrapped fd %d was selected for write %d\n", wrappedFds[idx].fd, wrappedFds[idx].sshSession->fd);
                FD_CLR(wrappedFds[idx].sshSession->fd, writefds);
                FD_SET(wrappedFds[idx].fd, writefds);
            }
        }
    }
    
    for (idx = 0; exceptfds && idx < MAXFD; idx++) {
        if (wrappedFds[idx].fd  > 0) {
            if (FD_ISSET(wrappedFds[idx].sshSession->fd, exceptfds)) {
                fprintf(stderr, "a wrapped fd %d was selected for except %d\n", wrappedFds[idx].fd, wrappedFds[idx].sshSession->fd);
                FD_CLR(wrappedFds[idx].sshSession->fd, exceptfds);
                FD_SET(wrappedFds[idx].fd, exceptfds);
            }
        }
    }
    
    
    return ret;
}
