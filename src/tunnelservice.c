#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <link.h>

#include <unistd.h>
#include <sys/types.h> 
#include <netinet/ip.h>
#include <alloca.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <signal.h>


#include "ssh.h"
#include "log.h"
#include "mutex.h"

       #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>
       
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

       
static int clientReader, clientWriter;
static int serverReader, serverWriter;

static void tunnelService();

static void startTunnelService(void) __attribute__((constructor));

static int requestMutex;
static int serverMutex;

static int c = 0;


static pid_t servicePid;


static void startTunnelService() {

    int pipefd[2];
    volatile int _initialized;
    
    static volatile int initialized[1] = { 0 };
    
    _initialized = __sync_fetch_and_add(initialized, 1);
    
    if (_initialized > 0) {
        return;
    }
    
    requestMutex = createMutex();
    serverMutex = createMutex();
    
    sshy_log("starting tunnel service %d %d.\n", initialized, c);
    
    pipe(pipefd);
    clientReader = pipefd[0];
    serverWriter = pipefd[1];
    pipe(pipefd);
    serverReader = pipefd[0];
    clientWriter = pipefd[1];
    
    
    
    sshy_log("starting, about to fork %d %d %d %d\n", clientReader, clientWriter, serverReader, serverWriter);
    servicePid = fork();
    sshy_log("starting, fork: %d\n", servicePid);
    if (servicePid == 0) {
        signal(SIGCHLD, SIG_IGN);
        close(clientReader);
        close(clientWriter);
        tunnelService();
        _exit(0);
    } else if (servicePid < 0) {
        sshy_log("omg, could not fork\n");
        _exit(1);
    }
    
    close(serverReader);
    close(serverWriter);
    
    dup(0); dup(1); dup(2);
    
    return;
}

static void readForSure(int fd, void *buf, size_t count) {
    int rc;
    
    sshy_log("%d reading %d bytes\n", fd, count);
    
    do {
        rc = read(fd, buf, count);
        
        if (rc < 1) {
            sshy_log("tunnelservice cannot read from socket any more\n");
            _exit(0);
        }
        
        count -= rc;
        buf += rc;
    } while (count);
    
}

static void writeForSure(int fd, const void *buf, size_t count) {
    int rc;
    
    sshy_log("%d writing %d bytes\n", fd, count);
    
    do {
        rc = write(fd, buf, count);
        
        if (rc < 1) {
            sshy_log("tunnelservice cannot write from socket any more\n");
            _exit(0);
        }
        
        buf += rc;
        count -= rc;
    } while (count);
}



static const char *hostnameFromAddress(char *buf, int buflen, const void *addr, socklen_t addrlen, int type) {
    return inet_ntop(type, addr, buf, buflen);
}

static u_int16_t portFromAddress(void *addr, socklen_t addrlen, int type) {
    struct sockaddr_in *inetAddress = (struct sockaddr_in *) addr;
    return ntohs(inetAddress->sin_port);
}

static void readTunnelRequest(struct sockaddr *addr, socklen_t *addrlen) {
    readForSure(serverReader, addrlen, sizeof(socklen_t));
    fprintf(stderr, "read addrlen %u\n", *addrlen);
    readForSure(serverReader, addr, *addrlen);
}

static void handleTunnelRequest(struct sockaddr *addr, socklen_t addrlen) {
    void *addrptr;
    char hostnamebuf[1024];
    const char *hostname;
    u_int16_t port, localTunnelEntryPort;
    

    addrptr = addr->sa_family == AF_INET ? (void *)  &((struct sockaddr_in *) addr)->sin_addr.s_addr : (void *) &((struct sockaddr_in6 *) addr)->sin6_addr;
        
    hostname = hostnameFromAddress(hostnamebuf, sizeof(hostnamebuf), addrptr, addrlen, addr->sa_family);
    port = portFromAddress((void*) addr, addrlen, addr->sa_family);
        
    sshy_log("handler getting port\n");
    
    localTunnelEntryPort = tunnelPort(hostname, port);
          
    writeForSure(serverWriter, &localTunnelEntryPort, sizeof(localTunnelEntryPort));
}

#define MAX(a, b) (a < b ? a : b)

static void tunnelService() {
    
    struct sockaddr *addr = alloca(2048); // XXX: is this enough?
    socklen_t addrlen;
    
    sshy_log("service started\n");
    
    while(1) {
        get_mutex(serverMutex);
        readTunnelRequest(addr, &addrlen);
        handleTunnelRequest(addr, addrlen);
        release_mutex(serverMutex);
    }
}

int requestTunnel(const struct sockaddr *addr, socklen_t addrlen) {
    u_int16_t port;
    
    get_mutex(requestMutex);
    
    writeForSure(clientWriter, &addrlen, sizeof(addrlen));
    writeForSure(clientWriter, addr, addrlen);
    readForSure(clientReader, &port, sizeof(port));
    
    sshy_log("requested tunnel @ port %d %c\n", port, port);
    
    release_mutex(requestMutex);
    
    return port;
}
