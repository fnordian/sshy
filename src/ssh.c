#include "ssh.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>

#include "connect.h"
#include "log.h"

static int ssh_initialized = 0;

static int connectToServer(const char *hostname, int port);

void handleTunnelClient(int clientSocket,const char *targetHost,
                        const int targetPort, struct sockaddr *clientAddress, int clientAddressLen);

struct sshSession *createSshSession();

const char *getKnownHostsFile() {
    static char knownHostsFile[1024];
    struct passwd *pw;
    const char *homedir;
    
    
    pw = getpwuid(getuid());
    homedir = pw->pw_dir;
    
    snprintf(knownHostsFile, sizeof(knownHostsFile), "%s/.ssh/known_hosts", homedir);
    
    return knownHostsFile;
}

int ssh_checkKnownHosts(struct sshSession *sshSession) {
    LIBSSH2_KNOWNHOSTS *nh;
    const char *fingerprint;
    size_t len;
    int type;
    struct libssh2_knownhost *host;
    int check;
    
    nh = libssh2_knownhost_init(sshSession->session);
    
    if (!nh) {
        return -1;
    }
    
     /* read all hosts from here */ 
    libssh2_knownhost_readfile(nh, getKnownHostsFile(), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    
    fingerprint = libssh2_session_hostkey(sshSession->session, &len, &type);
    
    if (!fingerprint) {
        return -1;
    }
    
    check = libssh2_knownhost_check(nh, sshSession->sshHostname,
                                            fingerprint, len,
                                            LIBSSH2_KNOWNHOST_TYPE_PLAIN|
                                            LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                            &host);
    
    return check == LIBSSH2_KNOWNHOST_CHECK_MATCH ? 0 : -1;
}

int ssh_agentAuthenticate(LIBSSH2_SESSION *session, const char *username) {
    LIBSSH2_AGENT *agent;
    struct libssh2_agent_publickey *key, *prev = NULL;
    int ret = -1;
    
    agent = libssh2_agent_init(session);
    if (!agent || libssh2_agent_connect(agent)) {
        return ret;
    }
        
    if (libssh2_agent_list_identities(agent)) {
        return ret;
    }
    
    while (agent != NULL && 0 == libssh2_agent_get_identity(agent, &key, prev)) {
        if (!libssh2_agent_userauth(agent, username, key)) {
            ret = 0;
            break;
        }
        prev = key;
    }
    
    return ret;
}

int ssh_authenticate(struct sshSession *sshSession) {
    char *userauthlist;
    char *publicKey;
    int ret = -1;
    LIBSSH2_SESSION *session;
    
    session = sshSession->session;
    
    userauthlist = libssh2_userauth_list(session, sshSession->username, strlen(sshSession->username));
    
    sshy_log( "authenticating %s\n", sshSession->username);
    
    if (!ssh_agentAuthenticate(session, sshSession->username)) {
        ret = 0;
    }
    
    if (ret && sshSession->privateKeyFilename[0]) {
        int rc;
        int len = strlen(sshSession->privateKeyFilename);
        publicKey = alloca(len+5);
        memcpy(publicKey, sshSession->privateKeyFilename, len);
        strcpy(publicKey+len, ".pub");
        
        if ((rc = libssh2_userauth_publickey_fromfile(session, sshSession->username, 
            publicKey, sshSession->privateKeyFilename, NULL))) {
            char *errbuf;
            sshy_log("key authentication failed\n");
            libssh2_session_last_error(session, &errbuf, NULL, 0); 
        } else {
            ret = 0;
        }
    }
    
    if (ret && libssh2_userauth_password(session, sshSession->username, sshSession->password)) {
        sshy_log( "password authentication failed\n");
    } else {
        ret = 0;
    }
   
    return ret;
}

int ssh_connect(struct sshSession *sshSession, int sockfd, const char *host, int port) {
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel = NULL;
    int rc;
    
    
    if (!ssh_initialized) {
        ssh_initialized = 1;
        libssh2_init(0);
    }
    
    session = libssh2_session_init();
    sshSession->session = session;
    rc = libssh2_session_startup(session, sockfd);
    
    if (ssh_checkKnownHosts(sshSession)) {
        sshy_log("cannot assure host identity\n");
        return -1;
    }
    
    if (ssh_authenticate(sshSession)) {
        sshy_log("cannot authenticate to ssh server\n");
        return -1;
    }
    
    channel = libssh2_channel_direct_tcpip(session, host, port);
    
    
    sshSession->channel = channel;
    sshSession->blocking = 1;
    sshSession->peekDataRead = 0;
    sshSession->peekData = '\0';
   
    
    if (channel != NULL) {
        return 0;
    } else {
        sshy_log( "couldn't get the channel!!!!\n");
        return -1;
    }
}

void ssh_free(struct sshSession *sshSession) {
    libssh2_channel_free(sshSession->channel);
    libssh2_session_disconnect(sshSession->session, "Client disconnecting normally");
    libssh2_session_free(sshSession->session);
}

ssize_t ssh_write(struct sshSession *sshSession, const char *buf, size_t buflen) {
    ssize_t ret;
    
    //libssh2_channel_set_blocking(sshSession->channel, 1);
   
    ret = libssh2_channel_write(sshSession->channel, buf, buflen);
    
    //libssh2_channel_set_blocking(sshSession->channel, 1);
    
    if (ret == LIBSSH2_ERROR_EAGAIN) {
        ret = -EAGAIN;
    }
    
    return ret;
}

ssize_t ssh_read(struct sshSession *sshSession, char *buf, size_t buflen) {
    ssize_t ret;
    
    if (sshSession->peekDataRead) {
        if (buflen > 0) {
            sshSession->peekDataRead = 0;
            buf[0] = sshSession->peekData;
            return 1;
        } else {
            return 0;
        }
    }
        
    
    //libssh2_channel_set_blocking(sshSession->channel, 1);
   
    ret = libssh2_channel_read(sshSession->channel, buf, buflen);
    
    if (ret == LIBSSH2_ERROR_EAGAIN) {
        ret = -1;
        errno = EAGAIN;
    }
        
/*    if (ret > 0) {
        //sshy_log( "ssh_read got: %s\n", buf);
    } else {
        sshy_log( "ssh_read error: %d\n", ret);
        
        if (libssh2_channel_eof(sshSession->channel)) {
            sshy_log( "ssh_read eof\n");
        } else {
            sshy_log( "ssh_read no eof\n");
        }   
    }
  */  
    //libssh2_channel_set_blocking(sshSession->channel, 1);
    
    return ret;
}

int ssh_read_peek(struct sshSession *sshSession, char *buf, size_t buflen) {
  
    int ret;
    
    if (!sshSession->peekDataRead) {
        ret = libssh2_channel_read(sshSession->channel, &sshSession->peekData, 1);
        if (ret > 0) {
            sshSession->peekDataRead = 1;
        }
    }
    
    if (sshSession->peekDataRead) {
        if (buflen > 0) {
            buf[0] = sshSession->peekData;
            return 1;
        }
    } 
    return 0;
    
}

int ssh_read_poll(struct sshSession *sshSession, int blocking) {
    int ret;
    
    if (sshSession->peekDataRead) {
        return 1;
    }
    
    libssh2_channel_set_blocking(sshSession->channel, 0);
    
    ret = libssh2_channel_read(sshSession->channel, &sshSession->peekData, 1);
    
    libssh2_channel_set_blocking(sshSession->channel, blocking);
    
    if (ret == 1) {
        sshSession->peekDataRead = 1;
    }
        
    
    return ret == 1 || ret == 0;
}

void ssh_set_block(struct sshSession *sshSession, int blocking) {
    if (sshSession->channel) {
        libssh2_channel_set_blocking(sshSession->channel, blocking);
    }
}

int createListenSocket(int *port) {
    struct sockaddr_in serv_addr;
    int sockfd;
    socklen_t addrlen;
    
    sockfd = real_socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        sshy_log( "cannot bind to ssh forward port, socket: %u\n", sockfd);
        return -1;
    }
    
    listen(sockfd,5);

    addrlen = sizeof(serv_addr);
    
    getsockname(sockfd, (struct sockaddr *) &serv_addr, &addrlen);
    *port = serv_addr.sin_port;
    
    return sockfd;
}

int tunnelPort(const char *targetHost, const int targetPort) {
    int listenSocket;
    int listenPort;
    struct sockaddr_in sin;
    socklen_t sinlen = sizeof(sin);
    pid_t p;
    
    
    listenSocket = createListenSocket(&listenPort);
        
    sshy_log("creating tunnel to %s:%d @ port %d\n", targetHost, targetPort, listenPort);

    
    if ((p = fork()) == 0) { // no zombies please
        int clientSocket;
        
        if((clientSocket = accept(listenSocket, (struct sockaddr *)&sin, &sinlen)) > 0) {
            real_close(listenSocket);
            
            handleTunnelClient(clientSocket, targetHost, targetPort, (struct sockaddr *) &sin, sinlen);
            real_close(clientSocket);
        }
    
        _exit(0);
    }
    
    real_close(listenSocket);
    return listenPort;
}

static const char *inet46_ntoa(struct sockaddr *sin, char *buf, int bufsize) {
   return inet_ntop(sin->sa_family, sin, buf, bufsize);
}

static unsigned short inet46_ntohs(struct sockaddr *sin) {
    if (sin->sa_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)sin)->sin_port);
    } else {
        return 0;
    }
}

#define STOP { stopped = 1; break; }

void handleTunnelClient(int clientSocket,const char *targetHost,
                        const int targetPort, struct sockaddr *clientAddress, int clientAddressLen) {
    struct sshSession * sshSession = createSshSession();
    fd_set fds;
    struct timeval tv;
    int stopped = 0;
    char buf[16384];
    int rc;
    ssize_t len, wr;
    char shost[200];
    unsigned short sport;
    int i;
    
    if (ssh_connect(sshSession, sshSession->fd, targetHost, targetPort)) {
        sshy_log( "ssh_connect error\n");
        return;
    }
    
    libssh2_session_set_blocking(sshSession->session, 0);

    inet46_ntoa(clientAddress, shost, sizeof(shost));
    sport = inet46_ntohs(clientAddress);
    
    while (! stopped) {
        FD_ZERO(&fds);
        FD_SET(clientSocket, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        rc = select(clientSocket + 1, &fds, NULL, NULL, &tv);
        
        if (-1 == rc) {
                
                break;
        }
        
        if (rc && FD_ISSET(clientSocket, &fds)) {
            int len = recv(clientSocket, buf, sizeof(buf), 0);
            if (len < 0) {
                break;
            } else if (0 == len) {
                sshy_log( "The client at %s:%d disconnected!\n", shost,
                    sport);
                break;
            }
            wr = 0;
            
            ssh_write(sshSession, buf, len);
              
        }
        while (1) {
            len = ssh_read(sshSession, buf, sizeof(buf));

            if (-1 == len && errno == EAGAIN) {
                break;
            } else if (len < 0) {
                STOP;
            } else if (len == 0) {
                STOP;
            }
            wr = 0;
            while (wr < len) {
                i = send(clientSocket, buf + wr, len - wr, 0);
                if (i <= 0) {
                    STOP;
                }
                wr += i;
            }
        }
    
    }
    
    real_close(clientSocket);
    
}



static int connectToServer(const char *hostname, int port) {
    int sockfd;
    struct addrinfo *addrinfo;
    char portstring[10];
    
    snprintf(portstring, sizeof(portstring), "%d", port);
    
    if (getaddrinfo(hostname, portstring, NULL, &addrinfo)) {
        sshy_log("ERROR, no such host as %s\n", hostname);
        return -1;
    }

    sockfd = real_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        freeaddrinfo(addrinfo);
        return -1;
    }
    
    /* connect: create a connection with the server */
    if (real_connect(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0) {
        close(sockfd);
        sockfd = -1;
    }
    
    freeaddrinfo(addrinfo);
    
    return sockfd;
}

struct sshSession *createSshSession() {
    struct sshSession *sshSession = calloc(1, sizeof(struct sshSession));
    
    
    strncpy(sshSession->username, getenv("SSHY_USER"), sizeof(sshSession->username));
    strncpy(sshSession->password, getenv("SSHY_PASS"), sizeof(sshSession->password));
    strncpy(sshSession->privateKeyFilename, getenv("SSHY_KEYFILE"), sizeof(sshSession->privateKeyFilename));
    strncpy(sshSession->sshHostname, getenv("SSHY_HOST"), sizeof(sshSession->sshHostname));
    
    sshSession->fd = connectToServer(sshSession->sshHostname, 22);
    
    if (sshSession->fd < 0) {
        return NULL;
    } else {    
        return sshSession;
    }
}
