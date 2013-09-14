#include "ssh.h"
#include <stdio.h>
#include <errno.h>

static int ssh_initialized = 0;

int ssh_connect(struct sshSession *sshSession, int sockfd, const char *host, int port) {
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel = NULL;
    int rc;
    char *userauthlist;
    
    if (!ssh_initialized) {
        ssh_initialized = 1;
        libssh2_init(0);
    }
    
    session = libssh2_session_init();
    rc = libssh2_session_startup(session, sockfd);
    
    userauthlist = libssh2_userauth_list(session, sshSession->username, strlen(sshSession->username));
    
    // TODO: obey userauthlist
    
    fprintf(stderr, "authenticating %s/%s\n", sshSession->username, sshSession->password);
    
    if (libssh2_userauth_password(session, sshSession->username, sshSession->password)) {
        fprintf(stderr, "authentication error\n");
        return -1;
    }
    
    fprintf(stderr, "opening tcpchannel to %s:%d\n", host, port);
    
    channel = libssh2_channel_direct_tcpip(session, host, port);
    
    sshSession->session = session;
    sshSession->channel = channel;
    sshSession->blocking = 1;
    sshSession->peekDataRead = 0;
    sshSession->peekData = '\0';
   
    
    if (channel != NULL) {
        fprintf(stderr, "i've got the channel!!!!\n");
        return 0;
    } else {
        fprintf(stderr, "couldn't get the channel!!!!\n");
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
        
    if (ret > 0) {
        fprintf(stderr, "ssh_read got: %s\n", buf);
    } else {
        fprintf(stderr, "ssh_read error: %d\n", ret);
        
        if (libssh2_channel_eof(sshSession->channel)) {
            fprintf(stderr, "ssh_read eof\n");
        } else {
            fprintf(stderr, "ssh_read no eof\n");
        }   
    }
    
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
    
    fprintf(stderr, "read poll ret: %d ____________-------------_______________-\n", ret);
    
    if (ret == 1) {
        sshSession->peekDataRead = 1;
    }
        
    
    return ret == 1 || ret == 0;
}

void ssh_set_block(struct sshSession *sshSession, int blocking) {
    if (sshSession->channel) {
        fprintf(stderr, "setting channel to %s\n", blocking ? "blocking" : "non blocking");
        libssh2_channel_set_blocking(sshSession->channel, blocking);
    }
}
