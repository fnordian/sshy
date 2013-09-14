#ifndef H_SSH
#define H_SSH

#include <libssh2.h>

struct sshSession {
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    char username[64];
    char password[64];
    struct sockaddr *addr;
    ssize_t addrlen;
    int fd;
    int blocking;
    char peekData;
    int peekDataRead;
};

int ssh_connect(struct sshSession *sshSession, int sockfd, char *host, int port);
ssize_t ssh_write(struct sshSession *session, const char *buf, size_t buflen);
ssize_t ssh_read(struct sshSession *session, char *buf, size_t buflen);
int ssh_read_peek(struct sshSession *sshSession, char *buf, size_t buflen);
int ssh_read_poll(struct sshSession *session, int blocking);
void ssh_set_block(struct sshSession *session, int blocking);
void ssh_free(struct sshSession *sshSession);

#endif
