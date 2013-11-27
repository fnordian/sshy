/* 
 * tcpclient.c - A simple TCP client
 * usage: tcpclient <host> <port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/wait.h>
#include "ssh.h"
#include "mutex.h"

#define BUFSIZE 1024

int do_main(int argc, char **argv);

/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    fprintf(stderr, "woop\n");
    perror(msg);
    exit(0);
}


void readFile() {
    int fd;
    const char *filename = "/etc/passwd";
    char buf[100];
    
    if ((fd = open(filename, O_RDONLY)) < 0) {
      perror(filename);
      exit(1);
    }
    
    if (read(fd, buf, sizeof(buf) - 1) <= 0) {
      perror(filename);
      exit(1);
    }
    
    buf[sizeof(buf)-1] = '\0';
    
    printf( "%s\n", buf);
  
}

int _argc;
char **_argv;

void *thread_start(void *p) {
    do_main(_argc, _argv);
    
    return NULL;
}

int main(int argc, char **argv) {
    int mutex;
    pthread_t t1, t2;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    int p;
    
    if ((p = fork())) {
        waitpid(p, NULL, 0);
        exit(0);
    }
    
    mutex = createMutex();
    
    printf("bla\n"),
    
    get_mutex(mutex);
    //get_mutex(mutex);
    
    printf("bam\n");
    
    
    _argc = argc;
    _argv = argv;
    
    pthread_create(&t1, NULL, thread_start, NULL);
    pthread_create(&t2, NULL, thread_start, NULL);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    //do_main(argc, argv);
    //do_main(argc, argv);
//    another_main(argc, argv);
    
    return 0;
}

int another_main(int argc, char **argv) {
    tunnelPort("yahoo.de", 80);
    
    return 0;
}

int do_main(int argc, char **argv) {
    int sockfd, portno, n;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];
    
    readFile();

    /* check command line arguments */
    if (argc != 3) {
       fprintf(stderr, "usage: %s <hostname> <port>\n", argv[0]);
       exit(0);
    }
    hostname = argv[1];
    portno = atoi(argv[2]);

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host as %s\n", hostname);
        exit(0);
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    /* connect: create a connection with the server */
    if (connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
      error("ERROR connecting");

    
    
    snprintf(buf, BUFSIZE, "GET /\r\n\r\n");
    
    
    // send the message line to the server
    n = write(sockfd, buf, strlen(buf));
    if (n < 0) 
      error("ERROR writing to socket");

    // print the server's reply 
    bzero(buf, BUFSIZE);
    n = read(sockfd, buf, BUFSIZE);
    if (n < 0) 
      error("ERROR reading from socket");
    printf( "Echo from server: %s", buf);
    close(sockfd);
    
    
    return 0;
}