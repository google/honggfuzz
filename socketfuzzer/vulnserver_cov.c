#include <crypt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Do nothing with first message */
void handleData0(char *data, int len) {
    printf("# vulnserver_cov: Auth success\n");
}

/* Second message is stack based buffer overflow */
void handleData1(char *data, int len) {
    char buff[8];
    bzero(buff, 8);
    memcpy(buff, data, len);
    printf("# vulnserver_cov: Handledata1: %s\n", buff);
}

/* Third message is heap overflow */
void handleData2(char *data, int len) {
    char *buff = malloc(8);
    if (!buff) {
        abort();
    }
    bzero(buff, 8);
    memcpy(buff, data, len);
    printf("# vulnserver_cov: Handledata2: %s\n", buff);
    free(buff);
}

void handleData3(char *data, int len) {
    printf("# vulnserver_cov: Handledata3: %i\n", len);
}

void handleData4(char *data, int len) {
    printf("# vulnserver_cov: Handledata4: %i\n", len);
}

void handleData5(char *data, int len) {
    printf("# vulnserver_cov: Handledata5: %i\n", len);
}

void doprocessing(int sock, int serversock) {
    char data[1024];
    int  n   = 0;
    int  len = 0;

    while (1) {
        bzero(data, sizeof(data));
        len = read(sock, data, 1024);

        if (len == 0 || len <= 1) {
            return;
        }

        printf("# vulnserver_cov: Received data with len: %i on state: %i\n", len, n);
        switch (data[0]) {
        case 'A':
            handleData0(data, len);
            write(sock, "ok", 2);
            break;
        case 'B':
            handleData1(data, len);
            write(sock, "ok", 2);
            break;
        case 'C':
            handleData2(data, len);
            write(sock, "ok", 2);
            break;
        case 'D':
            handleData3(data, len);
            write(sock, "ok", 2);
            break;
        case 'E':
            handleData4(data, len);
            write(sock, "ok", 2);
            break;
        case 'F':
            handleData5(data, len);
            write(sock, "ok", 2);
            // close the main server socket whoooops
            close(serversock);
            break;
        default:
            return;
        }

        n++;
    }
}

int main(int argc, char *argv[]) {
    int                sockfd, newsockfd, portno, clilen;
    char               buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int                n, pid;

    if (argc == 2) {
        portno = atoi(argv[1]);
    } else {
        portno = 5001;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("# vulnserver_cov: ERROR opening socket");
        exit(1);
    }

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse, sizeof(reuse)) < 0)
        perror("# vulnserver_cov: setsockopt(SO_REUSEPORT) failed");

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port        = htons(portno);

    printf("# vulnserver_cov: Listening on port: %i\n", portno);

    /* Now bind the host address using bind() call.*/
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("# vulnserver_cov: ERROR on binding");
        exit(1);
    }

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("# vulnserver_cov: ERROR on accept");
            exit(1);
        }
        printf("# vulnserver_cov: New client connected\n");
        doprocessing(newsockfd, sockfd);
        printf("# vulnserver_cov: Closing...\n");
        shutdown(newsockfd, 2);
        close(newsockfd);
    }
}
