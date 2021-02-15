#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define CLIENT_QUEUE_LEN 10
#define SERVER_PORT 2679
#define CIPHERTEXT_LEN (crypto_box_SEALBYTES + MESSAGE_LEN)
#define MESSAGE_LEN 7

#define PK "5c90463a8ba0880ca2d6a70e60be464853c8c7dfc4a5be8b60a246f1fc3c4f4f"
#define SK "2c7aa6fc26380ecaefdcd6fdab03464aa468d1c77cb8a272facb2522051da268"

unsigned char decrypted[MESSAGE_LEN];
unsigned char ciphertext[CIPHERTEXT_LEN];
unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];

// int sodium_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
//                   const char * const hex, const size_t hex_len,
//                   const char * const ignore, size_t * const bin_len,
//                   const char ** const hex_end);
void load_and_verify_key()
{
    char skhexout[crypto_box_PUBLICKEYBYTES * 2 + 1];

    if (sodium_hex2bin((unsigned char *)&recipient_sk,
                       crypto_box_SECRETKEYBYTES, SK, strlen(SK), NULL, NULL,
                       NULL) != 0)
    {
        printf("hex2bin failed\n");
        exit(1);
    }
    sodium_bin2hex((char *)&skhexout, crypto_box_SECRETKEYBYTES * 2 + 1,
                   (const unsigned char *)&recipient_sk,
                   crypto_box_SECRETKEYBYTES);
    if (strcmp(SK, skhexout) != 0)
    {
        printf("input text not equal to output text\n");
        exit(1);
    }
    printf("key loaded successfully\n");

    // also need the public key
    printf("loading pk: %s\n", PK);
    if (sodium_hex2bin((unsigned char *)&recipient_pk,
                       crypto_box_PUBLICKEYBYTES, PK, strlen(PK), NULL, NULL,
                       NULL) != 0)
    {
        printf("failed to load PK via hex2bin\n");
        exit(1);
    }
}

int decrypt()
{
    if (crypto_box_seal_open(decrypted, ciphertext, CIPHERTEXT_LEN,
                             recipient_pk, recipient_sk) != 0)
    {
        printf("failed to decrypt");
        return -1;
    }
    else
    {
        printf("Decrypted Message: %s\n", decrypted);
        return 0;
    }
}

int main(void)
{
    int listen_sock_fd = -1, client_sock_fd = -1;
    struct sockaddr_in6 server_addr, client_addr;
    socklen_t client_addr_len;
    char str_addr[INET6_ADDRSTRLEN];
    int ret, flag;
    char ch;

    load_and_verify_key();

    /* Create socket for listening (client requests) */
    listen_sock_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock_fd == -1)
    {
        perror("socket()");
        return EXIT_FAILURE;
    }

    /* Set socket to reuse address */
    flag = 1;
    ret = setsockopt(listen_sock_fd, SOL_SOCKET, SO_REUSEADDR, &flag,
                     sizeof(flag));
    if (ret == -1)
    {
        perror("setsockopt()");
        return EXIT_FAILURE;
    }

    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(SERVER_PORT);

    /* Bind address and socket together */
    ret = bind(listen_sock_fd, (struct sockaddr *)&server_addr,
               sizeof(server_addr));
    if (ret == -1)
    {
        perror("bind()");
        close(listen_sock_fd);
        return EXIT_FAILURE;
    }

    /* Create listening queue (client requests) */
    ret = listen(listen_sock_fd, CLIENT_QUEUE_LEN);
    if (ret == -1)
    {
        perror("listen()");
        close(listen_sock_fd);
        return EXIT_FAILURE;
    }

    client_addr_len = sizeof(client_addr);

    while (1)
    {
        /* Do TCP handshake with client */
        client_sock_fd = accept(listen_sock_fd, (struct sockaddr *)&client_addr,
                                &client_addr_len);
        if (client_sock_fd == -1)
        {
            perror("accept()");
            close(listen_sock_fd);
            return EXIT_FAILURE;
        }

        inet_ntop(AF_INET6, &(client_addr.sin6_addr), str_addr,
                  sizeof(str_addr));
        printf("New connection from: %s:%d ...\n", str_addr,
               ntohs(client_addr.sin6_port));

        /* Wait for data from client */
        ret = read(client_sock_fd, &ciphertext, CIPHERTEXT_LEN);
        if (ret == -1)
        {
            perror("read()");
            close(client_sock_fd);
            continue;
        }

        /* Do very useful thing with received data :-) */
        if (decrypt() == 0)
        {
            ret = write(client_sock_fd, "y", 1);
        }
        else
        {
            ret = write(client_sock_fd, "n", 1);
        }

        /* Send response to client */
        if (ret == -1)
        {
            perror("write()");
            close(client_sock_fd);
            continue;
        }

        /* Do TCP teardown */
        ret = close(client_sock_fd);
        if (ret == -1)
        {
            perror("close()");
            client_sock_fd = -1;
        }

        printf("Connection closed\n");
    }
    return EXIT_SUCCESS;
}
