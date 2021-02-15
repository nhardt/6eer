#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_PORT 2679

#define MESSAGE (const unsigned char *)"Message"
#define MESSAGE_LEN 7
#define CIPHERTEXT_LEN (crypto_box_SEALBYTES + MESSAGE_LEN)

#define PK "5c90463a8ba0880ca2d6a70e60be464853c8c7dfc4a5be8b60a246f1fc3c4f4f"

unsigned char ciphertext[CIPHERTEXT_LEN];
unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];

// char *sodium_bin2hex(
//           char * const hex,
//           const size_t hex_maxlen,
//           const unsigned char * const bin,
//           const size_t bin_len);
void create_keys()
{
    char pkhexout[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char skhexout[crypto_box_SECRETKEYBYTES * 2 + 1];

    crypto_box_keypair(recipient_pk, recipient_sk);

    sodium_bin2hex((char *)&pkhexout, crypto_box_PUBLICKEYBYTES * 2 + 1,
                   recipient_pk, crypto_box_PUBLICKEYBYTES);
    sodium_bin2hex((char *)&skhexout, crypto_box_SECRETKEYBYTES * 2 + 1,
                   recipient_sk, crypto_box_SECRETKEYBYTES);

    printf("pk: %s\n", pkhexout);
    printf("sk: %s\n", skhexout);
}

// int sodium_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
//                   const char * const hex, const size_t hex_len,
//                   const char * const ignore, size_t * const bin_len,
//                   const char ** const hex_end);
void load_keys()
{
    char pkhexout[crypto_box_PUBLICKEYBYTES * 2 + 1];
    const char *const ignore = NULL;
    size_t const bin_len = strlen(PK);

    printf("loading pk: %s\n", PK);
    if (sodium_hex2bin((unsigned char *)&recipient_pk,
                       crypto_box_PUBLICKEYBYTES, PK, strlen(PK), NULL, NULL,
                       NULL) != 0)
    {
        printf("failed to load PK via hex2bin\n");
        exit(1);
    }
}

void create_cipher()
{
    crypto_box_seal(ciphertext, MESSAGE, MESSAGE_LEN, recipient_pk);
}

int main(int argc, char *argv[])
{
    int sock_fd = -1;
    struct sockaddr_in6 server_addr;
    int ret;
    char ch = 'a';
    char connect_addr[255] = "::1";
    if (argc > 1)
    {
        strncpy(connect_addr, argv[1], 255);
    }
    printf("will attempt to connect to server at %s\n", connect_addr);

    if (strlen(PK) == 0)
    {
        create_keys();
    }
    else
    {
        load_keys();
    }
    create_cipher();

    /* Arguments could be used in getaddrinfo() to get e.g. IP of server */
    (void)argc;
    (void)argv;

    /* Create socket for communication with server */
    sock_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1)
    {
        perror("socket()");
        return EXIT_FAILURE;
    }

    /* Connect to server running on localhost */
    server_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, connect_addr, &server_addr.sin6_addr);
    server_addr.sin6_port = htons(SERVER_PORT);

    /* Try to do TCP handshake with server */
    ret =
        connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret == -1)
    {
        perror("connect()");
        close(sock_fd);
        return EXIT_FAILURE;
    }

    /* Send data to server */
    ret = write(sock_fd, &ciphertext, CIPHERTEXT_LEN);
    if (ret == -1)
    {
        perror("write");
        close(sock_fd);
        return EXIT_FAILURE;
    }

    /* Wait for data from server */
    ret = read(sock_fd, &ch, 1);
    if (ret == -1)
    {
        perror("read()");
        close(sock_fd);
        return EXIT_FAILURE;
    }

    printf("Received %c from server\n", ch);

    /* DO TCP teardown */
    ret = close(sock_fd);
    if (ret == -1)
    {
        perror("close()");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
