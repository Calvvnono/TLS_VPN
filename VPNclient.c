#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

/* Configuration Constants
 * HOME: Directory containing server certificates
 * CA_DIR: Directory containing CA certificates
 * BUFF_SIZE: Buffer size for data transmission
 * CERT_FILE_PATH: Path to client certificate
 * KEY_FILE_PATH: Path to client private key
 * CA_CERT_FILE_PATH: Path to CA certificate
 */
#define HOME "./cert_server/"
#define CA_DIR "./ca_client"
#define BUFF_SIZE 5000
#define CERT_FILE_PATH HOME "client-dsy-crt.pem"
#define KEY_FILE_PATH HOME "client-dsy-key.pem"
#define CA_CERT_FILE_PATH HOME "ca-dsy-crt.pem"

// Macro to check for NULL pointers
#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(1)

// Macro to check for errors
#define CHK_ERR(err, s) \
    if ((err) == -1) {  \
        perror(s);      \
        exit(1);        \
    }

// Macro to check SSL errors
#define CHK_SSL(err)                 \
    if ((err) < 1) {                 \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }

/**
 * Controls terminal echo mode for password input
 * @param fd: File descriptor for terminal
 * @param option: 1 to enable echo, 0 to disable
 * Returns: 0 on success, 1 on failure
 * Notes:
 * - Modifies terminal attributes to hide/show input
 * - Used for secure password entry
 */
int set_disp_mode(int fd, int option);

// Function to create a TUN device
/**
 * Creates and configures a TUN device for VPN tunnel
 * Returns: File descriptor for the TUN device, -1 on failure
 * Notes: 
 * - Opens /dev/net/tun with read/write permissions
 * - Configures device flags for TUN mode without packet info
 * - Enables IP forwarding and clears iptables
 */
int createTunDevice()
{
    int tunfd;
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    tunfd = open("/dev/net/tun", O_RDWR);
    if (tunfd == -1) {
        printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    ret = ioctl(tunfd, TUNSETIFF, &ifr);
    if (ret == -1) {
        printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    system("sysctl net.ipv4.ip_forward=1 &");
    system("iptables -F &");
    printf("Setup TUN interface success!\n");
    return tunfd;
}

// Callback function for certificate verification
/**
 * Callback function for SSL certificate verification
 * @param preverify_ok: Result of previous verification steps
 * @param x509_ctx: Certificate verification context
 * Returns: 1 to accept the certificate, 0 to reject
 * Notes:
 * - Prints certificate subject name
 * - Handles self-signed certificate cases
 * - Provides detailed verification failure information
 */
int verify_callback(int preverify_ok, X509_STORE_CTX* x509_ctx)
{
    char buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);

    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
        printf("Verification passed.\n");
    } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            printf("Ignoring self-signed certificate error.\n");
            return 1;
        }
        printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
        exit(7);
    }
    return preverify_ok;
}

// Function to setup TCP client connection
/**
 * Establishes TCP connection to VPN server
 * @param hostname: Server hostname to connect to
 * Returns: Socket file descriptor
 * Notes:
 * - Creates TCP socket
 * - Binds to local address
 * - Connects to remote server on port 4433
 */
int setupTCPClient(const char* hostname)
{
    struct sockaddr_in server_addr;
    struct hostent* hp = gethostbyname(hostname);

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(sockfd, "socket");

    struct sockaddr_in client_addr;
    bzero(&client_addr, sizeof(struct sockaddr_in));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(0);
    int err = bind(sockfd, (struct sockaddr*)&client_addr, sizeof(client_addr));
    CHK_ERR(err, "bind");

    memset(&server_addr, '\0', sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    server_addr.sin_port = htons(4433);
    server_addr.sin_family = AF_INET;

    connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));

    return sockfd;
}

// Function to handle data from TUN device
/**
 * Handles data received from TUN device
 * @param tunfd: TUN device file descriptor
 * @param ssl: SSL connection object
 * Returns: 1 on success, -1 on failure
 * Notes:
 * - Reads data from TUN device
 * - Encrypts and sends data through SSL connection
 */
int tunSelected(int tunfd, SSL* ssl)
{
    int len = 0;
    char buff[BUFF_SIZE];
    bzero(buff, sizeof(buff));
    printf("Got a packet from TUN\n");
    len = read(tunfd, buff, sizeof(buff));
    if (len <= 0) {
        if (len == 0) {
            printf("Got a packet length %d\n", len);
        }
        return -1;
    }
    SSL_write(ssl, buff, len);
    return 1;
}

// Function to handle data from socket
/**
 * Handles data received from SSL tunnel
 * @param tunfd: TUN device file descriptor
 * @param ssl: SSL connection object
 * Returns: 1 on success, -1 on failure
 * Notes:
 * - Reads encrypted data from SSL connection
 * - Decrypts and writes to TUN device
 */
int socketSelected(int tunfd, SSL* ssl)
{
    int len = 0;
    char buff[BUFF_SIZE];
    bzero(buff, sizeof(buff));
    printf("Got a packet from tunnel\n");
    len = SSL_read(ssl, buff, BUFF_SIZE);
    if (len <= 0) {
        if (len == 0) {
            printf("Got a packet length %d\n", len);
        }
        return -1;
    }
    write(tunfd, buff, len);
    return 1;
}

// Function to setup TLS client
/**
 * Initializes and configures SSL client
 * @param hostname: Server hostname for verification
 * Returns: Configured SSL object
 * Notes:
 * - Initializes OpenSSL library
 * - Loads certificates and private keys
 * - Configures verification parameters
 * - Sets up security options
 */
SSL* setupTLSClient(const char* hostname)
{
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD* meth;
    SSL_CTX* ctx;
    SSL* ssl;

    meth = (SSL_METHOD*)(SSLv23_client_method());
    ctx = SSL_CTX_new(meth);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE_PATH, NULL) < 1) {
        printf("Error loading CA file %s\n", CA_CERT_FILE_PATH);
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    SSL_CTX_set_verify_depth(ctx, 1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    if (SSL_CTX_load_verify_locations(ctx, NULL, CA_DIR) < 1) {
        printf("[ERRO] Error setting the verify locations. \n");
        exit(0);
    }

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE_PATH, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE_PATH, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-3);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public keyn");
        exit(-4);
    }
    ssl = SSL_new(ctx);

    X509_VERIFY_PARAM* vpm = SSL_get0_param(ssl);

    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
}

// Main function
/**
 * Main function - VPN client entry point
 * Command line args:
 * argv[1]: Server hostname
 * argv[2]: Server port
 * Process flow:
 * 1. Setup SSL/TLS connection
 * 2. Create and configure TUN device
 * 3. Perform user authentication
 * 4. Handle bidirectional VPN traffic
 */
int main(int argc, char* argv[])
{

    char* hostname = (char*)("yahoo.com");
    int port = 443;

    if (argc != 3) {
        printf("Invalid arguments\n");
        printf("Usage example: ./tlsclient dsy.com 4433\n");
        printf("The last argument means port number that miniVPNserver is listening\n");
        return 0;
    }
    hostname = argv[1];
    port = atoi(argv[2]);

    SSL* ssl = setupTLSClient(hostname);
    int sockfd = setupTCPClient(hostname);

    SSL_set_fd(ssl, sockfd);
    CHK_NULL(ssl);
    int err = SSL_connect(ssl);

    CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    char buf[9000];
    char sendBuf[200];

    int tunfd = createTunDevice();
    char ipstring[200] = "ifconfig tun0 192.168.53.2/24";
    char tunWorkString[300];
    system("ifconfig tun0 192.168.53.2/24 up");

    char clientip[200];
    strcpy(clientip, "192.168.53.2");
    SSL_write(ssl, clientip, sizeof(clientip));
    int len = SSL_read(ssl, clientip, sizeof(clientip) - 1);
    clientip[len] = '\0';
    if (0 == strcmp(clientip, "0.0.0.0")) {
        printf("All ip is occupied.There is no ip for this client.\n");
        printf("miniVPN is going to exit.\n");
        exit(1);
    }
    printf("Malloc ip successfully.Your ip is %s\n", clientip);
    strcpy(tunWorkString, ipstring);
    strcat(tunWorkString, " down");
    system(tunWorkString);
    strcpy(tunWorkString, "ifconfig tun0 ");
    strcat(tunWorkString, clientip);
    strcat(tunWorkString, "/24 up");
    system(tunWorkString);
    system("route add -net 192.168.60.0/24 tun0");

    char user[256];
    char passwd[256];
    char loginBuff[256];
    len = SSL_read(ssl, loginBuff, sizeof(loginBuff) - 1);
    if (len > 0) {
        loginBuff[len] = '\0';
        printf("Server says: %s\n", loginBuff);
    }

    for (int i = 0; i < 3; ++i) {
        printf("Please input username:");
        fgets(user, sizeof(user), stdin);
        user[strcspn(user, "\n")] = '\0';

        printf("Please input password:");
        set_disp_mode(STDIN_FILENO, 0);
        fgets(passwd, sizeof(passwd), stdin);
        set_disp_mode(STDIN_FILENO, 1);
        passwd[strcspn(passwd, "\n")] = '\0';

        int ret = SSL_write(ssl, user, strlen(user));
        if (ret <= 0) {
            printf("SSL_write failed when sending username.\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        ret = SSL_write(ssl, passwd, strlen(passwd));
        if (ret <= 0) {
            printf("SSL_write failed when sending password.\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        int replen = SSL_read(ssl, loginBuff, sizeof(loginBuff) - 1);
        if (replen <= 0) {
            printf("Server response error. Maybe server has exited.\n");
            printf("SSL_read returned %d\n", replen);
            ERR_print_errors_fp(stderr);
            printf("This client is going to exit.\n");
            exit(1);
        }
        loginBuff[replen] = '\0';

        printf("\nlogin response: length is %d, content is %s\n", replen, loginBuff);

        int response = atoi(loginBuff);
        if (response == 1) {
            printf("Login successfully.\n");
            break;
        } else if (response == -1) {
            printf("User %s not found or it is not a valid user.\n", user);
        } else if (response == -2) {
            printf("Invalid password.\n");
        }

        if (i == 2) {
            printf("Login failed. miniVPN is going to exit.\n");
            exit(1);
        }
    }

    int readResponse = 1;
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(tunfd, &readFDSet);
        FD_SET(sockfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(tunfd, &readFDSet)) {
            readResponse = tunSelected(tunfd, ssl);
        } else if (FD_ISSET(sockfd, &readFDSet)) {
            readResponse = socketSelected(tunfd, ssl);
        }
        if (readResponse == -1) {
            close(tunfd);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            printf("Because miniVPN server is terminated.This client is going to exit.\n");
            exit(0);
        }
    }
}

// Macro to define echo flags
#define ECHOFLAGS (ECHO | ECHOE | ECHOK | ECHONL)

/**
 * Controls terminal echo mode for password input
 * @param fd: File descriptor for terminal
 * @param option: 1 to enable echo, 0 to disable
 * Returns: 0 on success, 1 on failure
 * Notes:
 * - Modifies terminal attributes to hide/show input
 * - Used for secure password entry
 */
int set_disp_mode(int fd, int option)
{
    int err;
    struct termios term;
    if (tcgetattr(fd, &term) == -1) {
        perror("Cannot get the attribution of the terminal");
        return 1;
    }
    if (option)
        term.c_lflag |= ECHOFLAGS;
    else
        term.c_lflag &= ~ECHOFLAGS;
    err = tcsetattr(fd, TCSAFLUSH, &term);
    if (err == -1 && err == EINTR) {
        perror("Cannot set the attribution of the terminal");
        return 1;
    }
    return 0;
}