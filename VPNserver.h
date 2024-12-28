#include <arpa/inet.h>
#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <math.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Certificate and key file paths for SSL/TLS configuration
#define HOME "./cert_server/"
#define CERT_FILE_PATH HOME "server-dsy-crt.pem"
#define KEY_FILE_PATH HOME "server-dsy-key.pem"
#define CA_CERT_FILE_PATH HOME "ca-dsy-crt.pem"

// Network and buffer configurations
#define LISTEN_PORT 4433
#define BUFF_SIZE 5000

// Error checking macros
// CHK_NULL: Checks for NULL pointer and exits if true
#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(1)
    
// CHK_ERR: Checks for system call errors (-1)
#define CHK_ERR(err, s) \
    if ((err) == -1) {  \
        perror(s);      \
        exit(1);        \
    }

// CHK_SSL: Checks for SSL-specific errors
#define CHK_SSL(err)                 \
    if ((err) == -1) {               \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }

// Mutex worker structure for thread synchronization
typedef struct _mutexWorker {
    int num;                       // Worker identifier
    pthread_mutex_t mutex;         // Mutex for thread synchronization
    pthread_mutexattr_t mutexattr; // Mutex attributes
} mutexWorker;

// Structure for managing named pipes (FIFOs)
typedef struct _pipeFileNode {
    char name[256];               // Name of the pipe
    int pipefd;                   // File descriptor for the pipe
    struct _pipeFileNode* next;   // Pointer to next node in linked list
} pipeFileNode;

// Structure for mapping IP addresses to pipe file descriptors
typedef struct _pipefdTable {
    int ipCode;                   // IP address code
    char* object;                 // Object identifier
    int value;                    // Associated value (usually a file descriptor)
    int len;                      // Length of object data
    struct _pipefdTable* next;    // Pointer to next entry
} pipefdTable;

// Structure for SSL pipe operations
typedef struct _pipeWorker {
    char pipe[512];              // Pipe name/path
    SSL* ssl;                    // SSL connection handle
} pipeWorker;

// Structure for IP address flagging
typedef struct ipFlag {
    int area[256];              // Array for storing IP-related flags
} ipFlag;

// Structure for TUN device listening worker
typedef struct _tunListenWork {
    int tunfd;                  // TUN device file descriptor
    int pipefdTableShareMemoryId; // Shared memory ID for pipe table
    pipefdTable* tables;        // Pointer to pipe tables
} tunListenWorker;

// Extract IP code from object string
// Returns the last octet of an IP address
int pipefdTable_ipCode(char* object, int len)
{
    int numOfDot = 0;
    int p;
    for (int i = 0; i < len; i++) {
        if (object[i] == '.') {
            numOfDot++;
        }
        if (numOfDot == 3) {
            p = i;
            break;
        }
    }
    p++;
    int ip = atoi(object + p);
    return ip;
}

// Table management functions
void pipefdTable_insert(pipefdTable* tables, char* object, int len, int value)
{
    int ip = pipefdTable_ipCode(object, len);
    pipefdTable* head = &tables[ip];
    head->value = value;
}

void pipefdTable_insert_by_index(pipefdTable* tables, int index ,int value){
    tables[index].value = value;
}

pipefdTable* pipefdTable_get_by_index(pipefdTable* tables, int index){
    return &tables[index];
}

pipefdTable* pipefdTable_get(pipefdTable* tables, char* object, int len)
{
    printf("Start pipefdTable_get\n");
    int ip = pipefdTable_ipCode(object, len);
    return &tables[ip];
}

void pipefdTable_delete(pipefdTable* tables, char* object, int len)
{
    if (object == NULL) {
        return;
    }
    int ip = pipefdTable_ipCode(object, len);
    pipefdTable* head = &tables[ip];
    head->value = 0;
}

// Initialize mutex worker with process-shared attributes
void mutexWorkerInit(mutexWorker* worker)
{
    pthread_mutexattr_init(&worker->mutexattr);
    pthread_mutexattr_setpshared(&worker->mutexattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&worker->mutex, &worker->mutexattr);
}

// Initialize SSL context and create new SSL instance
// Returns: Configured SSL object
SSL* sslInit()
{
    SSL_METHOD* meth;
    SSL_CTX* ctx;
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    meth = (SSL_METHOD*)SSLv23_server_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE_PATH, NULL);

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE_PATH, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE_PATH, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    }
    return SSL_new(ctx);
}

// Set up TCP server socket
// Returns: File descriptor for the listening socket
int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset(&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(LISTEN_PORT);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));

    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

#define LINKED_LIST