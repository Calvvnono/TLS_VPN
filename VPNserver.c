#include "VPNserver.h"
#include <stdio.h>

// Global mutex workers for thread synchronization
mutexWorker* ipFlagMutexWorker;        // Mutex for IP allocation
mutexWorker* pipefdTableMutexWorker;   // Mutex for pipe file descriptor table

/**
 * Creates and configures a TUN device for VPN tunnel
 * Returns: file descriptor of TUN device, -1 on failure
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
    system("ifconfig tun0 192.168.53.1/24 up");
    system("sysctl net.ipv4.ip_forward=1 &");
    system("iptables -F &");
    printf("Setup TUN interface success!\n");
    return tunfd;
}

/**
 * Thread function that listens on TUN device for incoming packets
 * Forwards packets to appropriate named pipes based on destination IP
 * @param _worker: pointer to tunListenWorker containing TUN fd and pipe tables
 */
void* tunListen(void* _worker)
{
    tunListenWorker* worker = (tunListenWorker*)_worker;
    int tunfd = worker->tunfd;
    pipefdTable* tables = worker->tables;
    char buff[BUFF_SIZE];
    while (1) {
        // Read packet from TUN device
        int len = read(tunfd, buff, BUFF_SIZE);
        
        // Process only IPv4 packets (0x45 indicates IPv4)
        if (len > 19 && buff[0] == 0x45) {
            // Extract destination IP from packet header
            char ipdst[256];
            int ipv4[4];
            ipv4[0] = (unsigned char)buff[16];
            ipv4[1] = (unsigned char)buff[17];
            ipv4[2] = (unsigned char)buff[18];
            ipv4[3] = (unsigned char)buff[19];
            sprintf(ipdst, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
            printf("Receive from TUN: packet length:%d,packet dst ip: %s\n", len, ipdst);
            char pipe_filename[300];
            sprintf(pipe_filename, "/home/seed/Desktop/miniVPN/pipe/%s", ipdst);
            int pipefd;
            // Get or create pipe file descriptor for this destination
            pthread_mutex_lock(&pipefdTableMutexWorker->mutex);
            pipefdTable* record = pipefdTable_get_by_index(tables, ipv4[3]);
            if (record->value == 0) {
                pipefd = open(pipe_filename, O_WRONLY);
                pipefdTable_insert_by_index(tables, ipv4[3], pipefd);
            } else {
                if (record->value == 0) {
                    record->value = open(pipe_filename, O_WRONLY);
                }
                pipefd = record->value;
            }
            pthread_mutex_unlock(&pipefdTableMutexWorker->mutex);

            printf("open pipe file %s with pipefd %d\n", pipe_filename, pipefd);
            if (pipefd == -1) {
                printf("pipe file %s is not exist\n", pipe_filename);
            } else {
                write(pipefd, buff, len);
            }
        }
    }
}

/**
 * Handles user authentication using Linux shadow password system
 * @param ssl: SSL connection for secure communication
 * Returns: 1 on success, -1 for invalid user, -2 for invalid password, -3 for max attempts
 */
int login(SSL* ssl)
{
    char userName[256];
    char passwd[1024];
    char* invalid_user = "-1";
    char* invalid_passwd = "-2";
    char* success = "1";
    char* fail = "-3";

    int len;
    int threeChance = 3;
    while (threeChance != 0) {
        len = SSL_read(ssl, userName, sizeof(userName));
        userName[len - 1] = '\0';
        len = SSL_read(ssl, passwd, sizeof(passwd));
        passwd[len - 1] = '\0';
        struct spwd* user_profile;
        char* hash_passwd;
        user_profile = getspnam(userName);
        if (user_profile == NULL) {
            printf("password of %s not found or it is not a valid user\n", userName);
            SSL_write(ssl, invalid_user, strlen(invalid_user) + 1);
            threeChance--;
            continue;
        }
        hash_passwd = crypt(passwd, user_profile->sp_pwdp);
        if (strcmp(hash_passwd, user_profile->sp_pwdp) != 0) 
        {
            printf("Invalid password\n");
            SSL_write(ssl, invalid_passwd, strlen(invalid_passwd) + 1);
            threeChance--;
            continue;
        }
        SSL_write(ssl, success, strlen(success) + 1);
        return 1;
    }
    SSL_write(ssl, fail, strlen(fail) + 1);
    return -3;
}

/**
 * Thread function that listens on named pipe and forwards data to SSL connection
 * @param _worker: pointer to pipeWorker containing pipe path and SSL connection
 */
void* pipeListen(void* _worker)
{
    pipeWorker* worker = (pipeWorker*)_worker;
    printf("pipe listen thread try to open pipe %s\n", worker->pipe);
    int pipefd = open(worker->pipe, O_RDONLY);
    char buff[BUFF_SIZE];
    int len = 1;
    printf("pipe listen running\n");
    while (len > 0) {
        len = read(pipefd, buff, BUFF_SIZE);
        printf("read %d bytes from pipe %s\n", len, worker->pipe);
        SSL_write(worker->ssl, buff, len);
    }
    if (len < 0) {
        printf("len < 0 error\n");
    }
    printf("%d bytes read from %s.Connection closed and pipe remove\n", len, worker->pipe);
    printf("pipe listen ended\n");
    remove(worker->pipe);
}

/**
 * Creates a named pipe and starts a thread to listen on it
 * @param pipeThread: pointer to thread handle
 * @param worker: configuration for pipe listener thread
 */
void createSubThread(pthread_t* pipeThread, pipeWorker* worker)
{
    printf("try to create pipe %s\n", worker->pipe);
    if (mkfifo(worker->pipe, 0666) == -1) {
        printf("IP %s has been used\n", worker->pipe);
        return;
    } else {
        pthread_create(pipeThread, NULL, pipeListen, (void*)worker);
    }
}

/**
 * Allocates an available IP address from the VPN subnet
 * @param clientip: buffer to store allocated IP
 * @param flags: IP allocation status array
 * Returns: last octet of allocated IP, 0 if no IPs available
 */
int getAvailableIP(char* clientip, ipFlag* flags)
{
    pthread_mutex_lock(&ipFlagMutexWorker->mutex);
    for (int i = 3; i < 255; ++i) {
        if ((flags->area)[i] == 0) {
            sprintf(clientip, "192.168.53.%d", i);
            (flags->area)[i] = 1;
            pthread_mutex_unlock(&ipFlagMutexWorker->mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&ipFlagMutexWorker->mutex);
    return 0;
}

/**
 * Main function - Sets up VPN server and handles client connections
 * - Initializes shared memory for IP allocation and pipe file descriptors
 * - Creates TUN device
 * - Starts TUN listener thread
 * - Accepts and handles client connections in child processes
 */
int main()
{
    // Initialize shared memory for IP allocation tracking
    int ipFlagShareMemoryId = shmget(IPC_PRIVATE, sizeof(ipFlag), IPC_EXCL | 0666);
    int pipefdTableShareMemoryId = shmget(IPC_PRIVATE, 256 * sizeof(pipefdTable), IPC_EXCL | 0666);
    if (ipFlagShareMemoryId == -1) {
        printf("Get sharedMemory failed\n");
        exit(1);
    }
    ipFlag* ipflags = (ipFlag*)shmat(ipFlagShareMemoryId, NULL, 0);

    pipefdTable* pipefdTables = (pipefdTable*)shmat(pipefdTableShareMemoryId, NULL, 0);
    memset(ipflags, 0, sizeof(ipFlag));
    memset(pipefdTables, 0, sizeof(pipefdTable) * 256);
    for (int i = 0; i < 256; ++i) {
        pipefdTables[i].next = NULL;
    }

    // Initialize mutexes for thread synchronization
    ipFlagMutexWorker = mmap(NULL, sizeof(mutexWorker), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    memset(ipFlagMutexWorker, 0, sizeof(mutexWorker));
    mutexWorkerInit(ipFlagMutexWorker);

    pipefdTableMutexWorker = mmap(NULL, sizeof(mutexWorker), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    memset(pipefdTableMutexWorker, 0, sizeof(mutexWorker));
    mutexWorkerInit(pipefdTableMutexWorker);

    SSL* ssl;
    int err;
    ssl = sslInit();

    struct sockaddr_in sa_client;
    socklen_t client_len = sizeof(sa_client);

    int tcpListenSock = setupTCPServer();
    int tunfd = createTunDevice();
    printf("opened tunfd is %d\n", tunfd);
    system("rm -rf /home/seed/Desktop/miniVPN/pipe/*");
    mkdir("/home/seed/Desktop/miniVPN/pipe", 0666);
    pthread_t tunListenThread;

    tunListenWorker tunWorker;
    tunWorker.tunfd = tunfd;
    tunWorker.pipefdTableShareMemoryId = pipefdTableShareMemoryId;
    tunWorker.tables = pipefdTables;
    pthread_create(&tunListenThread, NULL, tunListen, (void*)(&tunWorker));

    // Main server loop
    while (1) {
        // Accept new client connection
        int tcpClientConnectionSock = accept(tcpListenSock, (struct sockaddr*)&sa_client, &client_len);
        int pid;
        // Fork new process for each client
        if ((pid = fork()) == 0) 
        {
            // Child process - handle client connection
            ipFlag* ipflags = (ipFlag*)shmat(ipFlagShareMemoryId, NULL, 0);
            pipefdTable* pipefdTables = (pipefdTable*)shmat(pipefdTableShareMemoryId, NULL, 0);
            close(tcpListenSock);
            // Establish SSL connection
            SSL_set_fd(ssl, tcpClientConnectionSock);
            int err = SSL_accept(ssl);
            CHK_SSL(err);
            printf("SSL connection established successfully\n");

            // Allocate IP address for client
            char clientip[256];
            SSL_read(ssl, clientip, sizeof(clientip));
            int malloc_ip;
            if (0 != (malloc_ip = getAvailableIP(clientip, ipflags))) {
                printf("ip %s is allocated successfully\n", clientip);
                SSL_write(ssl, clientip, sizeof(clientip));
            } else {
                printf("All ip is occupied\n");
                strcpy(clientip, "0.0.0.0");
                SSL_write(ssl, clientip, sizeof(clientip));
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(tcpClientConnectionSock);
                printf("Close sock and end subProcess pid:%d\n", pid);
                return 0;
            }

            printf("Client IP address: %s\n", clientip);

            // Authenticate user
            int login_result;
            pipeWorker worker;
            if ((login_result = login(ssl)) == 1)
            {
                char* success_message = "Login successfully";
                printf("%s\n", success_message);
                pthread_t pipeThread;

                strcpy(worker.pipe, "/home/seed/Desktop/miniVPN/pipe/");
                strcat(worker.pipe, clientip);
                sprintf(worker.pipe,"/home/seed/Desktop/miniVPN/pipe/%s",clientip);
                worker.ssl = ssl;

                // Create pipe and start forwarding threads
                createSubThread(&pipeThread, &worker);
                int len = 1;
                while (len > 0) {
                    char buf[BUFF_SIZE];
                    len = SSL_read(ssl, buf, sizeof(buf));
                    printf("SSL read %d bytes\n", len);
                    write(tunfd, buf, len);
                    printf("tun written %d bytes\n", len);
                }
                if (len < 0) {
                    printf("len < 0 error\n");
                }
                pthread_cancel(pipeThread);
                remove(worker.pipe);
            } else if (login_result == -1) {
                printf("login falied because of user error\n");
            } else if (login_result == -2) {
                printf("login failed because of wrong password\n");
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(tcpClientConnectionSock);

            // Cleanup when client disconnects
            // - Release IP address
            pthread_mutex_lock(&ipFlagMutexWorker->mutex);
            printf("ip %s is released\n", clientip);
            (ipflags->area)[malloc_ip] = 0;
            pthread_mutex_unlock(&ipFlagMutexWorker->mutex);

            // - Close pipe
            pthread_mutex_lock(&pipefdTableMutexWorker->mutex);
            printf("pipe file %s descriptor released\n", worker.pipe);
            pipefdTable_delete(pipefdTables, worker.pipe, strlen(worker.pipe));
            pthread_mutex_unlock(&pipefdTableMutexWorker->mutex);

            // - Detach shared memory
            shmdt((void*)ipflags);
            shmdt((void*)pipefdTables);
            printf("Close sock and end subProcess pid:%d\n", getpid());
            return 0;
        } else {
        }
    }
    shmdt((void*)ipflags);
    shmdt((void*)pipefdTables);
    return 0;
}