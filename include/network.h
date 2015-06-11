#ifndef NETWORK_H
#define NETWORK_H 1

#include <pthread.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <time.h>



#define THREAD_MODE_LISTEN (1)
#define THREAD_MODE_READ (2)
#define THREAD_MODE_WRITE (3)

#define THREAD_WRITETASK_NUM (1)
#define THREAD_READTASK_NUM (2)

struct client_node
{
    int index;
    int fd;
    int stat;
    int needClose;
    char ip_addr[IPV4_LEN];
    unsigned port;
    struct sockaddr_in sockaddr;
    int time_out;
    void *next;
};

struct client_list
{
    int count;
    pthread_t thread_id;
    struct client_node *head;
} ;


typedef int (*TYPE_PROCESS_FRAME)(struct client_node*);
typedef int (*TYPE_FUN_READTASK)(int,char *, int);

typedef void (*TYPE_FUN_TIMER_HANDLE)(int sig, siginfo_t *si, void *uc);


struct thread_node
{
    int index;
    int mode;
    pthread_t id;
    fd_set fdsr;
    int max_fd;
    int stat;
    int needClose;
    struct client_list *pclient_list;
    TYPE_PROCESS_FRAME pProcess_frame;
    void *next;
};

struct thread_list
{
    int count;
    struct thread_node *head;
};

//网络包头
struct net_packet_head 
{
    unsigned int command_code;			//包类型
    unsigned int version;				//版本
    unsigned int encryption_type;
    unsigned int data_type; 			//数据类型
    unsigned int data_len;
};

struct thread_readtask
{
    int fd;
    struct thread_readtask *next;
};
struct thread_writetask
{
    int fd;
    char *data;
    int data_len;
    struct thread_writetask *next;
};


int select_time_out(int fd,int second);
int select_time_out_tv(int fd,int sec,int usec);
int select_sleep(int sec,int usec);


int network_server_start(struct thread_list *pThreadList);
int client_list_get_max_fd(struct client_list* pclientlist);
int network_server_wait_finish(struct thread_list *pThreadList);
int network_client_connect(char *ip_addr,unsigned short server_port);

int network_connect_only(char *ip_addr,unsigned short server_port);

int network_client_disconnect(int client_fd);


int send_string(int server_fd,char *str,int n);
int send_conclude(int server_fd);
int send_command(int server_fd,char *str,int n);
int send_struct(int server_fd,unsigned char *data,int n);
int recive_struct(int socket_fd,unsigned char *data,int data_len);
int network_epoll_start();

int print_siginfo(siginfo_t *si);
int network_timer_create(timer_t *pTimerid,TYPE_FUN_TIMER_HANDLE timer_handle);
int network_timer_setting(timer_t timerid,int ms);


struct thread_list * network_server_init(unsigned short port,TYPE_PROCESS_FRAME pProcessFrame);
struct client_node* client_list_get_node(struct client_list* pClientList,int fd);


#endif
