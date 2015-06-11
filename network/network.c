#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h>        /* For mode constants */
#include <semaphore.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <errno.h>
#include "common.h"
#include "network.h"

#define CLOCKID CLOCK_REALTIME
#define SIG SIGRTMIN


static int server_listen_fd = 0;
static int process_count = 0;
static sem_t* sem_lock;
static int connect_count = 0;
static int connecting_count = 0;
static int max_fd = 0;

//epoll
int num = 0;
int epoll_fd = 0;
struct epoll_event ev, events[20];
pthread_mutex_t mutex;
pthread_cond_t cond;

struct thread_readtask *readtask_head=NULL;
struct thread_readtask *readtask_tail=NULL;
struct thread_writetask *writetask_head=NULL;
struct thread_writetask *writetask_tail=NULL;
struct client_list *clientlist=NULL;
TYPE_FUN_READTASK callback_readtask=NULL;
void *network_epoll_thread_read_task(void *args);
void *network_epoll_thread_write_task(void *args);


int print_siginfo(siginfo_t *si)
{
   timer_t *tidp;
   int or;

   tidp = si->si_value.sival_ptr;

   dlog("    sival_ptr = %p; ", si->si_value.sival_ptr);
   dlog("    *sival_ptr = 0x%lx\n", (long) *tidp);

   or = timer_getoverrun(*tidp);
   if (or == -1)
   {
       printf("print_siginfo:error timer_getoverrun\n");
       return -1;
   }
   else
       printf("    overrun count = %d\n", or);
}

static void handler(int sig, siginfo_t *si, void *uc)
{
   /* Note: calling printf() from a signal handler is not
      strictly correct, since printf() is not async-signal-safe;
      see signal(7) */

   printf("Caught signal %d\n", sig);
   print_siginfo(si);
   signal(sig, SIG_IGN);
}

int network_timer_create(timer_t *pTimerid,TYPE_FUN_TIMER_HANDLE timer_handle)
{
    timer_t timerid;
    struct sigevent sev;
    sigset_t mask;
    struct sigaction sa;

    /* Establish handler for timer signal */

    printf("Establishing handler for signal %d\n", SIG);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = timer_handle;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIG, &sa, NULL) == -1)
    {
       printf("network_timer_create:error sigaction\n");
       return -1;
    }

    /* Block timer signal temporarily */
/*
    printf("Blocking signal %d\n", SIG);
    sigemptyset(&mask);
    sigaddset(&mask, SIG);
    if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)
    {
       printf("network_timer_create:error sigprocmask\n");
       return -1;
    }
*/
    /* Create the timer */

    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIG;
    sev.sigev_value.sival_ptr = &timerid;
    if (timer_create(CLOCKID, &sev, &timerid) == -1)
    {
       printf("network_timer_create:error timer_create\n");
       return -1;
    }

    printf("timer ID is 0x%lx\n", (long) timerid);
    *pTimerid = timerid;
    return 0;
}

int network_timer_create_by_sig(timer_t *pTimerid,int sig,TYPE_FUN_TIMER_HANDLE timer_handle)
{
    timer_t timerid;
    struct sigevent sev;
    sigset_t mask;
    struct sigaction sa;

    /* Establish handler for timer signal */

    printf("Establishing handler for signal %d\n", sig);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = timer_handle;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, NULL) == -1)
    {
       printf("network_timer_create:error sigaction\n");
       return -1;
    }

    /* Block timer signal temporarily */
/*
    printf("Blocking signal %d\n", SIG);
    sigemptyset(&mask);
    sigaddset(&mask, SIG);
    if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)
    {
       printf("network_timer_create:error sigprocmask\n");
       return -1;
    }
*/
    /* Create the timer */

    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = sig;
    sev.sigev_value.sival_ptr = &timerid;
    if (timer_create(CLOCKID, &sev, &timerid) == -1)
    {
       printf("network_timer_create:error timer_create\n");
       return -1;
    }

    printf("timer ID is 0x%lx\n", (long) timerid);
    *pTimerid = timerid;
    return 0;
}


int network_timer_setting(timer_t timerid,int timeMSec)
{

    long long freq_nanosecs;

    struct itimerspec its;

    /* Start the timer */  
    its.it_value.tv_sec = timeMSec / 1000;  
    its.it_value.tv_nsec = (timeMSec % 1000) * 1000000;  
  
    its.it_interval.tv_sec = 0;  
    its.it_interval.tv_nsec = 0;  

    if (timer_settime(timerid, 0, &its, NULL) == -1)
    {
       dlog_error();
       printf("network_timer_setting:error timer_settime\n");
       return -1;
    }
    return 0;
}
int get_ip_and_port_from_client_list(int socketfd,char *ip,int *port)
{
    struct client_node *clientNode = NULL;

    if(ip == NULL || port == NULL)
    {
        printf("get_ip_and_port_from_client_list:NULL PTR input\n");
        return -1;
    }

    clientNode = client_list_get_node(clientlist,socketfd);

    if(clientNode == NULL)
    {
        printf("get_ip_and_port_from_client_list:client_list_get_node(%d) failed\n",socketfd);
        return -1;
    }


    strncpy(ip,inet_ntoa(clientNode->sockaddr.sin_addr),IPV4_LEN);
    *port = ntohs(clientNode->sockaddr.sin_port);

    dlog("get_ip_and_port_from_client_list: get %s:%d\n",ip,*port);

    return 0;
};

int dlog_error()
{
    int error_num = errno;
    dlog("errno is %d: %s\n",error_num,strerror(error_num));
    return error_num;
};
int select_time_out(int fd,int second)
{
    fd_set set;
    struct timeval timeout;
    int rv;
    
    FD_ZERO(&set); /* clear the set */
    FD_SET(fd, &set); /* add our file descriptor to the set */
    
    timeout.tv_sec = second;
    timeout.tv_usec = 0;
    
    rv = select(fd + 1, &set, NULL, NULL, &timeout);
    if(rv == -1)
    {
      dlog_error();
      dlog("read_by_time_out:select\n"); /* an error accured */
      return -1;
    }
    else if(rv == 0)
    {
      dlog("read_by_time_out:timeout\n"); /* a timeout occured */
      return 1;
    }

    return 0; /* there was data to read */
}
int select_sleep(int sec,int usec)
{
    fd_set set;
    struct timeval timeout;
    int rv;
    
    
    timeout.tv_sec = sec;
    timeout.tv_usec = usec;
    
    rv = select(0, NULL, NULL, NULL, &timeout);
    if(rv == -1)
    {
      dlog_error();
      dlog("read_by_time_out:select\n"); /* an error accured */
      return -1;
    }
    else if(rv == 0)
    {
      dlog("read_by_time_out:timeout\n"); /* a timeout occured */
      return 1;
    }

    return 0; /* there was data to read */
}

int select_time_out_tv(int fd,int sec,int usec)
{
    fd_set set;
    struct timeval timeout;
    int rv;
    
    FD_ZERO(&set); /* clear the set */
    FD_SET(fd, &set); /* add our file descriptor to the set */
    
    timeout.tv_sec = sec;
    timeout.tv_usec = usec;
    
    rv = select(fd + 1, &set, NULL, NULL, &timeout);
    if(rv == -1)
    {
      dlog_error();
      dlog("read_by_time_out:select\n"); /* an error accured */
      return -1;
    }
    else if(rv == 0)
    {
      dlog("read_by_time_out:timeout\n"); /* a timeout occured */
      return 1;
    }

    return 0; /* there was data to read */
}


void network_server_colse_fd(int sockid)
{
    pthread_mutex_lock(&mutex);
    dlog("network_server_colse_fd:lock\n");
    
    
    fsync(sockid);

    close(sockid);
    struct client_node *tmp = client_list_get_node(clientlist,sockid);
    if(client_list_del(clientlist,tmp) != -1)
    {
        
        connecting_count --;

    };
    ev.data.fd = server_listen_fd;
    ev.events = EPOLLIN|EPOLLET;
    epoll_ctl(epoll_fd,EPOLL_CTL_MOD,server_listen_fd,&ev);
    pthread_mutex_unlock(&mutex);
    dlog("network_server_colse_fd:unlock\n");

    dlog("closed(%d) connecting_count is %d\n",sockid,connecting_count);
    client_list_show(clientlist); 
}

int mylock_init()
{
    sem_unlink("1234");
    sem_lock = sem_open("1234", O_CREAT, 0666, 1); 
    if(sem_lock == SEM_FAILED)
    {
        printf("sem_open error\n");
        return -1;
    }


    int val;      
    sem_getvalue(sem_lock, &val);     
    printf("sem value is %d\n",val);
    return 0;
};
int mylock_lock()
{

    sem_wait(sem_lock);
    return 0;
};

int mylock_unlock()
{
    sem_post(sem_lock);
    return 0;
};


struct client_list* client_list_create()
{
    struct client_list* pClientList = (struct client_list*)malloc(sizeof(struct client_list));
    if(pClientList== NULL)
    {
        printf("client_list_create:error  malloc failed\n");
        return NULL;
    };
    memset(pClientList,0,sizeof(struct client_list));


    return pClientList;
};

int client_list_time_out_check(struct client_list *pclientlist)
{
    dlog("client_list_time_out_check:into\n");
    if(pclientlist == NULL )
    {
        printf("client_list_time_out null ptr input\n");
        return -1;
    }
    
    int i=0;
    int count = 0;
    struct client_node *tmp=NULL;
    struct client_node *need_del=NULL;
    tmp = pclientlist->head;
    while(tmp != NULL)
    {
        tmp->time_out ++;
        if(tmp->time_out >= CHECK_TIME_OUT) //50s
        {
            need_del = tmp;
            tmp = tmp->next;

            dlog("time_out_check: need del %s:%d\n",need_del->ip_addr,need_del->port);
            readtask_delete_fd(need_del->fd);
            network_server_colse_fd(need_del->fd);
            continue;
        }
		
        count ++;
        tmp = tmp->next;
    };
    dlog("client_list_time_out_check:client_list count is %d\n",count);

    return 0;
};

int client_list_rest_time_out(struct client_list *pclientlist,int fd)
{
    dlog("client_list_time_out_check:into\n");
    if(pclientlist == NULL )
    {
        printf("client_list_time_out null ptr input\n");
        return -1;
    }
    
    int i=0;
    struct client_node *tmp=NULL;
    struct client_node *need_del=NULL;
    tmp = pclientlist->head;
    while(tmp != NULL)
    {
        tmp->time_out ++;
        if(tmp->fd == fd) 
        {
            tmp->time_out = 0;
            return 0;
        }
        tmp = tmp->next;
    };

    return -1;

};

int client_list_add(struct client_list *pclientlist,struct client_node *pclient)
{

    dlog("int to client_list_add \n");
    if(pclientlist == NULL || pclient == NULL)
    {
        printf("client_list_add null ptr input\n");
        return -1;
    }
    dlog("%u:client_list_add:add a client(%s:%d)\n",(unsigned int)pclientlist->thread_id
        ,inet_ntoa(pclient->sockaddr.sin_addr)
        ,ntohs(pclient->sockaddr.sin_port));

    
    struct client_node *pclient_node;

    pclient_node = (struct client_node*)malloc(sizeof(struct client_node));
    if(pclient_node == NULL)
    {
        printf("client_list_add:error,malloc failed\n");
        return -1;
    };
    memset(pclient_node,0,sizeof(struct client_node));
    memcpy(pclient_node,pclient,sizeof(struct client_node));

    struct client_node *tmp;
    tmp = pclientlist->head;
    if(tmp == NULL)
    {
        pclientlist->head = pclient_node;
    }
    else
    {
        while(tmp->next != NULL)
        {
            tmp=tmp->next;
        };
        tmp->next = pclient_node;
    }
    pclientlist->count ++;
    
    printf("%u(%d):client_list_add:add a client(%s:%d)\n",(unsigned int)pclientlist->thread_id
        ,pclientlist->count
        ,inet_ntoa(pclient_node->sockaddr.sin_addr)
        ,ntohs(pclient_node->sockaddr.sin_port));
    return pclientlist->count;
};


int client_list_del(struct client_list* pclientlist,struct client_node *pclient)
{
    dlog("int to client_list_del \n");
    if(pclientlist == NULL || pclient == NULL)
    {
        printf("client_list_del null ptr input\n");
        return -1;
    }

    

    dlog("%u:client_list_del:list(size:%d) del a client(%s:%d)\n",(unsigned int)pclientlist->thread_id
        ,pclientlist->count,inet_ntoa(pclient->sockaddr.sin_addr)
        ,ntohs(pclient->sockaddr.sin_port));

 
    
    close(pclient->fd);
    
    struct client_node *tmp;
    tmp = pclientlist->head;
    if(tmp == pclient)
    {
        pclientlist->head = tmp->next;
    }
    else
    {
        while(tmp->next != pclient)
        {
            tmp = tmp->next;
        };
        
        tmp->next = pclient->next;
    }
    pclientlist->count --;

    
    free(pclient);

    
    return pclientlist->count;
};

int client_list_show(struct client_list* pClientList)
{
    dlog("client list is(count:%d):\n",pClientList->count);

    return 0;

    if(pClientList == NULL )
    {
        printf("client_list_show null ptr input\n");
        return -1;
    }

    
    int i=0;
    struct client_node *tmp=NULL;
    tmp = pClientList->head;
    while(tmp != NULL)
    {
        printf("%u:%d, %s:%d\n",(unsigned int)pClientList->thread_id,i++,inet_ntoa(tmp->sockaddr.sin_addr),ntohs(tmp->sockaddr.sin_port));
        tmp = tmp->next;
    };

    return 0;
}

struct client_node* client_list_get_node(struct client_list* pClientList,int fd)
{
    dlog("client list is:\n");

    if(pClientList == NULL )
    {
        dlog("client_list_show null ptr input\n");
        return NULL;
    }

    
    int i=0;
    struct client_node *tmp=NULL;
    tmp = pClientList->head;
    while(tmp != NULL)
    {
        if(tmp->fd == fd)
        {
            return tmp;
        }
        tmp = tmp->next;
    };

    return NULL;
}


int client_list_get_max_fd(struct client_list* pclientlist)
{
    dlog("client_list_get_max_fd:\n");
    if(pclientlist== NULL)
    {
        printf("client_list_get_max_fd null ptr input\n");
        return -1;
    }
    int i=0;
    int maxfd = 0;
    struct client_node *tmp;
    tmp = pclientlist->head;
    dlog("tmp ptr is %p\n",tmp);
    while(tmp != NULL)
    {
        if(tmp->fd > maxfd)
        {
            maxfd = tmp->fd;
        };
        tmp=tmp->next;
    };

    
    if(server_listen_fd > maxfd)
    {
        maxfd = server_listen_fd;
    };

    
    dlog("%u, maxfd:%d\n",(unsigned int)pclientlist->thread_id,maxfd);

    return maxfd;
}




int network_process_frame_temp(struct client_node* pclient)
{
    int recv_size = 0;
    int recv_count = 0;
    unsigned char buf[MAX_BUFF_SIZE];
    memset(buf,0,sizeof(buf));
    recv_size = recv(pclient->fd,buf,10,0);
    if(recv_size <= 0)
    {
        //client_list_del(pclient);
        pclient->needClose = 1;
        return 0;
    }

    recv_count += recv_size;

    dlog("%d:recv %d data\n",getpid(),recv_count);
    
    return 0;
};


void thread_main(void *arg)
{
    dlog("start thread_main\n");
    int pid = 0;
    int ret = 0;
    int client_fd = 0;
    int connect_num = 0;
    int i=0;
    

    struct timeval tv;
    socklen_t client_addr_size = sizeof(struct sockaddr_in);
    struct sockaddr_in client_addr;
    struct client_node stClienNode;
    struct thread_node *pThreadNode = (struct thread_node *)arg;

    memset(&tv,0,sizeof(tv));
    memset(&client_addr,0,sizeof(client_addr));
    memset(&stClienNode,0,sizeof(stClienNode));

    FD_ZERO(&(pThreadNode->fdsr));
    FD_SET(server_listen_fd,&(pThreadNode->fdsr));
    pThreadNode->max_fd = server_listen_fd; 

    tv.tv_sec = 30;
    tv.tv_usec = 0;



    dlog("thread %u start,max_fd is %d\n",(unsigned int)pThreadNode->id,pThreadNode->max_fd);

    while(1)
    {    

       FD_ZERO(&(pThreadNode->fdsr));

       
       FD_SET(server_listen_fd,&(pThreadNode->fdsr));

       
       int i=0;
       int i_del = 0;
       struct client_node *pClientNode = pThreadNode->pclient_list->head;
       struct client_node *tmp = NULL;
       while(pClientNode != NULL)
       {
           tmp = pClientNode->next;
           if(pClientNode->needClose == 1)
           { 
                if(pClientNode->fd == pThreadNode->max_fd)
                {
                    client_list_del(pThreadNode->pclient_list,pClientNode);
                    pThreadNode->max_fd = client_list_get_max_fd(pThreadNode->pclient_list);
                }
                else
                {
                    client_list_del(pThreadNode->pclient_list,pClientNode);
                }
           }
           else
           {
               FD_SET(pClientNode->fd,&(pThreadNode->fdsr));
               if(pThreadNode->max_fd<pClientNode->fd)
               {
                  pThreadNode->max_fd = pClientNode->fd;
               };

           }
           
           pClientNode = tmp;
       };
        dlog("has been process %d connect\n",connect_count);
        ret = select(pThreadNode->max_fd +1,&pThreadNode->fdsr,NULL,NULL,&tv);
        
        //ret = select(pThreadNode->max_fd +1,&pThreadNode->fdsr,NULL,NULL,NULL);
        dlog("%u:select active\n",(unsigned int)pThreadNode->id);
        if(ret < 0)
        {
            printf("select error\n");
            return ;
        }
        else if(ret == 0)
        {
            dlog("select timeout\n");
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            continue;
        }


        pClientNode = pThreadNode->pclient_list->head;
        tmp = NULL;
        while(pClientNode != NULL)
        {
            tmp = pClientNode->next;
            if(FD_ISSET(pClientNode->fd,&(pThreadNode->fdsr)))
            {
                if(pThreadNode->pProcess_frame != NULL)
                {
                    (*pThreadNode->pProcess_frame)(pClientNode);
                }
            }
            pClientNode = tmp;
        };

        if(FD_ISSET(server_listen_fd,&(pThreadNode->fdsr)))
        {
            if(pThreadNode->pclient_list->count < MAX_CONNECT_NUM)
            {
                mylock_lock();
                memset(&stClienNode,0,sizeof(stClienNode));
                memset(&client_addr,0,sizeof(client_addr));
                
                client_fd = accept(server_listen_fd,(struct sockaddr*)&client_addr,&client_addr_size);
                if(client_fd == -1)
                {
                    printf("%d:accept error\n",pid);
                    mylock_unlock();
                    continue;
                }
                else
                { 
                    dlog("client connected\n");
                    memset(&stClienNode,0,sizeof(stClienNode));
                    stClienNode.fd = client_fd;
                    stClienNode.stat = 1;
                    memcpy(&(stClienNode.sockaddr),&client_addr,sizeof(struct sockaddr_in));
                    ret = client_list_add(pThreadNode->pclient_list,&stClienNode);
                    if(ret == -1)
                    {
                        printf("thread_main:client_list_add error\n");
                                            continue;
                    }
                    connect_count ++;
                }
                mylock_unlock();

                client_list_show(pThreadNode->pclient_list);
            }
        };
    }
    
    //process_count ++;
};

struct thread_list* thread_list_createList()
{
    struct thread_list *pthread_list = (struct thread_list*)malloc(sizeof(struct thread_list));
    if(pthread_list == NULL)
    {
        printf("thread_list_createList:error , malloc failed\n");
        return 0;
    }
    memset(pthread_list,0,sizeof(struct thread_list));
    return pthread_list;
};
int thread_list_add(struct thread_list *pthread_list,struct thread_node *pthread_node)
{
    struct thread_node *tmp = NULL;

    if(pthread_list == NULL || pthread_node == NULL)
    {
        printf("error:thread_list_add,NULL ptr input\n");
        return -1;
    };

    if(pthread_list->head == NULL)
    {
        pthread_list->head = pthread_node;
        pthread_list->count ++;
    }
    else
    {
        tmp = pthread_list->head;
        while(tmp->next != NULL)
        {
            tmp=tmp->next;
        };
        tmp->next = pthread_node;
        pthread_list->count ++;
    }
    return 0;
};
int thread_list_del(struct thread_list *pthread_list,struct thread_node *pthread_node);
int thread_list_show(struct thread_list *pthread_list,struct thread_node *pthread_node);

struct thread_list * network_server_init(unsigned short port,TYPE_PROCESS_FRAME pProcessFrame)
{
    int i = 0;
    int ret = 0;
    int yes = 1; 
    pthread_t id;
    struct thread_list *pThreadlist = NULL;
    struct client_list *pClientList;
    struct thread_node *pstThreadNode;
    //int server_listen_fd = 0;
    struct sockaddr_in server_addr;
    memset(&server_addr,0,sizeof(server_addr));



    ret = mylock_init();
    if(ret == -1)
    {
        printf("mylock_init error\n");
        return NULL;
    }
    
    server_listen_fd = socket(AF_INET,SOCK_STREAM,0);
    if(server_listen_fd == -1)
    {
        printf("socket error\n");
        return NULL;
    }
    
    ret = setsockopt(server_listen_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
    if(ret < 0)
    {
        printf("setsockopt error\n");
        return NULL;
    }
    /*

    //使用SO_LINGER，close后不进入TIME_WAIT状态
    struct linger linger;
    linger.l_onoff = 0;
    linger.l_linger = 0;
    setsockopt(server_listen_fd,
      SOL_SOCKET, SO_LINGER,
      (const char *) &linger,
      sizeof(linger));
    */
    //if (fcntl(server_listen_fd, F_SETFL, O_NDELAY) < 0) 
    {
    //  printf("Can't set socket to non-blocking");
    //    return -1;
    }
    
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    ret = bind(server_listen_fd,(struct sockaddr *)&server_addr,sizeof(server_addr));
    if(ret == -1)
    {
        printf("bind error\n");
        return NULL;
    }
    
    ret = listen(server_listen_fd,MAX_LISTEN_NUM);
    if(ret == -1)
    {
        printf("listen error\n");
        return NULL;
    }

    pThreadlist = thread_list_createList();
    for(i=0;i<MAX_PROCESS_NUM;i++)
    {
        dlog("init the %dth thread\n",i);
        pstThreadNode = (struct thread_node*)malloc(sizeof(struct thread_node));
        if(pstThreadNode== NULL)
        {
            printf("network_server_init:error , malloc failed\n");
            return NULL;
        }
        memset(pstThreadNode,0,sizeof(struct thread_node));
        
                
        pClientList = client_list_create();
        if(pClientList == NULL)
        {
            printf("client_list_create error\n");
            return NULL;
        }
        pClientList->thread_id = pstThreadNode->id;
        pstThreadNode->index = i;
        pstThreadNode->pclient_list = pClientList;
        pstThreadNode->pProcess_frame = pProcessFrame;
        
        
        thread_list_add(pThreadlist,pstThreadNode);
    }


    return pThreadlist;
};

int network_server_start(struct thread_list *pThreadList)
{
    int i = 0;
    int ret = 0;



    pthread_t id;
    struct thread_node *pThreadNodeTmp = pThreadList->head;
    while(pThreadNodeTmp!=NULL)
    {
        ret = pthread_create(&(pThreadNodeTmp->id),NULL,(void *) thread_main,(void *)pThreadNodeTmp);
        if(ret!=0)
        {
            printf ("Create pthread error!\n");
            return (-1);
        }
        
        pThreadNodeTmp->pclient_list->thread_id = pThreadNodeTmp->id;
        pThreadNodeTmp= pThreadNodeTmp->next;
    }   
    return 0;
}

int network_server_wait_finish(struct thread_list *pThreadList)
{
    struct thread_node *pThreadNodeTmp = pThreadList->head;
    while(pThreadNodeTmp!=NULL)
    {
        pthread_join(pThreadNodeTmp->id,NULL);
        pThreadNodeTmp = pThreadNodeTmp->next;
    }   

}
int network_server_kill_all_thread(struct thread_list *pThreadList)
{
    struct thread_node *pThreadNodeTmp = pThreadList->head;
    while(pThreadNodeTmp!=NULL)
    {
        pthread_join(pThreadNodeTmp->id,NULL);
        pThreadNodeTmp = pThreadNodeTmp->next;
    }   

}


int network_connect_only(char *ip_addr,unsigned short server_port)
{
    dlog("network_client_connect:ip is %s, port is %d\n",ip_addr,server_port);
    int client_fd = -1;
    int recode = -1;
    struct net_packet_head packet;

    memset(&packet,0,sizeof(packet));

    client_fd = socket(AF_INET,SOCK_STREAM,0);
    if(client_fd == -1)
    {
        printf("socket error\n");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr,0,sizeof(server_addr));

    server_addr.sin_port = htons(server_port);
    server_addr.sin_family = AF_INET;

    recode = inet_pton(AF_INET,ip_addr,&(server_addr.sin_addr.s_addr));
    if(recode == -1)
    {
        printf("inet_pton error\n");
        return -1;
    }
    recode = connect(client_fd,(struct sockaddr *)&server_addr, sizeof(server_addr));
    if(recode == -1)
    {
        printf("connect failed\n");
        dlog_error();
        return -1;
    }
    dlog("connected to server\n");
    return client_fd;
}


int network_client_connect(char *ip_addr,unsigned short server_port)
{
    dlog("network_client_connect:ip is %s, port is %d\n",ip_addr,server_port);
    int client_fd = -1;
    int recode = -1;
    struct net_packet_head packet;

    memset(&packet,0,sizeof(packet));

    client_fd = socket(AF_INET,SOCK_STREAM,0);
    if(client_fd == -1)
    {
        printf("socket error\n");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr,0,sizeof(server_addr));

    server_addr.sin_port = htons(server_port);
    server_addr.sin_family = AF_INET;

    recode = inet_pton(AF_INET,ip_addr,&(server_addr.sin_addr.s_addr));
    if(recode == -1)
    {
        printf("inet_pton error\n");
        return -1;
    }
    recode = connect(client_fd,(struct sockaddr *)&server_addr, sizeof(server_addr));
    if(recode == -1)
    {
        printf("connect failed\n");
        dlog_error();
        return -1;
    }
    dlog("after connect\n");
    packet.command_code = NET_COMMAND_CODE_CONNECT;
    packet.data_type = NET_PACKET_TYPE_NULL;
    packet.data_len = 0;
    recode = write(client_fd,&packet,sizeof(packet));
    if(recode < 0)
    {
        int errorNum = errno;
        dlog("network_client_connect:write error (%d):%s\n",errorNum,strerror(errorNum));
        return -1;
    }
    dlog("after write send %d byte\n",recode);
    fsync(client_fd);
    memset(&packet,0,sizeof(packet));
    recode = read(client_fd,&packet,sizeof(packet));
    if(recode < 0)
    {
        int errorNum = errno;
        dlog("network_client_connect:read error (%d):%s\n",errorNum,strerror(errorNum));
        
        close(client_fd);
        return -1;
    } else if (recode == 0)
	{
        int errorNum = errno;
        printf("network_client_connect:read error (%d):%s\n",errorNum,strerror(errorNum));
        
        close(client_fd);
		return -1;
		
	}
    dlog("after read read %d byte\n",recode);
    dlog("pack: command %d len %d type %d\n",packet.command_code,packet.data_len,packet.data_type);
    if(packet.command_code == NET_COMMAND_CODE_CONNECTED)
    {
        dlog("connected to server\n");
        printf("connected to server\n");
        return client_fd;
    }
    
    close(client_fd);
    return -1;
}

int network_client_disconnect(int client_fd)
{
    int recode = 0;
    struct net_packet_head packet;
    memset(&packet,0,sizeof(packet));

    packet.command_code = NET_COMMAND_CODE_DISCONNECT;
    packet.data_len = sizeof(packet);
    packet.data_type =NET_PACKET_TYPE_NULL;

    recode = write(client_fd,&packet,sizeof(packet));
    if(recode < 0)
    {
        int errorNum = errno;
        dlog("network_client_disconnect:write error (%d):%s\n",errorNum,strerror(errorNum));
        close(client_fd);
        return -1;
    }
    fsync(client_fd);
    memset(&packet,0,sizeof(packet));
    recode = select_time_out(client_fd,TIME_OUT);
    if(recode == 0)
    {
        recode = read(client_fd,&packet,sizeof(packet));
        if(recode < 0)
        {
            int errorNum = errno;
            dlog("network_client_disconnect:read error (%d):%s\n",errorNum,strerror(errorNum));
            
            close(client_fd);
            return -1;
        }
        if(packet.command_code == NET_COMMAND_CODE_DISCONNECTED)
        {
            dlog("disconnected to server\n");
            close(client_fd);
            return 0;
        }
    }
    close(client_fd);
    return -1;
};
int send_data(int socket_fd,unsigned char *data,int data_len)
{
    if(data ==NULL)
    {
        printf("send_data:null ptr input \n");
        return -1;
    }
    dlog("data len is %d\n",data_len);
    int send_len = write(socket_fd,data,data_len);
    dlog("send Data %d\n",send_len);
    return send_len;
};
int recive_data(int socket_fd,unsigned char *data,int data_len)
{
    if(data ==NULL)
    {
        printf("send_data:null ptr input \n");
        return -1;
    }
    struct net_packet_head head;
    memset(&head,0,sizeof(head));
    
    pthread_mutex_lock(&mutex);
    dlog("recive_data:lock\n");
    int len = read(socket_fd,&head,sizeof(head));
    
    pthread_mutex_unlock(&mutex);
    dlog("recive_data:unlock\n");
    if(len != sizeof(head))
    {
        printf("recive other type packet");
        return -1;
    }
    
    return len;
};

int recive_head_time_out(int socket_fd,struct net_packet_head *pHead,int seconds)
{
    int len = 0;
    int recode = 0;

    if(pHead ==NULL)
    {
        printf("send_data:null ptr input \n");
        return -1;
    }
    struct net_packet_head head;
    memset(&head,0,sizeof(head));
    recode = select_time_out(socket_fd,seconds);
    if(recode == 0)
    {
        pthread_mutex_lock(&mutex);
        dlog("recive_head:lock\n");
        len = read(socket_fd,&head,sizeof(head));
        pthread_mutex_unlock(&mutex);
        dlog("recive_head:unlock\n");
    }

    dlog("read head ,size is %d,data_len is %d\n",len,head.data_len);
    if(len != sizeof(head))
    {
        printf("recive_head:error! recive other type packet\n");
        return -1;
    }
    dlog("end of recive_head\n");
    memcpy(pHead,&head,sizeof(head));
    return len;
};

int recive_head(int socket_fd,struct net_packet_head *pHead)
{
    int len = 0;
    int recode = 0;

    if(pHead ==NULL)
    {
        printf("send_data:null ptr input \n");
        return -1;
    }
    struct net_packet_head head;
    memset(&head,0,sizeof(head));
    recode = select_time_out(socket_fd,TIME_OUT);
    if(recode == 0)
    {
        pthread_mutex_lock(&mutex);
        dlog("recive_head:lock\n");
        len = read(socket_fd,&head,sizeof(head));
        pthread_mutex_unlock(&mutex);
        dlog("recive_head:unlock\n");
    }

    dlog("read head ,size is %d,data_len is %d\n",len,head.data_len);
    if(len != sizeof(head))
    {
        printf("recive_head:error! recive other type packet\n");
        return -1;
    }
    dlog("end of recive_head\n");
    memcpy(pHead,&head,sizeof(head));
    return len;
};

int recive_no_use_buf(int socket_fd,int n)
{
    int i=0;
    char buf[10];
    
    pthread_mutex_lock(&mutex);
    dlog("recive_no_use_buf:lock\n");
    for(i=0;i<n;i++)
    {
        read(socket_fd,buf,1);
    };
    pthread_mutex_unlock(&mutex);
    dlog("recive_no_use_buf:unlock\n");

    return 0;
};
int recive_struct_time_out(int socket_fd,unsigned char *data,int data_len,int seconds)
{
    if(data ==NULL)
    {
        printf("send_data:null ptr input \n");
        return -1;
    }
    int recode = 0;
    struct net_packet_head head;
    char buf[BUFFER_SIZE];
    memset(&head,0,sizeof(head));
    int len = recive_head_time_out(socket_fd,&head,seconds);
    if(len == -1)
    {
        printf("recive_head:error\n");
        return -1;
    }
    
    if(head.data_type != NET_PACKET_TYPE_STRUCT)
    {
        printf("not recive struct data\n");
        return -1;
    }
    dlog("data len is %d\n",data_len);
    if(head.data_len != data_len)
    {
        printf("net packet is not match given data, throw the net packet\n");
        recive_no_use_buf(socket_fd,head.data_len);
        return -1;
    }
    dlog("read struct data\n");
    recode = select_time_out(socket_fd,seconds);
    if(recode == 0)
    {
        pthread_mutex_lock(&mutex);
        dlog("recive_struct:lock\n");
        len = read(socket_fd,data,data_len);
        pthread_mutex_unlock(&mutex);
        dlog("recive_struct:unlock\n");
    }
    if(len == -1)
    {
        printf("read failed\n");
        return -1;
    }
    
    dlog("recive Data %d\n",len);
    return len;
};


int recive_struct(int socket_fd,unsigned char *data,int data_len)
{
    if(data ==NULL)
    {
        printf("send_data:null ptr input \n");
        return -1;
    }
    int recode = 0;
    struct net_packet_head head;
    char buf[BUFFER_SIZE];
    memset(&head,0,sizeof(head));
    int len = recive_head(socket_fd,&head);
    if(len == -1)
    {
        printf("recive_head:error\n");
        return -1;
    }
    
    if(head.data_type != NET_PACKET_TYPE_STRUCT)
    {
        printf("not recive struct data\n");
        return -1;
    }
    dlog("data len is %d\n",data_len);
    if(head.data_len != data_len)
    {
        printf("net packet is not match given data, throw the net packet\n");
        recive_no_use_buf(socket_fd,head.data_len);
        return -1;
    }
    dlog("read struct data\n");
    recode = select_time_out(socket_fd,TIME_OUT);
    if(recode == 0)
    {
        pthread_mutex_lock(&mutex);
        dlog("recive_struct:lock\n");
        len = read(socket_fd,data,data_len);
        pthread_mutex_unlock(&mutex);
        dlog("recive_struct:unlock\n");
    }
    if(len == -1)
    {
        printf("read error\n");
        return -1;
    }
    
    dlog("recive Data %d\n",len);
    return len;
};



int send_packet(int socket_fd,struct net_packet_head *pPacketHeader,char *data,int data_len)
{
    dlog("send_packet fd is %d\n",socket_fd);
    int buf_len = 0;
    int send_len = 0;
    char *buf=NULL;

    
    buf_len = sizeof(struct net_packet_head) + data_len;

    buf = (char *)malloc(buf_len);
    if(buf <= 0)
    {
        printf("send_packet:malloc error\n");
        return -1;
    }
    memset(buf,0,buf_len);

    memcpy(buf,pPacketHeader,sizeof(struct net_packet_head));
    memcpy((char *)buf + sizeof(struct net_packet_head),data,data_len);

    pthread_mutex_lock(&mutex);
    dlog("send_packet:lock\n");
    send_len = write(socket_fd,buf,buf_len);
    if(send_len < 0)
    {
        pthread_mutex_unlock(&mutex);
        printf("send_packet:write error\n");
        return -1;
    }
    pthread_mutex_unlock(&mutex);
    dlog("send_packet:pthread_mutex_unlock\n");
    dlog("send Data %d\n",send_len);
    free(buf);
    return send_len;
};


int send_command(int server_fd,char *str,int n)
{
    struct net_packet_head client_packet;
    char data[128];
    double h2 = 123321.123;
    memset(&client_packet,0,sizeof(client_packet));
    memset(&data,0,sizeof(data));


    memcpy(data,&h2,sizeof(h2));

    client_packet.data_type = 'c';
    client_packet.command_code = 0x81;
    client_packet.data_len = sizeof(h2);

    send_packet(server_fd,&client_packet,data,sizeof(h2));

};



int send_conclude(int server_fd)
{
    struct net_packet_head client_packet;
    char data[128];
    double h2 = 123321.123;
    memset(&client_packet,0,sizeof(client_packet));
    memset(&data,0,sizeof(data));


    memcpy(data,&h2,sizeof(h2));

    client_packet.data_type = 'q';
    client_packet.command_code = 0x82;
    client_packet.data_len = 0;

    send_packet(server_fd,&client_packet,NULL,0);

};


int send_string(int server_fd,char *str,int n)
{
    struct net_packet_head client_packet;
    char data[128];
    memset(&client_packet,0,sizeof(client_packet));
    memset(&data,0,sizeof(data));


    strncpy(data,str,127);

    client_packet.command_code = NET_COMMAND_CODE_DATA;
    client_packet.data_type = NET_PACKET_TYPE_STRING;
    client_packet.data_len = strlen(data)+1;

    send_packet(server_fd,&client_packet,data,strlen(data)+1);
};
int send_struct(int server_fd,unsigned char *data,int n)
{
    dlog("sent_struct\n");
    struct net_packet_head client_packet;
    memset(&client_packet,0,sizeof(client_packet));

    client_packet.command_code = NET_COMMAND_CODE_DATA;
    client_packet.data_type = NET_PACKET_TYPE_STRUCT;
    client_packet.data_len = n;

    send_packet(server_fd,&client_packet,data,n);

    return 0;
};

void setnonblocking(int sock)
{
    int opts;
    opts=fcntl(sock,F_GETFL);
    if(opts<0)
    {
        printf("fcntl(sock,GETFL)");
        return;
    }
    opts = opts|O_NONBLOCK;
    if(fcntl(sock,F_SETFL,opts)<0)
    {
        printf("fcntl(sock,SETFL,opts)");
        return;
    }
}

int readtask_showtask()
{
    return 0;
    pthread_mutex_lock(&mutex);
    dlog("readtask_showtask:lock\n");
    struct thread_readtask *task = readtask_head;
    int i=0;
    dlog("show task\n");
    while(task != NULL)
    {
        dlog("%d:fd is %d\n",i++,task->fd);
        task = task->next;
    }
    pthread_mutex_unlock(&mutex);
    dlog("readtask_showtask:unlock\n");

};
int writetask_showtask()
{
    return 0;
    pthread_mutex_lock(&mutex);
    dlog("writetask_showtask:lock\n");
    struct thread_writetask *task = writetask_head;
    int i=0;
    dlog("show task\n");
    while(task != NULL)
    {
        dlog("%d:fd is %d\n",i++,task->fd);
        task = task->next;
    }
    pthread_mutex_unlock(&mutex);
    dlog("writetask_showtask:unlock\n");

};


int readtask_get_task(struct thread_readtask *task)
{
    if(task == NULL)
    {
        printf("readtask_get_task:null ptr input\n");
        return -1;
    };
    pthread_mutex_lock(&mutex);
    dlog("readtask_get_task:lock\n");
    while(readtask_head == NULL)
    {
        dlog("readtask_get_task:unlock\n");
        pthread_cond_wait(&cond,&mutex);
        dlog("readtask_get_task:lock\n");
    }
    memcpy(task,readtask_head,sizeof(struct thread_readtask));
    free(readtask_head);
    
    readtask_head = task->next;
    
    if(task->next == NULL)
    {
        readtask_head = NULL;
        readtask_tail = NULL;
    }
    

    pthread_mutex_unlock(&mutex);
    dlog("readtask_get_task:unlock\n");

    return 0;
}

int writetask_get_task(struct thread_writetask *task)
{
    if(task == NULL)
    {
        printf("writetask_get_task:null ptr input\n");
        return -1;
    };
    pthread_mutex_lock(&mutex);
    dlog("writetask_get_task:lock\n");
    while(writetask_head == NULL)
    {
        dlog("writetask_get_task:unlock\n");
        pthread_cond_wait(&cond,&mutex);
        dlog("writetask_get_task:lock\n");
    }
    memcpy(task,writetask_head,sizeof(struct thread_writetask));
    free(writetask_head);
    
    writetask_head = task->next;
    
    if(task->next == NULL)
    {
        writetask_head = NULL;
        writetask_tail = NULL;
    }
    

    pthread_mutex_unlock(&mutex);
    dlog("writetask_get_task:unlock\n");

    return 0;
}



int readtask_add_task(int fd)
{
    dlog("readtask_add_task:fd is %d\n",fd);
    if(fd < 0)
    {
        printf("readtask_add_task:fd is invalid\n");
        return 0;
    }
    
    struct thread_readtask* new_task = (struct thread_readtask*)malloc(sizeof(struct thread_readtask));
    memset(new_task,0,sizeof(struct thread_readtask));
    new_task->fd = fd;
    
    pthread_mutex_lock(&mutex);
    dlog("readtask_add_task:lock\n");
    if(readtask_head == NULL)
    {
        readtask_head = new_task;
        readtask_tail = new_task;
    }
    else
    {
        readtask_tail->next = new_task;
        readtask_tail = new_task;
    }

    pthread_cond_signal(&cond);
    dlog("readtask_add_task:pthread_cond_signal\n");
    pthread_mutex_unlock(&mutex);
    dlog("readtask_add_task:unlock\n");

    return 0;
}


int writetask_delete_fd(int fd)
{
    writetask_showtask();
    pthread_mutex_lock(&mutex);
    dlog("writetask_delete_fd:lock\n");

    if(writetask_head == NULL || fd < 0)
    {
    
        pthread_mutex_unlock(&mutex);
        dlog("writetask_head is null\n");
        dlog("writetask_delete_fd:unlock\n");
        return -1;
    }
    int isFound = 0;

    struct thread_writetask *tmp = writetask_head;
    struct thread_writetask *tmpNext = tmp->next;

    //in the middle
    dlog("delete fd in middle\n");
    while(tmpNext != NULL)
    {
        if(tmpNext->fd == fd)
        {
            tmp->next = tmpNext->next;
            //until the end
            if(writetask_tail == tmpNext);
            {
                dlog("found in the tail\n");
                writetask_tail = tmp;
                writetask_tail->next = NULL;
                isFound = 1;
            }
            dlog("found in the middle\n");
            free(tmpNext);
        }
        tmp=tmp->next;
        if(tmp==NULL)
        {
            break;
        }
        tmpNext = tmp->next;
    }

    //in the head
    dlog("delete fd in middle\n");
    if(writetask_head ->fd == fd)
    {
        tmp = writetask_head;
        writetask_head = tmp->next;  
        dlog("found in the head\n");
        
        isFound = 1;
        free(tmp);
    }

    pthread_cond_signal(&cond);

    pthread_mutex_unlock(&mutex);
    dlog("writetask_delete_fd:unlock\n");


    if(isFound == 0)
    {
        dlog("%d not find in writetask\n",fd);
        return -1;
    }

    writetask_showtask();
    return 0;
};
int readtask_delete_fd(int fd)
{

    readtask_showtask();
    pthread_mutex_lock(&mutex);
    dlog("readtask_delete_fd:lock\n");

    if(readtask_head == NULL || fd < 0)
    {
    
        pthread_mutex_unlock(&mutex);
        dlog("readtask_head is null\n");
        dlog("readtask_delete_fd:unlock\n");
        return -1;
    }
    int isFound = 0;

    struct thread_readtask *tmp = readtask_head;
    struct thread_readtask *tmpNext = tmp->next;

    //in the middle
    dlog("delete fd in middle\n");
    while(tmpNext != NULL)
    {
        if(tmpNext->fd == fd)
        {
            tmp->next = tmpNext->next;
            //until the end
            if(readtask_tail == tmpNext);
            {
                dlog("found in the tail\n");
                readtask_tail = tmp;
                readtask_tail->next = NULL;
                isFound = 1;
            }
            dlog("found in the middle\n");
            free(tmpNext);
        }
        tmp=tmp->next;
        if(tmp==NULL)
        {
            break;
        }
        tmpNext = tmp->next;
    }

    //in the head
    dlog("delete fd in middle\n");
    if(readtask_head ->fd == fd)
    {
        tmp = readtask_head;
        readtask_head = tmp->next;  
        dlog("found in the head\n");
        
        isFound = 1;
        free(tmp);
    }

    pthread_cond_signal(&cond);

    pthread_mutex_unlock(&mutex);
    dlog("readtask_delete_fd:unlock\n");


    if(isFound == 0)
    {
        dlog("%d not find in readtask\n",fd);
        return -1;
    }

    readtask_showtask();
    return 0;
};


void *network_epoll_thread_write_task(void *args)
{
    int fd = -1;
    int ret = 0;
    int n = 0;
    char ip_addr[IPV4_LEN];
    int port = 0;
    struct thread_writetask task;
    struct net_packet_head head;
    char *buf=NULL;
    while(1)
    {
        buf = NULL;
        memset(&task,0,sizeof(task));
        ret = writetask_get_task(&task);
        if(ret == -1)
        {
            continue;
        }
        dlog("writetask %d\n",num++);
        dlog("write head,fd is %d\n\n",task.fd);
        while(1)
        {
        
            memset(&head,0,sizeof(head));
            memset(ip_addr,0,sizeof(ip_addr));
            port = 0;
            pthread_mutex_lock(&mutex);
            dlog("writetask:lock\n");
            n = write(task.fd,&head,sizeof(head));
            pthread_mutex_unlock(&mutex);

            get_ip_and_port_from_client_list(task.fd,ip_addr,&port);
            dlog("writetask:unlock\n");
            dlog("writetask:%s:%d\n",ip_addr,port);
            dlog("write head, fd is %d,size is %d\n",task.fd,n);
            dlog("writetask: packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
            if(n < 0)
            {
                if (errno == ECONNRESET)
                {
                    ev.data.fd = task.fd;
                    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                    writetask_delete_fd(task.fd);
                    network_server_colse_fd(task.fd);
                    break;
                }
                else
                {
                    int errNum = errno;
                    printf("writetask:write error (%d):%s\n",errNum,strerror(errNum));
                    break;
                }
            }
            else if(n == 0)
            {
                                    
                dlog("socket CloseFd:%d\n",task.fd);
                
                ev.data.fd = task.fd;
                epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                ret = writetask_delete_fd(task.fd);
                network_server_colse_fd(task.fd);
                break;
            }
            
            if(n != sizeof(head))
            {
                printf("size invalied recive other packet\n");
                continue;
            }
            
            if(NET_PACKET_TYPE_MY_TYPE_START > head.data_type || NET_PACKET_TYPE_MY_TYPE_END < head.data_type)
            {
                printf("type invalied recive other headType\n");
                continue;

            }
            if(head.command_code== NET_COMMAND_CODE_CONNECT)
            {
                dlog("writetask:connect packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
                memset(&head,0,sizeof(head));
                head.command_code= NET_COMMAND_CODE_CONNECTED;
                head.data_len = 0;
                head.data_type = NET_PACKET_TYPE_NULL;
                dlog("writetask:write packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
                n = write(task.fd,&head,sizeof(head));
                if(n < 0)
                {
                    int errNum = errno;
                    printf("writetask:write connect packet error (%d):%s\n",errNum,strerror(errNum));
                    
                    ev.data.fd = task.fd;
                    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                    writetask_delete_fd(task.fd);
                    network_server_colse_fd(task.fd);
                    break;
                }; 
                break;
            };
            if(head.command_code == NET_COMMAND_CODE_DISCONNECT)
            {
                dlog("writetask:disconnect packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
                memset(&head,0,sizeof(head));
                head.command_code = NET_COMMAND_CODE_DISCONNECTED;
                head.data_len = 0;
                head.data_type = NET_PACKET_TYPE_NULL;
                dlog("writetask:write packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
                n = write(task.fd,&head,sizeof(head));
                if(n < 0)
                {
                    int errNum = errno;
                    printf("writetask:write disconnect packet error (%d):%s\n",errNum,strerror(errNum));
                }; 
                ev.data.fd = task.fd;
                epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                writetask_delete_fd(task.fd);
                network_server_colse_fd(task.fd);
                break;
            };
            
            buf = (char *)malloc(head.data_len);
            memset(buf,0,head.data_len);
            
            
            pthread_mutex_lock(&mutex);
            dlog("writetask:lock\n");
            n = write(task.fd,buf,head.data_len);
            
            pthread_mutex_unlock(&mutex);
            dlog("writetask:unlock\n");
            dlog("write buf,fd is %d,data_len is %d, size is %d\n",task.fd,head.data_len,n);
            if(n < 0)
            {
                if (errno == ECONNRESET)
                {
                    ev.data.fd = task.fd;
                    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                    writetask_delete_fd(task.fd);
                    network_server_colse_fd(task.fd);
                }
                else
                {
                    dlog("writetask:write error\n");
                }
                free(buf);
                continue;
            }
            if(n == 0)
            {          
                dlog("socket network_server_colse_fd:%d\n",task.fd);
                
                ev.data.fd = task.fd;
                epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                writetask_delete_fd(task.fd);
                network_server_colse_fd(task.fd);
                continue;
            }
            free(buf);
            }
    }
}


void *network_epoll_thread_read_task(void *args)
{
    int fd = -1;
    int ret = 0;
    int n = 0;
    char ip_addr[IPV4_LEN];
    int port = 0;
    struct thread_readtask task;
    struct net_packet_head head;
    char *buf=NULL;
    while(1)
    {
        buf = NULL;
        memset(&task,0,sizeof(task));
        ret = readtask_get_task(&task);
        if(ret == -1)
        {
            continue;
        }
        dlog("readtask %d\n",num++);
        dlog("read head,fd is %d\n\n",task.fd);
        while(1)
        {
        
            memset(&head,0,sizeof(head));
            memset(ip_addr,0,sizeof(ip_addr));
            port = 0;
            pthread_mutex_lock(&mutex);
            dlog("readtask:lock\n");
            n = read(task.fd,&head,sizeof(head));
            pthread_mutex_unlock(&mutex);

            get_ip_and_port_from_client_list(task.fd,ip_addr,&port);
            dlog("readtask:unlock\n");
            dlog("readtask:%s:%d\n",ip_addr,port);
            dlog("read head, fd is %d,size is %d\n",task.fd,n);
            dlog("readtask: packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
            if(n < 0)
            {
                if (errno == ECONNRESET)
                {
                    ev.data.fd = task.fd;
                    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                    readtask_delete_fd(task.fd);
                    network_server_colse_fd(task.fd);
                    break;
                }
                else
                {
                    int errNum = errno;
                    printf("readtask:read error (%d):%s\n",errNum,strerror(errNum));
                    break;
                }
            }
            else if(n == 0)
            {
                                    
                dlog("socket CloseFd:%d\n",task.fd);
                
                ev.data.fd = task.fd;
                epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                ret = readtask_delete_fd(task.fd);
                network_server_colse_fd(task.fd);
                break;
            }
            
            if(n != sizeof(head))
            {
                printf("size invalied recive other packet\n");
                continue;
            }
            
            if(NET_PACKET_TYPE_MY_TYPE_START > head.data_type || NET_PACKET_TYPE_MY_TYPE_END < head.data_type)
            {
                printf("type invalied recive other headType\n");
                continue;

            }
            if(head.command_code== NET_COMMAND_CODE_CONNECT)
            {
                dlog("readtask:connect packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
                memset(&head,0,sizeof(head));
                head.command_code= NET_COMMAND_CODE_CONNECTED;
                head.data_len = 0;
                head.data_type = NET_PACKET_TYPE_NULL;
                dlog("readtask:write packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
                n = write(task.fd,&head,sizeof(head));
                if(n < 0)
                {
                    int errNum = errno;
                    printf("readtask:write connect packet error (%d):%s\n",errNum,strerror(errNum));
                    
                    ev.data.fd = task.fd;
                    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                    readtask_delete_fd(task.fd);
                    network_server_colse_fd(task.fd);
                    break;
                }; 
                break;
            };
            if(head.command_code == NET_COMMAND_CODE_DISCONNECT)
            {
                dlog("readtask:disconnect packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
                memset(&head,0,sizeof(head));
                head.command_code = NET_COMMAND_CODE_DISCONNECTED;
                head.data_len = 0;
                head.data_type = NET_PACKET_TYPE_NULL;
                dlog("readtask:write packet:command %d len %d type %d\n",head.command_code,head.data_len,head.data_type);
                n = write(task.fd,&head,sizeof(head));
                if(n < 0)
                {
                    int errNum = errno;
                    printf("readtask:write disconnect packet error (%d):%s\n",errNum,strerror(errNum));
                }; 
                ev.data.fd = task.fd;
                epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                readtask_delete_fd(task.fd);
                network_server_colse_fd(task.fd);
                break;
            };
            
            buf = (char *)malloc(head.data_len);
            memset(buf,0,head.data_len);
            
            
            pthread_mutex_lock(&mutex);
            dlog("readtask:lock\n");
            n = read(task.fd,buf,head.data_len);
            
            pthread_mutex_unlock(&mutex);
            dlog("readtask:unlock\n");
            dlog("read buf,fd is %d,data_len is %d, size is %d\n",task.fd,head.data_len,n);
            if(n < 0)
            {
                if (errno == ECONNRESET)
                {
                    ev.data.fd = task.fd;
                    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                    readtask_delete_fd(task.fd);
                    network_server_colse_fd(task.fd);
                }
                else
                {
                    dlog("readtask:read error\n");
                }
                free(buf);
                continue;
            }
            if(n == 0)
            {          
                dlog("socket network_server_colse_fd:%d\n",task.fd);
                
                ev.data.fd = task.fd;
                epoll_ctl(epoll_fd,EPOLL_CTL_DEL,task.fd,&ev);
                readtask_delete_fd(task.fd);
                network_server_colse_fd(task.fd);
                continue;
            }

            if(callback_readtask != NULL)
            {
                ret = (*callback_readtask)(task.fd,buf,n);
                if(ret == -1)
                {
                    dlog("readtask:callback_readtask error\n");
                }
            }
            free(buf);
            }
    }
}
int writetask_add_task(int fd,char *buf, int n)
{
    if(fd<0)
    {
        printf("writetask_add_task:fd error\n");
        return -1;
    }
    struct thread_writetask *new_task = (struct thread_writetask *)malloc(sizeof(struct thread_writetask));
    char *data=(char *)malloc(n);
    memset(data,0,n);
    
    memcpy(data,buf,n);
    new_task->fd = fd;
    new_task->data = data;
    new_task->data_len = n;

    if(writetask_head == NULL)
    {
        writetask_head = new_task;
        writetask_tail = new_task;
    }
    else
    {
        writetask_tail->next = new_task;
        writetask_tail = new_task;
    }
/*
    pthread_cond_broadcast(&cond);
    
    dlog("writetask_get_task:unlock\n");
    pthread_mutex_unlock(&mutex);
    dlog("writetask_add_task:end\n");
*/

    dlog("epoll_mod fd is %d\n",fd);
    
    ///ev.data.fd = fd;
    
    //dlog("ev.data.fd is %d,fd is %d\n",ev.data.fd,fd);
    ev.data.ptr = new_task;
    
   // dlog("ev.data.fd is %d,fd is %d\n",ev.data.fd,fd);
    ev.events = EPOLLOUT | EPOLLET;


   // dlog("ev.data.ptr is %p\n",new_task);
    //dlog("ev.data.fd is %d,fd is %d\n",ev.data.fd,fd);
    epoll_ctl(epoll_fd,EPOLL_CTL_MOD,fd,&ev);


    return 0;
};

int network_epoll_thread_list_start(struct thread_list *pThreadList)
{
    int i = 0;
    int ret = 0;



    pthread_t id;
    struct thread_node *pThreadNodeTmp = pThreadList->head;
    while(pThreadNodeTmp!=NULL)
    {
        ret = pthread_create(&(pThreadNodeTmp->id),NULL,(void *) network_epoll_thread_read_task,NULL);
        if(ret!=0)
        {
            printf ("Create pthread error!\n");
            dlog_error();
            return (-1);
        }
        
        pThreadNodeTmp->pclient_list->thread_id = pThreadNodeTmp->id;
        pThreadNodeTmp->mode = THREAD_MODE_READ;
        pThreadNodeTmp= pThreadNodeTmp->next;
    }   
    return 0;
}

int network_epoll_init(struct thread_list *pthread_list,TYPE_FUN_READTASK callback_task)
{
    if(pthread_list == NULL)
    {
        printf("network_epoll_init:NULL ptr input\n");
        return -1;
    };

    epoll_fd = epoll_create(4096);

    pthread_mutex_init(&mutex,NULL);
    pthread_cond_init(&cond,NULL);

    setnonblocking(server_listen_fd);
    ev.data.fd = server_listen_fd;
    ev.events = EPOLLIN|EPOLLET;
    epoll_ctl(epoll_fd,EPOLL_CTL_ADD,server_listen_fd,&ev);

    callback_readtask = callback_task;

    struct thread_node *tmp = NULL;
   
    tmp = pthread_list->head;
    while(tmp->next != NULL)
    {
        //tmp->pProcess_frame = callback_task;
        tmp->pProcess_frame = NULL;
        tmp=tmp->next;
    };
        
    return 0;
}
int network_epoll_start(struct thread_list *pThreadList)
{
    dlog("network_epoll_start\n");
    int i=0;
    int nfds = 0;
    int connect_fd = 0;
    
    socklen_t client_addr_size = sizeof(struct sockaddr_in);
    struct thread_readtask *readtask=NULL;
    struct thread_writetask *writetask=NULL;
    struct sockaddr_in connect_addr;
    
    clientlist =  client_list_create();


    network_epoll_thread_list_start(pThreadList);
    
    while(1)
    {
        dlog("epoll_wait start\n");
        dlog("connect count is %d\n",connect_count);
        dlog("connecting count is %d\n",connecting_count);
        dlog("max_fd is %d\n",max_fd);
        nfds = epoll_wait(epoll_fd,events,20,NET_TIMEOUT * 1000);
        dlog("nfds is %d\n",nfds);
        if(nfds == 0)
        {
            printf("epoll_wait timeout\n");
            if(connecting_count < MAX_CONNECT_NUM)
            {
                ev.data.fd = server_listen_fd;
                ev.events = EPOLLIN|EPOLLET;
                epoll_ctl(epoll_fd,EPOLL_CTL_MOD,server_listen_fd,&ev);
            }

            client_list_time_out_check(clientlist);
            continue;
        }
		else if(nfds < 0)
		{
			if(errno == EINTR)
			  continue;
			else
			  perror("EPOLL_WAIT");
		}
        else 
        {
            for(i=0;i<nfds;i++)
            {
                //accept connecting
                if(events[i].data.fd == server_listen_fd)
                {
                    while(connect_fd!=-1)
                    {
                        memset(&connect_addr,0,sizeof(connect_addr));   
                        connect_fd = accept(server_listen_fd,(struct sockaddr*)&connect_addr,&client_addr_size);
                        if(connect_fd == -1)
                        {
                        
                            int errNum = errno;
                            printf("accept error,errorno is %d,strerroris %s\n",errNum,strerror(errNum));
                            if (errno != EAGAIN && errno != ECONNABORTED  
                                && errno != EPROTO && errno != EINTR)  
                            {
                                connect_fd = 0;
                                break;
                            }
                            
                            dlog("accept handle finish\n");
                            connect_fd = 0;
                            break;
                        }
                        else
                        { 
                            setnonblocking(connect_fd);
                            
                            dlog("connect form %s:%d\n",inet_ntoa(connect_addr.sin_addr),ntohs(connect_addr.sin_port));
                            memset(&ev,0,sizeof(ev));
                            ev.data.fd = connect_fd;
                            ev.events = EPOLLIN | EPOLLET;
                            epoll_ctl(epoll_fd,EPOLL_CTL_ADD,connect_fd,&ev);

                            if(connect_fd > max_fd)
                            {
                                max_fd = connect_fd;
                            }
                            connect_count ++;
                            connecting_count ++;

                            
                            struct client_node stClienNode;
                            memset(&stClienNode,0,sizeof(stClienNode));
                            stClienNode.fd = connect_fd;
                            stClienNode.stat = 1;
                            strncpy(stClienNode.ip_addr,inet_ntoa(connect_addr.sin_addr),IPV4_LEN);
                            stClienNode.port = ntohs(connect_addr.sin_port);
                            memcpy(&(stClienNode.sockaddr),&connect_addr,sizeof(struct sockaddr_in));
                            client_list_add( clientlist,&stClienNode);
                        }

                    }
                    
                }
                else if(events[i].events & EPOLLERR)
                {
                //connect error
                    dlog("epoll connect error:fd is %d\n",events[i].data.fd);
                    ev.data.fd = events[i].data.fd;
                    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,events[i].data.fd,&ev);
                    network_server_colse_fd(events[i].data.fd);
                    readtask_delete_fd(events[i].data.fd);
                    continue;
                }
                else if(events[i].events & EPOLLHUP)
                {
                //connect relase
                    dlog("EPOLLHUP:socket network_server_colse_fd:%d\n",events[i].data.fd);
                    ev.data.fd = events[i].data.fd;
                    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,events[i].data.fd,&ev);
                    network_server_colse_fd(ev.data.fd);
                    readtask_delete_fd(events[i].data.fd);
                    continue;
                }
                else if(events[i].events & EPOLLIN)
                {
                //data in 
                
                    client_list_rest_time_out(clientlist,events[i].data.fd);
                    
                    dlog("reading %d\n",num++);
                    if(events[i].data.fd<0)
                    {
                        printf("events fd error\n");
                        continue;
                    }
                    dlog("add task\n");
                    readtask_add_task(events[i].data.fd);
                }
                else if(events[i].events & EPOLLOUT)
                {
                //data out
                    dlog("wrinting %d\n",num++);
                    struct thread_writetask *task = events[i].data.ptr;
                    dlog("writeing task is %p,fd is %d\n",task,task->fd);
                    if(task->fd<0)
                    {
                        printf("events fd error\n");
                        continue;
                    }
                    send_struct(task->fd,task->data,task->data_len);
                    
                    ev.data.fd = task->fd;
                    ev.events = EPOLLIN | EPOLLET;
                    epoll_ctl(epoll_fd,EPOLL_CTL_MOD,task->fd,&ev);
                    free(task->data);
                    free(task);
                    dlog("end writing\n");
                }
            }
        }
    }
    

    return 0;
}


/*
#define MAXLINE 10
#define OPEN_MAX 100
#define LISTENQ 20
#define SERV_PORT 5555
#define INFTIM 1000

int network_epoll()
{
    int i, maxi, listenfd, connfd, sockfd, epfd, nfds;
       ssize_t n;
       char line[MAXLINE];
       socklen_t clilen;
       //声明epoll_event结构体的变量,ev用于注册事件,数组用于回传要处理的事件
       struct epoll_event ev, events[20];
       //生成用于处理accept的epoll专用的文件描述符
       epfd = epoll_create(256);
    
       struct sockaddr_in clientaddr;
       struct sockaddr_in serveraddr;
       listenfd = socket(AF_INET, SOCK_STREAM, 0);
       //把socket设置为非阻塞方式
       setnonblocking(listenfd);
       //设置与要处理的事件相关的文件描述符
       ev.data.fd = listenfd;
       //设置要处理的事件类型
       ev.events = EPOLLIN | EPOLLET;
       //注册epoll事件
       epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);
    
       bzero(&serveraddr, sizeof(serveraddr));
       serveraddr.sin_family = AF_INET;
    
       char *local_addr = "200.200.200.204";
       inet_aton(local_addr, &(serveraddr.sin_addr)); //htons(SERV_PORT);
       serveraddr.sin_port = htons(SERV_PORT);
       bind(listenfd, (sockaddr *)&serveraddr, sizeof(serveraddr));
       listen(listenfd, LISTENQ);
    
       maxi = 0;
       for ( ; ; )
       {
           //等待epoll事件的发生
           nfds = epoll_wait(epfd, events, 20, 500);
           //处理所发生的所有事件
           for(i = 0; i < nfds; ++i)
           {
               if(events[i].data.fd == listenfd)
               {
    
                   connfd = accept(listenfd, (sockaddr *)&clientaddr, &clilen);
                   if(connfd < 0)
                   {
                       printf("connfd<0");
                       exit(1);
                   }
                   setnonblocking(connfd);
    
                   char *str = inet_ntoa(clientaddr.sin_addr);
                   std::cout << "connect from " < _u115 ? tr << std::endl;
                   //设置用于读操作的文件描述符
                   ev.data.fd = connfd;
                   //设置用于注测的读操作事件
                   ev.events = EPOLLIN | EPOLLET;
                   //注册ev
                   epoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
               }
               else if(events[i].events & EPOLLIN)
               {
                   if ( (sockfd = events[i].data.fd) < 0) continue;
                   if ( (n = read(sockfd, line, MAXLINE)) < 0)
                   {
                       if (errno == ECONNRESET)
                       {
    
                           close(sockfd);
                           events[i].data.fd = -1;
                       }
                       else
                           std::cout << "readline error" << std::endl;
                   }
                   else if (n == 0)
                   {
                       close(sockfd);
                       events[i].data.fd = -1;
                   }
                   //设置用于写操作的文件描述符
                   ev.data.fd = sockfd;
                   //设置用于注测的写操作事件
                   ev.events = EPOLLOUT | EPOLLET;
                   //修改sockfd上要处理的事件为EPOLLOUT
                   epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
               }
               else if(events[i].events & EPOLLOUT)
               {
                   sockfd = events[i].data.fd;
                   write(sockfd, line, n);
                   //设置用于读操作的文件描述符
                   ev.data.fd = sockfd;
                   //设置用于注测的读操作事件
                   ev.events = EPOLLIN | EPOLLET;
                   //修改sockfd上要处理的事件为EPOLIN
                   epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
               }
    
           }
    
       }

    return 0;
}

int network_epoll1()
{
        int i, maxi, listenfd, connfd, sockfd,epfd,nfds, portnumber;
        char line[MAXLINE];
        socklen_t clilen;
    
        portnumber = 5000;
    
        //声明epoll_event结构体的变量,ev用于注册事件,数组用于回传要处理的事件
    
        struct epoll_event ev,events[20];
        //生成用于处理accept的epoll专用的文件描述符
    
        epfd=epoll_create(256);
        struct sockaddr_in clientaddr;
        struct sockaddr_in serveraddr;
        listenfd = socket(AF_INET, SOCK_STREAM, 0);
    
        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
        serveraddr.sin_port=htons(portnumber);
    
        // bind and listen
        bind(listenfd,(sockaddr *)&serveraddr, sizeof(serveraddr));
        listen(listenfd, LISTENQ);
    
        //设置与要处理的事件相关的文件描述符
        ev.data.fd=listenfd;
        //设置要处理的事件类型
        ev.events=EPOLLIN|EPOLLET;
        //ev.events=EPOLLIN;
    
        //注册epoll事件
        epoll_ctl(epfd,EPOLL_CTL_ADD,listenfd,&ev);
    
        maxi = 0;
    
        int bOut = 0;
        for ( ; ; )
        {
            if (bOut == 1)
                break;
            //等待epoll事件的发生
    
            nfds=epoll_wait(epfd,events,20,-1);
            //处理所发生的所有事件
            cout << "\nepoll_wait returns\n";
    
            for(i=0;i<nfds;++i)
            {
                if(events[i].data.fd==listenfd)//如果新监测到一个SOCKET用户连接到了绑定的SOCKET端口，建立新的连接。
                {
                    connfd = accept(listenfd,(sockaddr *)&clientaddr, &clilen);
                    if(connfd<0){
                        printf("connfd<0");
                        return (1);
                    }
                    
    
                    char *str = inet_ntoa(clientaddr.sin_addr);
                    cout << "accapt a connection from " << str << endl;
                    //设置用于读操作的文件描述符
    
                    setnonblocking(connfd);
                    ev.data.fd=connfd;
                    //设置用于注测的读操作事件
    
                    ev.events=EPOLLIN | EPOLLET;
                    //ev.events=EPOLLIN;
    
                    //注册ev
                    epoll_ctl(epfd,EPOLL_CTL_ADD,connfd,&ev);
                }
                else if(events[i].events & EPOLLIN)//如果是已经连接的用户，并且收到数据，那么进行读入。
                {
                    cout << "EPOLLIN" << endl;
                    if ( (sockfd = events[i].data.fd) < 0)
                        continue;
    
                    char * head = line;
                    int recvNum = 0;
                    int count = 0;
                    bool bReadOk = false;
                    while(1)
                    {
                        // 确保sockfd是nonblocking的
                        recvNum = recv(sockfd, head + count, MAXLINE, 0);
                        if(recvNum < 0)
                        {
                            if(errno == EAGAIN)
                            {
                                // 由于是非阻塞的模式,所以当errno为EAGAIN时,表示当前缓冲区已无数据可读
                                // 在这里就当作是该次事件已处理处.
                                bReadOk = true;
                                break;
                            }
                            else if (errno == ECONNRESET)
                            {
                                    // 对方发送了RST
                                    CloseAndDisable(sockfd, events[i]);
                                    cout << "counterpart send out RST\n";
                                    break;
                             }
                            else if (errno == EINTR)
                            {
                                // 被信号中断
                                continue;
                            }
                            else
                            {
                                //其他不可弥补的错误
                                CloseAndDisable(sockfd, events[i]);
                                cout << "unrecovable error\n";
                                break;
                            }
                       }
                       else if( recvNum == 0)
                       {
                            // 这里表示对端的socket已正常关闭.发送过FIN了。
                            CloseAndDisable(sockfd, events[i]);
                            cout << "counterpart has shut off\n";
                            break;
                       }
    
                       // recvNum > 0
                        count += recvNum;
                       if ( recvNum == MAXLINE)
                       {
                           continue;   // 需要再次读取
                       }
                       else // 0 < recvNum < MAXLINE
                       {
                           // 安全读完
                           bReadOk = true;
                           break; // 退出while(1),表示已经全部读完数据
                       }
                    }
    
                    if (bReadOk == true)
                    {
                        // 安全读完了数据
                        line[count] = '\0';
    
                        cout << "we have read from the client : " << line;
                        //设置用于写操作的文件描述符
    
                        ev.data.fd=sockfd;
                        //设置用于注测的写操作事件
    
                        ev.events = EPOLLOUT | EPOLLET;
                        //修改sockfd上要处理的事件为EPOLLOUT
    
                        epoll_ctl(epfd,EPOLL_CTL_MOD,sockfd,&ev);
                    }
                }
                else if(events[i].events & EPOLLOUT) // 如果有数据发送
                {
                    const char str[] = "hello from epoll : this is a long string which may be cut by the net\n";
                    memcpy(line, str, sizeof(str));
                    cout << "Write " << line << endl;
                    sockfd = events[i].data.fd;
    
                    bool bWritten = false;
                    int writenLen = 0;
                    int count = 0;
                    char * head = line;
                    while(1)
                    {
                            // 确保sockfd是非阻塞的
                            writenLen = send(sockfd, head + count, MAXLINE, 0);
                            if (writenLen == -1)
                            {
                                if (errno == EAGAIN)
                                {
                                    // 对于nonblocking 的socket而言，这里说明了已经全部发送成功了
                                    bWritten = true;
                                    break;
                                }
                                else if(errno == ECONNRESET)
                                {
                                    // 对端重置,对方发送了RST
                                    CloseAndDisable(sockfd, events[i]);
                                    cout << "counterpart send out RST\n";
                                    break;
                                }
                                else if (errno == EINTR)
                                {
                                    // 被信号中断
                                    continue;
                                }
                                else
                                {
                                    // 其他错误
                                }
                            }
    
                            if (writenLen == 0)
                            {
                                // 这里表示对端的socket已正常关闭.
                                CloseAndDisable(sockfd, events[i]);
                                cout << "counterpart has shut off\n";
                                break;
                            }
    
                            // 以下的情况是writenLen > 0
                            count += writenLen;
                            if (writenLen == MAXLINE)
                            {
                                // 可能还没有写完
                                continue;
                            }
                            else // 0 < writenLen < MAXLINE
                            {
                                // 已经写完了
                                bWritten = true;
                                break; // 退出while(1)
                            }
                    }
    
                    if (bWritten == true)
                    {
                        //设置用于读操作的文件描述符
                        ev.data.fd=sockfd;
    
                        //设置用于注测的读操作事件
                        ev.events=EPOLLIN | EPOLLET;
    
                        epoll_ctl(epfd,EPOLL_CTL_MOD,sockfd,&ev);
                    }
                }
            }
        }
        return 0;

}

*/

