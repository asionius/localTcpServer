#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "server.h"
#include "network.h"


int is_ad_server = 0;
char ad_server_ip[IPV4_LEN];
int ad_server_port;
static int ad_connecting_stat = 1;

int fild_id = 0;

timer_t timer_usb_use = 0;
int usb_is_used = 0;


static void timer_handler_ad_connect(int sig, siginfo_t *si, void *uc)
{
   /* Note: calling printf() from a signal handler is not
      strictly correct, since printf() is not async-signal-safe;
      see signal(7) */
    static int count = 0;
   dlog("timer_handler_ad_connect:Caught signal %d,count is %d\n", sig,count++);
   //print_siginfo(si);
   ad_connecting_stat = 1;
   signal(sig, SIG_IGN);

   
}

//static void timer_handler_usb_used(int sig, siginfo_t *si, void *uc)
static void policy_handler_usb_used(void)
{
	const char * cmd_usb_useless_pre = "mv /lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko /lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko.bak";
	const char * cmd_usb_useless_exec = "rmmod usb_storage";
	const char * cmd_usb_useful_enable = "mv /lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko.bak /lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko"; 
	static int has_usb_limit_handled = 0;
	int ret;

   if(usb_is_used == 0)
   {
	   if(has_usb_limit_handled == 0)
	   {
		   system(cmd_usb_useless_pre);
		   system(cmd_usb_useless_exec);
		   has_usb_limit_handled = 1;
		   dlog("The USB has been limited\n");
	   }
   }
   else
   {
		ret = system(cmd_usb_useful_enable);
		has_usb_limit_handled = 0;
		if(ret == 0)
		{
			dlog("The USB has been unlimited\n");
		}
   }
#if 0
   /* Note: calling printf() from a signal handler is not
      strictly correct, since printf() is not async-signal-safe;
      see signal(7) */
    static int count = 0;
   dlog("timer_handler_usb_used:Caught signal %d,count is %d,usb_is_used is %d\n", sig,count++,usb_is_used);
   //print_siginfo(si);
   
   signal(sig, SIG_IGN);

   
   timer_t timer_usb = 0;
   network_timer_create_by_sig(&timer_usb,SIGRTMAX,timer_handler_usb_used);
   network_timer_setting(timer_usb,3000);

   if(usb_is_used == 0)
   {
        // ½ûÓÃUSB
        char dev_name[NAME_LEN];
        char comman_line[NAME_LEN];
        system("ls /dev/sd* > /tmp/disk_list.txt");
        FILE * disks_fd = fopen("/tmp/disk_list.txt","r");
        if(disks_fd == NULL)
        {
            dlog("fopen error\n");
            dlog_error();
            return;
        }
        memset(dev_name,0,sizeof(dev_name));
        memset(comman_line,0,sizeof(comman_line));
        dlog("fopen after\n");
        while((fgets(dev_name,sizeof(dev_name),disks_fd))!=NULL)
        {
            //dlog("dev_name is %s\n",dev_name);
            if(strstr(dev_name,"sda") != NULL)
			{
                dlog("pass dev_name is %s\n",dev_name);
                continue;
			}
            else if(strstr(dev_name,"sdb") != NULL)
			{
                dlog("pass dev_name is %s\n",dev_name);
                continue;
			}
	        sprintf(comman_line,"umount %s",dev_name);
	        dlog("comman_line is %s\n",comman_line);
	        system(comman_line);
            memset(comman_line,0,sizeof(comman_line));
            memset(dev_name,0,sizeof(dev_name));
        };
   }
#endif
}

static void init_usb(void)
{
	/* limit the usb defaultly */
	policy_handler_usb_used();
	return ;
}

int getProcessName(char *name,int n)
{
    FILE *fd;
    char filename[256];
    char process_name[PROCESS_NAME_LEN];
    
    memset(process_name,0,sizeof(process_name));
    memset(filename,0,sizeof(filename));

    sprintf(filename,"/proc/%u/comm",getpid());

    fd = fopen(filename,"r");
    if(fd == NULL)
    {
        printf("fopen error\n");
        return -1;
    }

    if(fgets(process_name,sizeof(process_name),fd)== NULL)
    {
        printf("fgets error\n");
        return -1;
    };

    memcpy(name,process_name,strlen(process_name) - 1);//end is \n
    
    return 0;
};

int getHostName(char *pHostName,int n)
{
    dlog("getHostName\n");
	FILE *fd = NULL;
	char hostname[NAME_LEN];
	int readBytes;

    memset(hostname,0,sizeof(hostname));

	fd = fopen("/etc/hostname","r");
	if(fd == NULL)
	{
        printf("fopen error\n");
        return -1;
	}

	readBytes = fread(hostname,1,NAME_LEN - 1,fd);
	if(readBytes <= 0)
	{
        printf("fread error\n");
        return -1;
	}
	dlog("get hostname is %s\n",hostname);
    memcpy(pHostName,hostname,readBytes);
    fclose(fd);
	return 0;
};

int get_ad_server_fd(char *ip,unsigned short port)
{
    timer_t timer_connect_ad = 0;
    int i=0;
    int ret = 0;
    int socket_fd = 0;
    if(ad_connecting_stat == 0)
    {
        printf("can not connect ad \n");
        return -1;
    }
    
    for (i=0;i<3;i++)
    {
        
        socket_fd = network_client_connect(ip,port);
        if(socket_fd <= 0)
        {
            printf("%dth:connect timeout,try againt \n",i+1);
            usleep(300*1000);
            continue;
        }
        else
        {
            dlog("successfully connected to server.\n");
            return socket_fd;
        }
    }
    
    dlog("get_ad_server_fd:connect faild\n");

    mylock_lock();
    if(ad_connecting_stat == 1)
    {
        ret = network_timer_create(&timer_connect_ad,timer_handler_ad_connect);
        if(ret == -1)
        {
            printf("get_ad_server_fd:network_timer_create failed\n");
            return -1;
        }
        network_timer_setting(timer_connect_ad,3000);
        

        ad_connecting_stat = 0;
    }
    mylock_unlock();
    return -1;

};
int request_ad_random_string(int socket_fd,char *randomString,struct net_packet_group_policy *pPacket)
{
    int ret = 0;
    struct net_packet_group_policy stGroupPolicy;

    memset(&stGroupPolicy,0,sizeof(stGroupPolicy));

    
    strncpy(stGroupPolicy.user_name,pPacket->user_name,sizeof(stGroupPolicy.user_name));
    dlog("request_ad_random_string:user name is %s\n",stGroupPolicy.user_name);
    
    strncpy(stGroupPolicy.host_name,pPacket->host_name,sizeof(stGroupPolicy.host_name));
    dlog("request_ad_random_string:host name is %s\n",stGroupPolicy.host_name);

    stGroupPolicy.size = sizeof(stGroupPolicy);
    stGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_REQUEST_RANDOM_STRING;
    ret = send_struct(socket_fd,(unsigned char*)&stGroupPolicy,sizeof(stGroupPolicy));
    if(ret == -1)
    {
        printf("request_ad_random_string:send_data error\n");
        close(socket_fd);
		return -1;
    }
    
    memset(&stGroupPolicy,0,sizeof(stGroupPolicy));
    ret = recive_struct(socket_fd,(unsigned char*)&stGroupPolicy,sizeof(stGroupPolicy));
    if(ret == -1&&ret!=sizeof(stGroupPolicy))
    {
        printf("request_ad_random_string:receive_struct error\n");
        
        close(socket_fd);
        return -1;
    }
    dlog("request_ad_random_string:SUCCESS:random_string is '%s'\n", stGroupPolicy.random_string);
    strncpy(randomString,stGroupPolicy.random_string,sizeof(stGroupPolicy.random_string));

    return 0;
}


int etcd_connect()
{
    return 0;
};
int etcd_get_file_id()
{
    return 0;
};
int etcd_disconnect()
{
    return 0;
};


int process_usb_use_packet(struct net_packet_group_policy *pstGroupPolicy)
{ 
    if(pstGroupPolicy->file_id == 1)
    {
        dlog("process_usb_use_packet: unused usb\n");
        //½ûÓÃUSB
        mylock_lock();
        usb_is_used = 0;
        mylock_unlock();
    }
    else
    {
        dlog("process_usb_use_packet: used usb\n");
        //ÆôÓÃUSB      
        mylock_lock();
        usb_is_used = 1;
        mylock_unlock();
        
    }
	policy_handler_usb_used();

    
    dlog("process_usb_use_packet:file_id is %d,usb_is_used is %d\n",pstGroupPolicy->file_id,usb_is_used);
};

int request_group_policy_file(int socket_fd,char *randomString,struct net_packet_group_policy *pPacket)
{
    int ret = 0;
    struct net_packet_group_policy stGroupPolicy;

    memset(&stGroupPolicy,0,sizeof(stGroupPolicy));

    
    strncpy(stGroupPolicy.user_name,pPacket->user_name,sizeof(stGroupPolicy.user_name));
    dlog("request_group_policy_file:user name is %s\n",stGroupPolicy.user_name);
    
    strncpy(stGroupPolicy.host_name,pPacket->host_name,sizeof(stGroupPolicy.host_name));
    dlog("request_group_policy_file:host name is %s\n",stGroupPolicy.host_name);

    stGroupPolicy.size = sizeof(stGroupPolicy);
    stGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_REQUEST_USB_USED;
    ret = send_struct(socket_fd,(unsigned char*)&stGroupPolicy,sizeof(stGroupPolicy));
    if(ret == -1)
    {
        printf("request_group_policy_file:send_data error\n");
        close(socket_fd);
		return -1;
    }
    
    memset(&stGroupPolicy,0,sizeof(stGroupPolicy));
    ret = recive_struct(socket_fd,(unsigned char*)&stGroupPolicy,sizeof(stGroupPolicy));
    if(ret == -1&&ret!=sizeof(stGroupPolicy))
    {
        printf("request_group_policy_file:receive_struct error\n");
        
        close(socket_fd);
        return -1;
    }
    if(stGroupPolicy.content_type == CONTENT_TYPE_GROUP_POLICY_RESPOND_USB_USED)
    {
        process_usb_use_packet(&stGroupPolicy);
        dlog("request_group_policy_file:SUCCESS:file_id is %d\n", stGroupPolicy.file_id);
    }
    else
    {
        dlog("request_group_policy_file:recive other content_type 0x%x\n",stGroupPolicy.content_type);
    };
    

    return 0;
};

int request_ad_file_id_by_user_name()
{
    int ret = 0;
    ret = etcd_connect();
    if(ret != 0)
    {
        printf("process_group_policy_user_login:request_ad_random_string faild\n");
        return -1;
    }

    
    ret = etcd_get_file_id();
    if(ret != 0)
    {
        printf("process_group_policy_user_login:request_ad_random_string faild\n");
        return -1;
    }
    
    
    ret = etcd_disconnect();
    if(ret != 0)
    {
        printf("process_group_policy_user_login:request_ad_random_string faild\n");
        return -1;
    }

    return 0;
};




int process_group_policy_user_login(int fd,struct net_packet_group_policy *pPacket)
{
    dlog("process_group_policy_user_login:into fd is %d\n",fd);
    int ret = 0;
    char randomString[NAME_LEN];
    struct net_packet_group_policy stNetPacketGroupPolicy;

    memset(&stNetPacketGroupPolicy,0,sizeof(stNetPacketGroupPolicy));
    memset(randomString,0,sizeof(randomString));

    strncpy(stNetPacketGroupPolicy.user_name,pPacket->user_name,sizeof(stNetPacketGroupPolicy.user_name));


    int socket_fd = get_ad_server_fd(ad_server_ip,ad_server_port);
    if(socket_fd <= 0)
    {   
        printf("process_group_policy_user_login:get_ad_server_fd failed\n");
        stNetPacketGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_ERROR_CONNECT_AD;
        send_struct(fd,(unsigned char *)&stNetPacketGroupPolicy,sizeof(stNetPacketGroupPolicy));
        return -1;
    }
    
    //request random string
    //ret = request_ad_random_string(socket_fd,randomString,pPacket);
    if(ret != 0)
    {
        printf("process_group_policy_user_login:request_ad_random_string faild\n");
        stNetPacketGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_ERROR_REQUEST_RANDOM_STRING;
        send_struct(fd,(unsigned char *)&stNetPacketGroupPolicy,sizeof(stNetPacketGroupPolicy));
        return -1;
    }
    

    //request file id 
    ret = request_ad_file_id_by_user_name();
    if(ret != 0)
    {
        stNetPacketGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_ERROR_REQUEST_RANDOM_STRING;
        send_struct(fd,(unsigned char *)&stNetPacketGroupPolicy,sizeof(stNetPacketGroupPolicy));
        printf("process_group_policy_user_login:request_ad_file_id_by_user_name faild\n");
        return -1;
    }
    //get group policy file
    ret = request_group_policy_file(socket_fd,randomString,pPacket);
    if(ret != 0)
    {
        stNetPacketGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_ERROR_REQUEST_POLICY_FILE;
        send_struct(fd,(unsigned char *)&stNetPacketGroupPolicy,sizeof(stNetPacketGroupPolicy));
        printf("process_group_policy_user_login:request_group_policy_file faild\n");
        return -1;
    }

    //send sucess packet
    stNetPacketGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_RESPOND_USER_LOGIN;
    strncpy(stNetPacketGroupPolicy.random_string,randomString,sizeof(stNetPacketGroupPolicy.random_string));
    
    send_struct(fd,(unsigned char *)&stNetPacketGroupPolicy,sizeof(stNetPacketGroupPolicy));

    //disconnect from ad server
    ret = network_client_disconnect(socket_fd);
    if(ret != 0)
    {
        printf("process_group_policy_user_login:network_client_disconnect faild\n");
        return -1;

    };
    return 0;
};

int process_request_random_string(int fd,struct net_packet_group_policy *pPacket)
{
    struct net_packet_group_policy stNet_packet_group_policy;

    memset(&stNet_packet_group_policy,0,sizeof(stNet_packet_group_policy));
    
    printf("user name is %s\n",pPacket->user_name);
    printf("host_name  is %s\n",pPacket->host_name);
    stNet_packet_group_policy.content_type = CONTENT_TYPE_GROUP_POLICY_RESPOND_RANDOM_STRING;

    printf("get randomString\n");
    static int count = 0;
    int randomNum = 0;
    char randomString[NAME_LEN];
    memset(randomString,0,sizeof(randomString));

    
    mylock_lock();
    srandom(time(NULL) + count );
    randomNum = random();
    sprintf(stNet_packet_group_policy.random_string,"%d",count++);
    mylock_unlock();

    stNet_packet_group_policy.size = pPacket->size;
    strncpy(stNet_packet_group_policy.host_name,pPacket->host_name,sizeof(stNet_packet_group_policy.host_name));
    strncpy(stNet_packet_group_policy.user_name,pPacket->user_name,sizeof(stNet_packet_group_policy.user_name));
    stNet_packet_group_policy.content_type = CONTENT_TYPE_GROUP_POLICY_RESPOND_RANDOM_STRING;


    send_struct(fd,(unsigned char *)&stNet_packet_group_policy,sizeof(stNet_packet_group_policy));



    return 0;
};
int process_request_usb_use(int fd,struct net_packet_group_policy *pPacket)
{
    struct net_packet_group_policy stNet_packet_group_policy;
    memset(&stNet_packet_group_policy,0,sizeof(stNet_packet_group_policy));
    
    printf("process_request_usb_use:user name is %s\n",pPacket->user_name);
    printf("process_request_usb_use:host_name  is %s\n",pPacket->host_name);

    static int count = 0;
    int randomNum = 0;
    char randomString[NAME_LEN];
    memset(randomString,0,sizeof(randomString));

    
    mylock_lock();
    srandom(time(NULL) + count );
    randomNum = random();
    sprintf(stNet_packet_group_policy.random_string,"%d",count++);
    fild_id = (fild_id == 0)?1:0;
    stNet_packet_group_policy.file_id = fild_id ;
    mylock_unlock();

    dlog("process_request_usb_use:file_id is %d\n",stNet_packet_group_policy.file_id);

    stNet_packet_group_policy.size = pPacket->size;
    strncpy(stNet_packet_group_policy.host_name,pPacket->host_name,sizeof(stNet_packet_group_policy.host_name));
    strncpy(stNet_packet_group_policy.user_name,pPacket->user_name,sizeof(stNet_packet_group_policy.user_name));
    stNet_packet_group_policy.content_type = CONTENT_TYPE_GROUP_POLICY_RESPOND_USB_USED;


    send_struct(fd,(unsigned char *)&stNet_packet_group_policy,sizeof(stNet_packet_group_policy));



    return 0;
};




int network_callback(int fd,char *buf,int n)
{
    dlog("network_callback:into\n");
    int recv_size = 0;
    int recv_count = 0;
    int ret = 0;
    struct net_packet_group_policy net_packet_group_policy;
    memset(&net_packet_group_policy,0,sizeof(net_packet_group_policy));

    if(n != sizeof(net_packet_group_policy))
    {
        printf("network_callback:buf size error\n");
        return -1;
    }
    memcpy(&net_packet_group_policy,buf,sizeof(net_packet_group_policy));
    dlog("network_callback:net_packet_group_policy.command_code is 0x%x\n",net_packet_group_policy.content_type);
    switch(net_packet_group_policy.content_type)
    {
        case CONTENT_TYPE_GROUP_POLICY_REQUEST_RANDOM_STRING:
            ret = process_request_random_string(fd,&net_packet_group_policy);
            break;
        case CONTENT_TYPE_GROUP_POLICY_REQUEST_USB_USED:
            ret = process_request_usb_use(fd,&net_packet_group_policy);
            break;
        case CONTENT_TYPE_GROUP_POLICY_REQUEST_USER_LOGIN:
            ret = process_group_policy_user_login(fd,&net_packet_group_policy);
            break;
        default:
            printf("network_callback:not find command code 0x%x\n",net_packet_group_policy.content_type);
            return -1;
    }
    if(ret != 0)
    {
        printf("network_callback:process packet faild\n");
        return -1;
    }

    /*
    recv_size = send_data(fd,(char *)&token_r,sizeof(token_r));
    if(recv_size <= 0)
    {
        //client_list_del(pclient);
        return 0;
    }

    recv_size = send_data(fd,(char *)&token_r,sizeof(token_r));
    if(recv_size <= 0)
    {
        //client_list_del(pclient);
        return 0;
    }
*/

    
    return 0;
};

int network_process_frame(struct client_node* pclient)
{
    int recv_size = 0;
    int ret =0;
    int recv_count = 0;
    static int token_count = 0;
    unsigned char buf[MAX_BUFF_SIZE];
    struct token_net_packet token_r;
    struct net_packet_head head;
    
    memset(&token_r,0,sizeof(token_r));
    memset(buf,0,sizeof(buf));
    memset(&head,0,sizeof(head));
    recv_size = recv(pclient->fd,&head,sizeof(head),0);
    if(recv_size <= 0)
    {
        //client_list_del(pclient);
        pclient->needClose = 1;
        return 0;
    }

    if(head.data_type != NET_PACKET_TYPE_STRUCT
            ||head.data_len != sizeof(struct token_net_packet))
    {
        printf("not recive struct data\n");
        
        recive_no_use_buf(pclient->fd,head.data_len);
        return -1;
    }

    recv_size = recv(pclient->fd,&token_r,sizeof(token_r),0);
    if(recv_size <= 0)
    {
        //client_list_del(pclient);
        pclient->needClose = 1;
        return 0;
    }

 
    
    printf("user name is %s\n",token_r.user_name);
    printf("process name is %s\n",token_r.process_name);
    token_r.command_code = COMMAND_CODE_TOKEN_RESPOND;

    mylock_lock();
    printf("get toke\n");
    ret = 1;
    mylock_unlock();



    recv_size = send_data(pclient->fd,(char *)&token_r,sizeof(token_r));
    if(recv_size <= 0)
    {
        //client_list_del(pclient);
        pclient->needClose = 1;
        return 0;
    }

    printf("%d:recv %d data\n",getpid(),recv_count);
    
    return 0;
};

int use_epoll = 1;

int main(int argc,char* argv[])
{

    int ret = 0;
    int status = 0;
    pid_t pid = 0, w = 0;


    //while(1)
	if(1)
    {
        pid = fork();
        if (pid == -1) 
        {
           dlog("main :fork error\n");
           return -1;
        }
        
        if(pid == 0)
        {
            
			dlog("fork() :forked server\n");
			
            //¿¿USB
			init_usb();
#if 0
            //ret = network_timer_create_by_sig(&timer_usb_use,SIGRTMAX,timer_handler_usb_used);
			
            if(ret == -1)
            {
                printf("get_ad_server_fd:network_timer_create failed\n");
                return -1;
            }
            //network_timer_setting(timer_usb_use,3000);
#endif

            struct thread_list *pThreadList = NULL;

            sprintf(ad_server_ip,"127.0.0.1");
            ad_server_port = 12000;

            if(argc == 2)
            {
                is_ad_server = 1;
                ad_server_port = 13000;
                sprintf(ad_server_ip,"127.0.0.1");
            }
            
            if(argc == 3)
            {
                is_ad_server = 0;
                ad_server_port = 13000;
                sprintf(ad_server_ip,"127.0.0.1");
            }


        	if(is_ad_server == 1)
        	{
                pThreadList = network_server_init(ad_server_port,network_process_frame);
        	}
        	else
        	{
                pThreadList = network_server_init(SERVER_PORT_GROUP_POLICY,network_process_frame);
        	}
            if(pThreadList == NULL)
            {
                perror("network_server_init error\n");
                return -1;
            }
            if(use_epoll == 1)
            {

                printf("start epoll\n");
                network_epoll_init(pThreadList,network_callback);
            }
            
            while(1)
            {
                
                if(use_epoll == 0)
                {

                    network_server_start(pThreadList);
                }
                else
                {
            	    network_epoll_start(pThreadList);
                }

                network_server_wait_finish(pThreadList);
            }

        }
        dlog("main :forked server\n");
        
        w = waitpid(pid, &status, WUNTRACED | WCONTINUED);
        if (w == -1) 
	    {
            dlog("mian:waitpid error\n");
            return -1;
        }
    }
    return 0;
}
