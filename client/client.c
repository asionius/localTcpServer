#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>

#include "common.h"
#include "network.h"
#include "client.h"

int numOfConn = 0;

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
int getUserName(char *username,int n)
{
    uid_t my_uid;
  //  pid = getpid();
    struct passwd *my_info;
    my_uid = getuid();
    my_info = getpwuid(my_uid);
    if(my_info)
    {
    /*
        printf("My Login Name:%s " ,my_info->pw_name);

        printf("My Password :%s " ,my_info->pw_passwd);

        printf("My User ID :%uld ",my_info->pw_uid);

        printf("My Group ID :%uld ",my_info->pw_gid);

        printf("My Real Name:%s " ,my_info->pw_gecos);

        printf("My Home Dir :%s ", my_info->pw_dir);

        printf("My Work Shell:%s ", my_info->pw_shell);
        */
    }
    else
    {
        printf("not found this program username\n");
        return -1;
    }

    strncpy(username,my_info->pw_name,n);
    return 0;
}

int getServerFd(char *ip,unsigned short port)
{
    int i=0;
    int socket_fd = 0;
    for (i=0;i<3;i++)
    {
        
        socket_fd = network_client_connect(ip,port);
        if(socket_fd <= 0)
        {
            printf("%dth:connect timeout,try againt \n",i+1);
            sleep(3);
            continue;
        }
        else
        {
            dlog("successfully connected to server.\n");
            printf("successfully connected to server.\n");
            return socket_fd;
        }
    }
    
    printf("connect faild\n");
    return -1;

};

int request_user_login(int socket_fd)
{
    int ret = 0;
    struct net_packet_group_policy stGroupPolicy;
    
    memset(&stGroupPolicy,0,sizeof(stGroupPolicy));
    ret = getUserName(stGroupPolicy.user_name,sizeof(stGroupPolicy.user_name));
    if(ret != 0)
    {
        printf("getUserName error\n");
        return -1;
    }
    
    sprintf(stGroupPolicy.user_name,"test");
    ret = getHostName(stGroupPolicy.host_name ,sizeof(stGroupPolicy.host_name));
	if(ret != 0)
    {
        printf("getProcessName error\n");
        return -1;
    }
    
    stGroupPolicy.size = sizeof(stGroupPolicy);
    stGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_REQUEST_USER_LOGIN;
    dlog("request_user_login:send packet, command code is 0x%x\n",stGroupPolicy.content_type);
    ret = send_struct(socket_fd,(unsigned char*)&stGroupPolicy,sizeof(stGroupPolicy));
    if(ret == -1)
    {
        printf("send_data error\n");
        close(socket_fd);
		return -1;
    }
    
    memset(&stGroupPolicy,0,sizeof(stGroupPolicy));
    ret = recive_struct_time_out(socket_fd,(unsigned char*)&stGroupPolicy,sizeof(stGroupPolicy),LOGIN_TIME_OUT);
    if(ret == -1&&ret!=sizeof(stGroupPolicy))
    {
        printf("receive_struct error\n");
        
        close(socket_fd);
        return -1;
    }
    if(stGroupPolicy.content_type & CONTENT_TYPE_GROUP_POLICY_ERROR_CODE == CONTENT_TYPE_GROUP_POLICY_ERROR_CODE)
    {
        
        printf("FAILD:user login faild,random is '%s'\n", stGroupPolicy.random_string);
        return -1;
    }
    printf("SUCCESS:user login finish,random is '%s'\n", stGroupPolicy.random_string);

    return 0;
};
int requestRandomString(int socket_fd,char *randomString)
{
    int ret = 0;
    struct net_packet_group_policy stGroupPolicy;

    memset(&stGroupPolicy,0,sizeof(stGroupPolicy));

    
    ret = getUserName(stGroupPolicy.user_name,sizeof(stGroupPolicy.user_name));
    if(ret != 0)
    {
        printf("getUserName error\n");
        return -1;
    }
    dlog("user name is %s\n",stGroupPolicy.user_name);

    ret = getHostName(stGroupPolicy.host_name ,sizeof(stGroupPolicy.host_name));
	if(ret != 0)
    {
        printf("getProcessName error\n");
        return -1;
    }
    
    //printf("process name is %s\n",token_rquest.process_name);



    stGroupPolicy.size = sizeof(stGroupPolicy);
    stGroupPolicy.content_type = CONTENT_TYPE_GROUP_POLICY_REQUEST_RANDOM_STRING;
    ret = send_struct(socket_fd,(unsigned char*)&stGroupPolicy,sizeof(stGroupPolicy));
    if(ret == -1)
    {
        printf("send_data error\n");
        close(socket_fd);
		return -1;
    }
    
    //dlog("wait for recive...\n");
    memset(&stGroupPolicy,0,sizeof(stGroupPolicy));
    ret = recive_struct(socket_fd,(unsigned char*)&stGroupPolicy,sizeof(stGroupPolicy));
    if(ret == -1&&ret!=sizeof(stGroupPolicy))
    {
        printf("receive_struct error\n");
        
        close(socket_fd);
        return -1;
    }
    //dlog("successfully recive data.\n");
    printf("SUCCESS:random_string is '%s'\n", stGroupPolicy.random_string);

    return 0;
}
int client_num = 0;

struct net_packet_save 
{
    unsigned char size;			//包类型
    unsigned char cmdFlag;				//版本
    unsigned int save_menoy;
    unsigned int save_index; 			//数据类型
    unsigned char crc;
};
struct net_packet_polling 
{
    unsigned char size;			//包类型
    unsigned char cmdFlag;				//版本
    unsigned int machine_id;
    unsigned char check; 			//数据类型
    unsigned char crc;
};



int main(int argc, char* argv[])
{
    int ret = 0;

    int process_num = CLIENT_NUM;//client.h
    int socket_num = 100;//client.h


    if(argc == 2)
    {
        process_num=atoi(argv[1]);
    }
    if(argc == 3)
    {
        process_num=atoi(argv[1]);
        socket_num=atoi(argv[2]);
    }

    printf("process num is %d\n",process_num);

    
    int i=0;
    for(i=0;i<process_num;i++)
    {
        if(fork()==0)
        {
            int socket_fd = getServerFd("127.0.0.1",12000);
			printf("the socket_fd is:%d................................\n",socket_fd) ;
	//return 0 ;
            if(socket_fd <= 0)
            {
                printf("getServerFd faild\n");
                return -1;
            }
            ret = request_user_login(socket_fd);
            if(ret != 0)
            {
                printf("requestToken faild\n");
                
                network_client_disconnect(socket_fd);
                //sleep(5);
                return -1;
            }
            sleep(3);
            network_client_disconnect(socket_fd);
            return 0;
        }
    }

            /*
        
            char randomString[NAME_LEN];
            memset(randomString,0,sizeof(randomString));
            int j=0;
            for(j=0;j<socket_num;j++)
            {
                int *socket_fd = (int *)malloc(sizeof(int));
                *socket_fd = network_connect_only("192.168.96.1",9016);
                if(*socket_fd <= 0)
                {
                    printf("getServerFd faild\n");
                    return -1;
                }

                struct net_packet_save packet;
                struct net_packet_polling polling;
                memset(&packet,0,sizeof(packet));
                memset(&polling,0,sizeof(polling));

                packet.size = sizeof(packet)-1;
                packet.cmdFlag= 0x07;
                packet.save_menoy = 100;
                packet.save_index = 1;

                polling.size = sizeof(polling)-1;
                polling.cmdFlag = 0xFF;
                polling.machine_id = 1;
                polling.check = 1;

                int recode = write(*socket_fd,&polling,sizeof(polling));
                if(recode < 0)
                {
                    int errorNum = errno;
                    dlog("network_client_disconnect:write error (%d):%s\n",errorNum,strerror(errorNum));
                    close(*socket_fd);
                    return -1;
                }
                char buf[100];
                memset(buf,0,sizeof(buf));
                recode = read(*socket_fd,buf,sizeof(buf));
                if(recode < 0)
                {
                    int errorNum = errno;
                    dlog("network_client_disconnect:write error (%d):%s\n",errorNum,strerror(errorNum));
                    close(*socket_fd);
                    return -1;
                }
                
                dlog("read %d\n",recode);
                select_sleep(0,1000);
            }
            sleep(1000);
            return 0;
            int socket_fd = getServerFd("192.168.96.1",9016);
            if(socket_fd <= 0)
            {
                printf("getServerFd faild\n");
                return -1;
            }
            
            ret = requestRandomString(socket_fd,randomString);
            if(ret != 0)
            {
                printf("requestToken faild\n");
                
                //sleep(5);
                return -1;
            }
            ret = request_user_login(socket_fd);
            if(ret != 0)
            {
                printf("requestToken faild\n");
                
                network_client_disconnect(socket_fd);
                //sleep(5);
                return -1;
            }
            sleep(3);
            network_client_disconnect(socket_fd);
            return 0;
        }
    }
    return 0;
    sleep(2);// Wait for all child to exit
    for (i = 0; i < process_num; i++)
    {
        int stat;
        int rt;
        rt = wait(&stat);
        if (rt > 0)
        {
            printf("Child %d exit status: %d\n", rt, WEXITSTATUS(stat));
        }
        else if (rt < 0)
        {
            printf("wait()");
        }
        fflush(NULL);
    }
    */
	wait();
    return 0;
}
