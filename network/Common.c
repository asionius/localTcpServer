#include "common.h"
#include "stdio.h"
#include "stdarg.h"
void dlog(const char *fmt, ...)
{
//	return;
    static int is_need_rm_log_file = 0;
	va_list args;
    FILE *fd = NULL;

    if(is_need_rm_log_file == 1)
    { 
        fd = fopen("log.txt","w+");
    }
    else
    {
        fd = fopen("log.txt","a");
    }

    if(fd == NULL)
    {
        printf("dlog:fopen failed\n");
        return;
    }
    is_need_rm_log_file = 0;
    
    fseek(fd,0,SEEK_END);
    int size = ftell(fd);
    if(size >= 50*1024*1024) //50MB
    {
        is_need_rm_log_file = 1;
		fseek(fd, 0, SEEK_SET);
    }
    
	va_start(args, fmt);
	vprintf(fmt,args);
	va_end(args);
	va_start(args, fmt);
	vfprintf(fd,fmt,args);
	va_end(args);

    fclose(fd);
}

