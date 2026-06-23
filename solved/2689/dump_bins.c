// LD_PRELOAD 로 main 에 끼워 fexecve 직전 memfd 내용을 /tmp/dump/bin_<idx> 로 저장.
// build: gcc -shared -fPIC -O2 -o dump_bins.so dump_bins.c -ldl
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
static int (*real_fexecve)(int,char*const[],char*const[]);
static int idx=0;
int fexecve(int fd, char *const argv[], char *const envp[]){
    if(!real_fexecve) real_fexecve=dlsym(RTLD_NEXT,"fexecve");
    char path[64]; snprintf(path,sizeof path,"/tmp/dump/bin_%d",idx++);
    mkdir("/tmp/dump",0755);
    // memfd 내용을 통째로 복사
    char src[64]; snprintf(src,sizeof src,"/proc/self/fd/%d",fd);
    int in=open(src,O_RDONLY), out=open(path,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(in>=0&&out>=0){ char buf[65536]; ssize_t r; while((r=read(in,buf,sizeof buf))>0) write(out,buf,r); }
    if(in>=0)close(in); if(out>=0)close(out);
    return real_fexecve(fd,argv,envp);
}
