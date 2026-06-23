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
int fexecve(int fd, char *const argv[], char *const envp[]){
    if(!real_fexecve) real_fexecve=dlsym(RTLD_NEXT,"fexecve");
    const char *name=(argv&&argv[0])?argv[0]:"bin_unknown";
    mkdir("/tmp/dump",0755);
    char path[160]; snprintf(path,sizeof path,"/tmp/dump/%s",name);
    char src[64]; snprintf(src,sizeof src,"/proc/self/fd/%d",fd);
    int in=open(src,O_RDONLY), out=open(path,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(in>=0&&out>=0){char buf[65536];ssize_t r;while((r=read(in,buf,sizeof buf))>0){if(write(out,buf,r)<0)break;}}
    if(in>=0)close(in); if(out>=0)close(out);
    // 자식 env 에서 LD_PRELOAD 제거(자식 bin 크래시 방지, 덤프엔 무관)
    int n=0; while(envp&&envp[n]) n++;
    char **e2=malloc((n+1)*sizeof(char*)); int j=0;
    for(int i=0;i<n;i++) if(strncmp(envp[i],"LD_PRELOAD=",11)!=0) e2[j++]=envp[i];
    e2[j]=0;
    return real_fexecve(fd,argv,(char*const*)e2);
}
