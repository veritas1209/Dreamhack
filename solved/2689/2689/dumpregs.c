// sym8(0x8040c8) 쓰기를 세며, 지정 구간(START~END)에서 레지스터파일(.sym.p) 전체를 덤프.
// 비교 시점에 secret 이 어느 레지스터에 있는지 잡는다. (bin당 1회 실행 추출 목표)
// build: gcc -O2 -o dumpregs dumpregs.c
// run: ./dumpregs ./bin_0 0101010101010101 bin_0 /host/regs0 2860 2895
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#define WP 0x8040c8UL
#define SYMP 0x804000UL
#define SYMP_LEN 0x1000
static long pu(pid_t p,int i){return ptrace(PTRACE_PEEKUSER,p,(void*)offsetof(struct user,u_debugreg[i]),0);}
static void po(pid_t p,int i,unsigned long v){ptrace(PTRACE_POKEUSER,p,(void*)offsetof(struct user,u_debugreg[i]),(void*)v);}
int main(int argc,char**argv){
    const char*outdir=argv[4];
    long START=strtol(argv[5],0,10), END=strtol(argv[6],0,10);
    { char c[300]; snprintf(c,sizeof c,"mkdir -p %s",outdir); if(system(c)){} }
    unsigned char a8[8]; const char*hx=argv[2];
    for(int i=0;i<8;i++){char t[3]={hx[2*i],hx[2*i+1],0}; a8[i]=strtoul(t,0,16);}
    pid_t pid=fork();
    if(pid==0){ ptrace(PTRACE_TRACEME,0,0,0);
        char arg1[9]; memcpy(arg1,a8,8); arg1[8]=0;
        char*av[]={(char*)argv[3],arg1,0}; char*ev[]={"PATH=/usr/bin:/bin",0};
        execve(argv[1],av,ev); _exit(127); }
    int st; waitpid(pid,&st,0);
    po(pid,0,WP); po(pid,7,(0x1)|(0xd<<16));
    char memp[64]; snprintf(memp,sizeof memp,"/proc/%d/mem",pid); int mem=open(memp,O_RDONLY);
    long n=0;
    ptrace(PTRACE_CONT,pid,0,0);
    while(1){
        waitpid(pid,&st,0);
        if(WIFEXITED(st)||WIFSIGNALED(st)) break;
        if(WIFSTOPPED(st)){
            if(pu(pid,6)&0x1){
                if(n>=START && n<=END){
                    unsigned char buf[SYMP_LEN];
                    if(pread(mem,buf,SYMP_LEN,SYMP)==SYMP_LEN){
                        char fp[320]; snprintf(fp,sizeof fp,"%s/symp_w%05ld.bin",outdir,n);
                        int fd=open(fp,O_WRONLY|O_CREAT|O_TRUNC,0644);
                        if(fd>=0){ if(write(fd,buf,SYMP_LEN)){} close(fd);}
                    }
                }
                n++;
                if(n>END+2){ /* 구간 지나면 빨리 종료 위해 WP 해제 */ po(pid,7,0);} 
                po(pid,6,0);
            }
            ptrace(PTRACE_CONT,pid,0,0);
        }
    }
    close(mem);
    fprintf(stderr,"[*] sym8 writes total=%ld, dumped symp for [%ld..%ld] -> %s\n",n,START,END,outdir);
    return 0;
}
