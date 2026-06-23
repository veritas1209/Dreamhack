// sym8(0x8040c8) 에 쓰기 워치포인트. TM 도는 동안 거기 쓰이는 값 시퀀스를 기록.
// 입력↔secret 비교가 이 레지스터로 흐른다. build: gcc -O2 -o tracesym8 tracesym8.c
// run: ./tracesym8 ./bin_5 0101010101010101 bin_5 /host/sym8_5.txt [maxN]
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
static long pu(pid_t p,int i){return ptrace(PTRACE_PEEKUSER,p,(void*)offsetof(struct user,u_debugreg[i]),0);}
static void po(pid_t p,int i,unsigned long v){ptrace(PTRACE_POKEUSER,p,(void*)offsetof(struct user,u_debugreg[i]),(void*)v);}
int main(int argc,char**argv){
    long maxN = argc>5? strtol(argv[5],0,10): 400000;
    unsigned char a8[8]; const char*hx=argv[2];
    for(int i=0;i<8;i++){char t[3]={hx[2*i],hx[2*i+1],0}; a8[i]=strtoul(t,0,16);}
    pid_t pid=fork();
    if(pid==0){ ptrace(PTRACE_TRACEME,0,0,0);
        char arg1[9]; memcpy(arg1,a8,8); arg1[8]=0;
        char*av[]={(char*)argv[3],arg1,0}; char*ev[]={"PATH=/usr/bin:/bin",0};
        execve(argv[1],av,ev); _exit(127); }
    int st; waitpid(pid,&st,0);
    po(pid,0,WP);
    po(pid,7,(0x1)|(0xd<<16)); // L0=1, DR0: rw=01(write) len=11(8byte) => (LEN<<2|RW)=0b1101=0xd at bits16-19
    char memp[64]; snprintf(memp,sizeof memp,"/proc/%d/mem",pid); int mem=open(memp,O_RDONLY);
    FILE*out=fopen(argv[4],"w");
    long n=0;
    ptrace(PTRACE_CONT,pid,0,0);
    while(1){
        waitpid(pid,&st,0);
        if(WIFEXITED(st)||WIFSIGNALED(st)) break;
        if(WIFSTOPPED(st)){
            long dr6=pu(pid,6);
            if(dr6 & 0x1){
                unsigned long v=0; pread(mem,&v,8,WP);
                if(n<maxN) fprintf(out,"%ld %#lx\n",n,v);
                n++;
                po(pid,6,0);
            }
            ptrace(PTRACE_CONT,pid,0,0);
        }
    }
    fclose(out); close(mem);
    fprintf(stderr,"[*] sym8 writes: %ld (logged first %ld)\n",n,maxN<n?maxN:n);
    return 0;
}
