// 지정 VA 에 read/write 워치포인트 → 트랩 횟수 카운트 (루프 구간 매핑용).
// reloc[i] 주소 = 0x1005000 + i*24. 여러 i 를 찍어 읽힌 횟수로 루프 구간 발견.
// build: gcc -O2 -o countread countread.c
// run: ./countread ./bin_0 018d93fe70f1ffa1 bin_0 0x1005000
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
static long pu(pid_t p,int i){return ptrace(PTRACE_PEEKUSER,p,(void*)offsetof(struct user,u_debugreg[i]),0);}
static void po(pid_t p,int i,unsigned long v){ptrace(PTRACE_POKEUSER,p,(void*)offsetof(struct user,u_debugreg[i]),(void*)v);}
int main(int argc,char**argv){
    unsigned long WP=strtoul(argv[4],0,16);
    unsigned char a8[8]; const char*hx=argv[2];
    for(int i=0;i<8;i++){char t[3]={hx[2*i],hx[2*i+1],0}; a8[i]=strtoul(t,0,16);}
    pid_t pid=fork();
    if(pid==0){ ptrace(PTRACE_TRACEME,0,0,0);
        char arg1[9]; memcpy(arg1,a8,8); arg1[8]=0;
        char*av[]={(char*)argv[3],arg1,0}; char*ev[]={"PATH=/usr/bin:/bin",0};
        execve(argv[1],av,ev); _exit(127); }
    int st; waitpid(pid,&st,0);
    po(pid,0,WP); po(pid,7,(0x1)|(0xf<<16)); // rw=11 len=8
    long n=0;
    ptrace(PTRACE_CONT,pid,0,0);
    while(1){
        waitpid(pid,&st,0);
        if(WIFEXITED(st)||WIFSIGNALED(st)){ printf("%#lx reads=%ld exit=%d\n",WP,n,WEXITSTATUS(st)); break;}
        if(WIFSTOPPED(st)){ if(pu(pid,6)&0x1){ n++; po(pid,6,0);} ptrace(PTRACE_CONT,pid,0,0);}
    }
    return 0;
}
