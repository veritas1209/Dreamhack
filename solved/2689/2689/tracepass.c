// reloc[0].r_offset (0x1005000) 에 읽기 워치포인트 → ld.so 가 RELA 테이블을 한 바퀴 돌 때마다 1트랩.
// 패스 수 + 각 패스 시작 시 sym7/sym8/sym16/correct/wrong 상태를 기록.
// build: gcc -O2 -o tracepass tracepass.c
// run: ./tracepass ./bin_0 018d93fe70f1ffa1 bin_0 /host/pass_0c.txt
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
#define RELA0 0x1005000UL
#define SYM7 0x8040b0UL
#define SYM8 0x8040c8UL
#define SYM16 0x804188UL
#define CORRECT 0x404040UL
#define WRONG 0x404030UL
static long pu(pid_t p,int i){return ptrace(PTRACE_PEEKUSER,p,(void*)offsetof(struct user,u_debugreg[i]),0);}
static void po(pid_t p,int i,unsigned long v){ptrace(PTRACE_POKEUSER,p,(void*)offsetof(struct user,u_debugreg[i]),(void*)v);}
static unsigned long rd(int mem,unsigned long a){unsigned long v=0; pread(mem,&v,8,a); return v;}
int main(int argc,char**argv){
    unsigned char a8[8]; const char*hx=argv[2];
    for(int i=0;i<8;i++){char t[3]={hx[2*i],hx[2*i+1],0}; a8[i]=strtoul(t,0,16);}
    pid_t pid=fork();
    if(pid==0){ ptrace(PTRACE_TRACEME,0,0,0);
        char arg1[9]; memcpy(arg1,a8,8); arg1[8]=0;
        char*av[]={(char*)argv[3],arg1,0}; char*ev[]={"PATH=/usr/bin:/bin",0};
        execve(argv[1],av,ev); _exit(127); }
    int st; waitpid(pid,&st,0);
    // DR0 = RELA0, 읽기/쓰기 워치포인트(x86 HW WP 는 read-only 불가, rw=11=read/write 사용), len=8
    po(pid,0,RELA0);
    po(pid,7,(0x1)|(0xf<<16)); // L0=1, rw=11(read/write) len=11(8) => 0b1111=0xf
    char memp[64]; snprintf(memp,sizeof memp,"/proc/%d/mem",pid); int mem=open(memp,O_RDONLY);
    FILE*out=fopen(argv[4],"w");
    long pass=0;
    fprintf(out,"pass : sym7 sym8 sym16 correct wrong\n");
    ptrace(PTRACE_CONT,pid,0,0);
    while(1){
        waitpid(pid,&st,0);
        if(WIFEXITED(st)||WIFSIGNALED(st)){ fprintf(out,"# exit code=%d\n",WEXITSTATUS(st)); break;}
        if(WIFSTOPPED(st)){
            if(pu(pid,6)&0x1){
                unsigned long s7=rd(mem,SYM7),s8=rd(mem,SYM8),s16=rd(mem,SYM16),
                              c=rd(mem,CORRECT),w=rd(mem,WRONG);
                fprintf(out,"%ld : %#lx %#lx %#lx %#lx %#lx\n",pass,s7,s8,s16,c,w);
                pass++;
                po(pid,6,0);
            }
            ptrace(PTRACE_CONT,pid,0,0);
        }
    }
    fclose(out); close(mem);
    fprintf(stderr,"[*] passes=%ld\n",pass);
    return 0;
}
