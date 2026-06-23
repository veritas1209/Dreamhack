// run bin clean (NO LD_*, argv0=bin_N), break at main(0x4011cb)=로드/패치 완료 후,
// 키 즉시값창(0x401286,32B)+expected(0x4013c3,8B) 덤프
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
static unsigned long KEY=0x401286, EXP=0x4013c3;
int main(int argc,char**argv){
    unsigned long BRK = (argc>4)? strtoul(argv[4],0,16) : 0x4013a2;
    unsigned char a8[8]; const char*hx=argv[2];
    for(int i=0;i<8;i++){char t[3]={hx[2*i],hx[2*i+1],0}; a8[i]=strtoul(t,0,16);}
    pid_t pid=fork();
    if(pid==0){
        ptrace(PTRACE_TRACEME,0,0,0);
        char arg1[9]; memcpy(arg1,a8,8); arg1[8]=0;
        char*av[]={ (char*)argv[3], arg1, 0 };
        char*ev[]={ "PATH=/usr/bin:/bin", 0 };
        execve(argv[1],av,ev); _exit(127);
    }
    int st; waitpid(pid,&st,0);
    if(BRK==0){ // run-to-exit 모드: 종료코드만
        ptrace(PTRACE_CONT,pid,0,0);
        while(1){ waitpid(pid,&st,0);
            if(WIFEXITED(st)){ printf("exit=%d\n",WEXITSTATUS(st)); return 0; }
            if(WIFSIGNALED(st)){ printf("signal=%d\n",WTERMSIG(st)); return 0; }
            ptrace(PTRACE_CONT,pid,0,0); }
    }
    long orig=ptrace(PTRACE_PEEKTEXT,pid,(void*)BRK,0);
    ptrace(PTRACE_POKETEXT,pid,(void*)BRK,(void*)((orig&~0xffUL)|0xCC));
    ptrace(PTRACE_CONT,pid,0,0);
    waitpid(pid,&st,0);
    if(!WIFSTOPPED(st)){ fprintf(stderr,"not stopped (exit=%d sig=%d)\n",WEXITSTATUS(st),WTERMSIG(st)); return 2; }
    char memp[64]; snprintf(memp,sizeof memp,"/proc/%d/mem",pid); int mem=open(memp,O_RDONLY);
    unsigned char kb[32],exp[8];
    if(pread(mem,kb,32,KEY)!=32||pread(mem,exp,8,EXP)!=8){fprintf(stderr,"pread fail\n");return 3;}
    printf("keyblob="); for(int i=0;i<32;i++)printf("%02x",kb[i]);
    printf(" exp=");     for(int i=0;i<8;i++) printf("%02x",exp[i]); printf("\n");
    ptrace(PTRACE_KILL,pid,0,0); return 0;
}
