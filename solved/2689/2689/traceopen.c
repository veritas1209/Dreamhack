// main 을 도커 기본대로 실행하며 모든 자식의 execve/execveat/openat 경로를 로깅.
// "실행파일을 터치하는 ld.so/파일" 전수 확인용.  build: gcc -O2 -o traceopen traceopen.c
// run  : ./traceopen /app/main /app/flag.png 2>trace.log   (필터: .so / ld- / /app)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>
static void rdstr(pid_t pid,unsigned long addr,char*out,int n){
    int i=0;
    while(i<n-1){
        errno=0; long w=ptrace(PTRACE_PEEKDATA,pid,(void*)(addr+i),0);
        if(errno) break;
        memcpy(out+i,&w,sizeof w);
        int br=0; for(unsigned k=0;k<sizeof w;k++) if(out[i+k]==0){br=1;break;}
        i+=sizeof w; if(br)break;
    }
    out[n-1]=0;
}
int main(int argc,char**argv){
    pid_t pid=fork();
    if(pid==0){ ptrace(PTRACE_TRACEME,0,0,0);
        execv(argv[1],&argv[1]); _exit(127); }
    int st; waitpid(pid,&st,0);
    ptrace(PTRACE_SETOPTIONS,pid,0,(void*)(PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|
        PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC));
    ptrace(PTRACE_SYSCALL,pid,0,0);
    int entry=1; // 대략적 enter/exit 토글은 pid별로 안 하고 openat만 enter에서 읽음
    while(1){
        int status; pid_t w=waitpid(-1,&status,0);
        if(w<0) break;
        if(WIFEXITED(status)||WIFSIGNALED(status)){ if(w==pid) ; continue; }
        if(WIFSTOPPED(status)){
            int sig=WSTOPSIG(status);
            if(sig==(SIGTRAP|0x80)){
                struct user_regs_struct r;
                if(ptrace(PTRACE_GETREGS,w,0,&r)==0){
                    long nr=r.orig_rax; char buf[300];
                    if(nr==SYS_openat){ rdstr(w,r.rsi,buf,sizeof buf);
                        if(strstr(buf,".so")||strstr(buf,"ld-")||strstr(buf,"/app")||strstr(buf,"main"))
                            fprintf(stderr,"[%d] openat %s\n",w,buf); }
                    else if(nr==SYS_execve){ rdstr(w,r.rdi,buf,sizeof buf);
                        fprintf(stderr,"[%d] execve %s\n",w,buf); }
                    else if(nr==SYS_execveat){ rdstr(w,r.rsi,buf,sizeof buf);
                        fprintf(stderr,"[%d] execveat(fd=%lld) %s\n",w,(long long)r.rdi,buf[0]?buf:"<memfd>"); }
                }
            }
            ptrace(PTRACE_SYSCALL,w,0,0);
        }
    }
    return 0;
}
