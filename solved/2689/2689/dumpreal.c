// LD_PRELOAD 없이 main 정상 실행, 각 fexecve(execveat)에서 넘기는 memfd(=실제 로딩 파일)를
// ptrace 로 그대로 덤프. main 의 RELA 패치가 적용된 REAL bin 들을 잡는다.
// build: gcc -O2 -o dumpreal dumpreal.c
// run  : ./dumpreal /app/main /app/flag.png /host/realdump
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/stat.h>
static int counter=0;
static const char* OUT;
static void dump_fd(pid_t pid,long fd){
    char src[64]; snprintf(src,sizeof src,"/proc/%d/fd/%ld",pid,fd);
    int in=open(src,O_RDONLY); if(in<0) return;
    char dst[256]; snprintf(dst,sizeof dst,"%s/bin_%d",OUT,counter);
    int out=open(dst,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(out>=0){ char buf[65536]; ssize_t r; off_t tot=0;
        while((r=pread(in,buf,sizeof buf,tot))>0){ if(write(out,buf,r)<0)break; tot+=r; }
        close(out);
        fprintf(stderr,"[+] bin_%d <- pid %d fd %ld (%lld bytes)\n",counter,pid,fd,(long long)tot);
    }
    close(in); counter++;
}
int main(int argc,char**argv){
    OUT=argv[3]?argv[3]:"/host/realdump";
    { char c[300]; snprintf(c,sizeof c,"mkdir -p %s",OUT); if(system(c)){} }
    pid_t pid=fork();
    if(pid==0){ ptrace(PTRACE_TRACEME,0,0,0);
        char*av[]={ argv[1], argv[2], 0 };
        char*ev[]={ "PATH=/usr/bin:/bin", 0 };   // clean: LD_* / COLUMNS 없음
        execve(argv[1],av,ev); _exit(127); }
    int st; waitpid(pid,&st,0);
    ptrace(PTRACE_SETOPTIONS,pid,0,(void*)(PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|
        PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC));
    ptrace(PTRACE_SYSCALL,pid,0,0);
    while(1){
        int status; pid_t w=waitpid(-1,&status,0);
        if(w<0) break;
        if(WIFEXITED(status)||WIFSIGNALED(status)){ if(w==pid) break; else continue; }
        if(WIFSTOPPED(status)){
            int sig=WSTOPSIG(status);
            if(sig==(SIGTRAP|0x80)){
                struct user_regs_struct r;
                if(ptrace(PTRACE_GETREGS,w,0,&r)==0 && r.orig_rax==SYS_execveat){
                    dump_fd(w, (long)r.rdi);   // fexecve 의 fd = 실제 로딩 memfd
                }
            }
            ptrace(PTRACE_SYSCALL,w,0,0);
        }
    }
    fprintf(stderr,"[*] total dumped: %d\n",counter);
    return 0;
}
