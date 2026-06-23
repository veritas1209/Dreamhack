// TM 실행 중 RWE(0x205b000)에 깔리는 코드를 시계열로 캡처.
// HW 실행 BP 를 RWE 시작에 걸고, 트랩마다 RWE 페이지를 덤프 + rbx/rip 기록.
// build: gcc -O2 -o ripcode ripcode.c
// run  : ./ripcode ./bin_5 0101010101010101 bin_5 /host/code5
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
#include <sys/uio.h>

#define RWE 0x205b000UL
static long peekuser(pid_t p,int idx){ return ptrace(PTRACE_PEEKUSER,p,(void*)offsetof(struct user,u_debugreg[idx]),0); }
static void pokeuser(pid_t p,int idx,unsigned long v){ ptrace(PTRACE_POKEUSER,p,(void*)offsetof(struct user,u_debugreg[idx]),(void*)v); }

int main(int argc,char**argv){
    const char*outdir=argv[4];
    { char c[300]; snprintf(c,sizeof c,"mkdir -p %s",outdir); if(system(c)){} }
    unsigned char a8[8]; const char*hx=argv[2];
    for(int i=0;i<8;i++){char t[3]={hx[2*i],hx[2*i+1],0}; a8[i]=strtoul(t,0,16);}
    pid_t pid=fork();
    if(pid==0){ ptrace(PTRACE_TRACEME,0,0,0);
        char arg1[9]; memcpy(arg1,a8,8); arg1[8]=0;
        char*av[]={(char*)argv[3],arg1,0};
        char*ev[]={"PATH=/usr/bin:/bin",0};
        execve(argv[1],av,ev); _exit(127); }
    int st; waitpid(pid,&st,0);
    // RWE 에 실행 HW BP (DR0=RWE, DR7 L0 + len1 rw=00(exec))
    pokeuser(pid,0,RWE);
    pokeuser(pid,7,0x1);   // L0=1, DR0 type=00(exec) len=00
    char memp[64]; snprintf(memp,sizeof memp,"/proc/%d/mem",pid); int mem=open(memp,O_RDONLY);
    char idxp[300]; snprintf(idxp,sizeof idxp,"%s/log.txt",outdir); FILE*log=fopen(idxp,"w");
    int hits=0, lastdump=-1;
    ptrace(PTRACE_CONT,pid,0,0);
    while(1){
        waitpid(pid,&st,0);
        if(WIFEXITED(st)||WIFSIGNALED(st)) break;
        if(WIFSTOPPED(st)){
            struct user_regs_struct r; ptrace(PTRACE_GETREGS,pid,0,&r);
            long dr6=peekuser(pid,6);
            if(dr6 & 0x1){ // DR0 hit = RWE 실행
                // RWE 페이지(0x1000) 덤프 — 내용이 직전과 다르면 파일로
                unsigned char buf[0x1000];
                if(pread(mem,buf,sizeof buf,RWE)==sizeof buf){
                    // 비0 바이트 수
                    int nz=0; for(int i=0;i<0x1000;i++) if(buf[i]) nz++;
                    if(hits<200){ // 처음 200개 트랩만 페이지 저장(폭주 방지)
                        char fp[320]; snprintf(fp,sizeof fp,"%s/rwe_%04d.bin",outdir,hits);
                        int fd=open(fp,O_WRONLY|O_CREAT|O_TRUNC,0644); if(fd>=0){ if(write(fd,buf,0x1000)){} close(fd);}
                    }
                    fprintf(log,"hit %d rip=%llx rbx=%llx rax=%llx nz=%d\n",hits,
                        (unsigned long long)r.rip,(unsigned long long)r.rbx,(unsigned long long)r.rax,nz);
                }
                hits++;
                pokeuser(pid,6,0);
            }
            ptrace(PTRACE_CONT,pid,0,0);
        }
    }
    fclose(log); close(mem);
    fprintf(stderr,"[*] RWE 실행 트랩 %d회, 덤프 %s/rwe_*.bin (처음 200개)\n",hits,outdir);
    return 0;
}
