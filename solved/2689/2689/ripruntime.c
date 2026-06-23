// clean 실행, check(0x4013a2)에서 멈춰 런타임 의심 영역 통째로 덤프.
// build: gcc -O2 -o ripruntime ripruntime.c
// run  : ./ripruntime ./bin_5 0101010101010101 bin_5 /host/rip5
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
static unsigned long BRK=0x4013a2;
struct R{unsigned long a,sz;const char*name;};
int main(int argc,char**argv){
    const char*outdir=argv[4];
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
    long orig=ptrace(PTRACE_PEEKTEXT,pid,(void*)BRK,0);
    ptrace(PTRACE_POKETEXT,pid,(void*)BRK,(void*)((orig&~0xffUL)|0xCC));
    ptrace(PTRACE_CONT,pid,0,0);
    waitpid(pid,&st,0);
    if(!WIFSTOPPED(st)){ fprintf(stderr,"not stopped (exit=%d sig=%d)\n",WEXITSTATUS(st),WTERMSIG(st)); return 2; }
    char memp[64]; snprintf(memp,sizeof memp,"/proc/%d/mem",pid); int mem=open(memp,O_RDONLY);
    struct R regs[]={
        {0x205b000,0x2000,"rwe"},        // RWE 세그먼트(런타임 생성 코드 의심)
        {0x404000,0x1000,"data"},         // wrong@404030 correct@404040
        {0x804000,0x1000,"symp"},         // .sym.p 레지스터
        {0x400000,0x6000,"img"},          // 헤더+코드+rodata (즉시값 등)
        {0x1005000,0x56000,"relap"},      // .rela.p (자기수정 추적용)
    };
    char path[256];
    { char c[300]; snprintf(c,sizeof c,"mkdir -p %s",outdir); system(c);}
    for(unsigned i=0;i<sizeof regs/sizeof regs[0];i++){
        char*buf=malloc(regs[i].sz);
        ssize_t g=pread(mem,buf,regs[i].sz,regs[i].a);
        if(g>0){ snprintf(path,sizeof path,"%s/%s.bin",outdir,regs[i].name);
            int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0644); write(fd,buf,g); close(fd);
            fprintf(stderr,"[+] %s @%#lx %#zx bytes\n",regs[i].name,regs[i].a,(size_t)g); }
        free(buf);
    }
    // maps 도 저장
    char mp[64]; snprintf(mp,sizeof mp,"/proc/%d/maps",pid);
    FILE*m=fopen(mp,"r"); snprintf(path,sizeof path,"%s/maps.txt",outdir);
    FILE*o=fopen(path,"w"); char ln[512]; while(fgets(ln,sizeof ln,m))fputs(ln,o);
    fclose(m);fclose(o);
    // RWE 앞부분이 0이 아닌지 즉시 보고
    unsigned char head[64]; pread(mem,head,64,0x205b000);
    int nz=0; for(int i=0;i<64;i++) if(head[i]) nz=1;
    fprintf(stderr,"[*] RWE(0x205b000) head non-zero? %s : ",nz?"YES":"no");
    for(int i=0;i<32;i++) fprintf(stderr,"%02x",head[i]); fprintf(stderr,"\n");
    ptrace(PTRACE_KILL,pid,0,0); return 0;
}
