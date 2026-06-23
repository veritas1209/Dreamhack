// clean 실행으로 main 을 띄우고 _start(e_entry) 에서 멈춰 main-backed 메모리를 덤프.
// LD_PRELOAD 미사용 = anti-debug 트리거 안 건드림. ptrace 는 lyla 체크리스트에 없음.
// build: gcc -O2 -o dump_main_mem dump_main_mem.c
// run  : ./dump_main_mem /app/main /app/flag.png  -> /tmp/main_mem.bin (+ .idx)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>

static unsigned long read_e_entry(const char*p){
    int fd=open(p,O_RDONLY); if(fd<0){perror("open main");exit(1);}
    unsigned char h[64]; if(pread(fd,h,64,0)!=64){perror("read hdr");exit(1);} close(fd);
    if(memcmp(h,"\x7f""ELF",4)){fprintf(stderr,"not ELF\n");exit(1);}
    unsigned long e_entry; memcpy(&e_entry,h+0x18,8); return e_entry;
}

int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: %s /app/main /app/flag.png\n",argv[0]);return 1;}
    const char*mainpath=argv[1];
    unsigned long entry=read_e_entry(mainpath);
    fprintf(stderr,"[*] e_entry=%#lx\n",entry);
    pid_t pid=fork();
    if(pid==0){
        ptrace(PTRACE_TRACEME,0,0,0);
        char*av[]={ (char*)mainpath, argv[2], 0 };   // argv[0]=/app/main (트리거 만족)
        char*ev[]={ "PATH=/usr/bin:/bin", 0 };        // clean env: LD_* / COLUMNS 없음
        execve(mainpath,av,ev);                         // execve via execv? need execve
        _exit(127);
    }
    int st; waitpid(pid,&st,0);                         // execve 직후 stop
    // _start 에 BP
    long orig=ptrace(PTRACE_PEEKTEXT,pid,(void*)entry,0);
    long bp=(orig & ~0xffUL)|0xCC;
    ptrace(PTRACE_POKETEXT,pid,(void*)entry,(void*)bp);
    ptrace(PTRACE_CONT,pid,0,0);
    waitpid(pid,&st,0);
    if(!WIFSTOPPED(st)){ fprintf(stderr,"[!] not stopped at entry, st=%x\n",st); return 2; }
    struct user_regs_struct r; ptrace(PTRACE_GETREGS,pid,0,&r);
    fprintf(stderr,"[*] hit entry rip=%#llx — dumping main-backed memory\n",(unsigned long long)r.rip);
    char mp[64]; snprintf(mp,sizeof mp,"/proc/%d/maps",pid);
    char memp[64]; snprintf(memp,sizeof memp,"/proc/%d/mem",pid);
    FILE*m=fopen(mp,"r"); int mem=open(memp,O_RDONLY);
    FILE*out=fopen("/tmp/main_mem.bin","wb"); FILE*idx=fopen("/tmp/main_mem.idx","w");
    char line[1024]; unsigned long total=0;
    while(fgets(line,sizeof line,m)){
        unsigned long lo,hi; char perm[8]={0};
        if(sscanf(line,"%lx-%lx %4s",&lo,&hi,perm)!=3) continue;
        // main 바이너리 백킹 매핑만 (블롭 포함). 경로가 mainpath 또는 basename 매치
        if(!strstr(line, "main")) continue;
        if(perm[0]!='r') continue;
        unsigned long sz=hi-lo; char*buf=malloc(sz);
        ssize_t got=pread(mem,buf,sz,lo);
        if(got>0){ fwrite(buf,1,got,out); fprintf(idx,"%lx %lx %s",lo,hi,line+ (strchr(line,'/')?(strchr(line,'/')-line):0)); total+=got; }
        free(buf);
    }
    fclose(out); fclose(idx); fclose(m); close(mem);
    fprintf(stderr,"[*] dumped %#lx bytes -> /tmp/main_mem.bin\n",total);
    ptrace(PTRACE_KILL,pid,0,0);
    return 0;
}
