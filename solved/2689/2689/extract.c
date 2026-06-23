// 선형검출기(slope=249) 기반 secret 복구 + oracle 검증 + byte0 재시도.
// 진짜 비교검출기만 M==249 로 통과 -> echo/오인덱스 배제.
// 출력(stdout): "<hex16> <oracle_exit>"  build: gcc -O2 -o extract extract.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#define RELA 0x1005000UL
#define SLOPE 249
#define SLINV 73   /* 249^{-1} mod 256 */
static long pu(pid_t p,int i){return ptrace(PTRACE_PEEKUSER,p,(void*)offsetof(struct user,u_debugreg[i]),0);}
static void po(pid_t p,int i,unsigned long v){ptrace(PTRACE_POKEUSER,p,(void*)offsetof(struct user,u_debugreg[i]),(void*)v);}
const char*BIN,*AV0;
long do_run(const unsigned char*a8, unsigned long wp, int*ec){
    pid_t pid=fork();
    if(pid==0){ ptrace(PTRACE_TRACEME,0,0,0);
        char arg1[9]; memcpy(arg1,a8,8); arg1[8]=0;
        char*av[]={(char*)AV0,arg1,0}; char*ev[]={"PATH=/usr/bin:/bin",0};
        execve(BIN,av,ev); _exit(127); }
    int st; waitpid(pid,&st,0);
    po(pid,0,wp); po(pid,7,(0x1)|(0xf<<16));
    long n=0; ptrace(PTRACE_CONT,pid,0,0);
    while(1){ waitpid(pid,&st,0);
        if(WIFEXITED(st)){ if(ec)*ec=WEXITSTATUS(st); break;}
        if(WIFSIGNALED(st)){ if(ec)*ec=-1; break;}
        if(WIFSTOPPED(st)){ if(pu(pid,6)&0x1){ n++; po(pid,6,0);} ptrace(PTRACE_CONT,pid,0,0);}
    }
    return n;
}
unsigned long relasz_of(const char*p){ FILE*f=fopen(p,"rb"); if(!f)return 0;
    fseek(f,0x2f30,SEEK_SET); unsigned long v=0; if(fread(&v,8,1,f)){} fclose(f); return v; }
int SENS0[8]={4000,5250,6600,8100,9500,11000,12700,14100};
int NREL0=14647;

// 검출기 후보 addr 에서 byte k 풀기. slope==249 확인 + 검증. 반환 1..255 또는 0.
int probe(unsigned char*secret,int k,unsigned long addr){
    unsigned char a8[8]; for(int i=0;i<8;i++) a8[i]= i<k?secret[i]:1;
    int pa[]={1,3,5,9,17,33,65,129,193};
    for(int pi=0;pi<9;pi++){ int va=pa[pi];
        a8[k]=va;   long ra=do_run(a8,addr,0);
        a8[k]=va+1; long rb=do_run(a8,addr,0);
        if(((int)(ra-rb)&0xff)!=SLOPE) continue;     // 진짜 검출기(slope 249)만
        int cand=(va + (int)((ra%256)*SLINV))&0xff;
        if(cand<1) continue;
        a8[k]=cand; if(do_run(a8,addr,0)==0) return cand;  // 최종 검증 reads=0
    }
    return 0;
}
int OFFS[256]; int NOFF=0;
void mkoffs(){ OFFS[NOFF++]=0; for(int s=8;s<=400;s+=8){ OFFS[NOFF++]=s; OFFS[NOFF++]=-s; } }
int solve_one(unsigned char*secret,int k,double scale){
    int base=(int)(SENS0[k]*scale+0.5);
    for(int oi=0;oi<NOFF;oi++){ int v=probe(secret,k,RELA+(unsigned long)(base+OFFS[oi])*24); if(v)return v; }
    return 0;
}
int try_b0(unsigned char*secret,int b0,double scale){
    secret[0]=b0;
    for(int k=1;k<8;k++){ int v=solve_one(secret,k,scale); if(!v)return -1; secret[k]=v; }
    int ec=-1; do_run(secret,RELA,&ec); return ec;
}
int main(int argc,char**argv){
    BIN=argv[1]; AV0=argv[2]; const char*known=argc>3?argv[3]:0;
    mkoffs();
    unsigned long rsz=relasz_of(BIN); long nrel=rsz/24; double scale=(double)nrel/NREL0;
    fprintf(stderr,"[*] %s nreloc=%ld scale=%.4f\n",BIN,nrel,scale);
    unsigned char secret[8]={0};
    int ok=1; for(int k=0;k<8;k++){ int v=solve_one(secret,k,scale);
        if(!v){ok=0; fprintf(stderr,"  byte%d FAIL\n",k); break;}
        secret[k]=v; fprintf(stderr,"  byte%d=%#04x\n",k,v); }
    int ec=-1; if(ok) do_run(secret,RELA,&ec);
    if(ec!=0){ // byte0 ∈{1,2} 재시도
        for(int b0=1;b0<=2 && ec!=0;b0++){ unsigned char s2[8]={0}; int e=try_b0(s2,b0,scale);
            fprintf(stderr,"  [retry b0=%d] ec=%d\n",b0,e);
            if(e==0){ memcpy(secret,s2,8); ec=0; } }
    }
    char hx[17]; for(int i=0;i<8;i++) sprintf(hx+2*i,"%02x",secret[i]);
    printf("%s %d\n",hx,ec);
    if(known) fprintf(stderr,"[=] known=%s %s\n",known,strcmp(hx,known)==0?"MATCH":"MISMATCH");
    fprintf(stderr,"[=] oracle exit=%d %s\n",ec,ec==0?"OK":"REJECT");
    return 0;
}
