#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "boxes.h"
// Per H: precompute each pair's allowed-V mask as a function decomposable by L via rotation.
// General pair (members may be in different blocks A,B):
//   cond: base_A[(V+aa)]-aa == base_B[(V+ab)]-ab, aa=(L+DA)&255, ab=(L+DB)&255.
//   Let x=(V+aa)&255 (index into A). Then V=(x-aa). (V+ab)=(x-aa+ab)=(x+(ab-aa))=(x+delta)&255.
//   cond: base_A[x]-aa == base_B[(x+delta)&255]-ab  => base_A[x]-base_B[(x+delta)&255] == aa-ab = -delta.
//   delta=(DB-DA)&255 const; target=(-delta)&255 const. So allowed-x set X_AB (depends on blocks A,B
//   and delta) is INDEPENDENT of L. V=(x-aa)&255 => Vmask = rotr(Xmask, aa). aa=(L+DA)&255.
//   So Vmask(L)=rotr(Xmask_{A,B}, (L+DA)&255).
// Blocks A=(L+DA)>>8, B=(L+DB)>>8 depend on L (carry). Each in {gA0,gA0+1},{gB0,gB0+1}.
// Precompute Xmask for the (<=4) block-combos per pair. Per L select combo, rotate, AND.
static inline void rotr256(const uint64_t*in,int s,uint64_t*out){
    s&=255;uint64_t res[4]={0,0,0,0};
    for(int w=0;w<4;w++){uint64_t lo=in[w];int db=(w*64 - s)&255;int dw=(db>>6)&3,bb=db&63;res[dw]|=lo<<bb;if(bb)res[(dw+1)&3]|=lo>>(64-bb);}
    out[0]=res[0];out[1]=res[1];out[2]=res[2];out[3]=res[3];
}
static int NPAIR;static uint32_t PA[8192],PB[8192],P0;static int DA[8192],DB[8192],DELTA[8192];
static void build_base(int b,int c,int d,unsigned char*o){for(int X=0;X<256;X++){int i=s1[X];i=s2[(i+b)&255];i=s3[(i+c)&255];i=s4[(i+d)&255];i=r[i];i=(S4[i]-d)&255;i=(S3[i]-c)&255;i=(S2[i]-b)&255;o[X]=S1[i];}}
// Xmask per pair per (selA,selB) in {0,1}^2
static uint64_t XM[8192][2][2][4];
int main(int argc,char**argv){
    FILE*f=fopen(argv[1],"r");if(fscanf(f,"%d",&NPAIR)!=1)return 1;if(fscanf(f,"%u",&P0)!=1)return 1;
    uint32_t maxpos=0;for(int i=0;i<NPAIR;i++){unsigned a,b;if(fscanf(f,"%u %u",&a,&b)!=2)return 1;PA[i]=a;PB[i]=b;if(a>maxpos)maxpos=a;if(b>maxpos)maxpos=b;}
    fclose(f);
    uint64_t Hs=strtoull(argv[2],0,10),He=strtoull(argv[3],0,10);
    int span=maxpos-P0;int nblk=(255+span)/256+2;
    for(int i=0;i<NPAIR;i++){DA[i]=PA[i]-P0;DB[i]=PB[i]-P0;DELTA[i]=(DB[i]-DA[i])&255;}
    unsigned char (*BT)[256]=malloc(sizeof(unsigned char[256])*nblk);
    int GA0[8192],GB0[8192];for(int i=0;i<NPAIR;i++){GA0[i]=DA[i]>>8;GB0[i]=DB[i]>>8;}
    for(uint64_t H=Hs;H<He;H++){
        for(int k=0;k<nblk;k++){uint64_t Hk=(H+k)&0xFFFFFF;build_base(Hk&255,(Hk>>8)&255,(Hk>>16)&255,BT[k]);}
        for(int i=0;i<NPAIR;i++){
            int delta=DELTA[i],target=(-delta)&255;
            for(int sa=0;sa<2;sa++)for(int sb=0;sb<2;sb++){
                int gA=GA0[i]+sa,gB=GB0[i]+sb;
                uint64_t m[4]={0,0,0,0};
                if(gA<nblk&&gB<nblk){const unsigned char*bA=BT[gA];const unsigned char*bB=BT[gB];
                    for(int x=0;x<256;x++) if(((bA[x]-bB[(x+delta)&255])&255)==target) m[x>>6]|=1ULL<<(x&63);}
                XM[i][sa][sb][0]=m[0];XM[i][sa][sb][1]=m[1];XM[i][sa][sb][2]=m[2];XM[i][sa][sb][3]=m[3];
            }
        }
        for(int L=0;L<256;L++){
            uint64_t acc[4]={~0ULL,~0ULL,~0ULL,~0ULL};int empty=0;
            for(int i=0;i<NPAIR;i++){
                int ta=L+DA[i],tb=L+DB[i];int aa=ta&255;
                int sa=(ta>>8)-GA0[i],sb=(tb>>8)-GB0[i];
                if(sa<0||sa>1||sb<0||sb>1)continue;
                uint64_t vm[4];rotr256(XM[i][sa][sb],aa,vm);
                acc[0]&=vm[0];acc[1]&=vm[1];acc[2]&=vm[2];acc[3]&=vm[3];
                if(!(acc[0]|acc[1]|acc[2]|acc[3])){empty=1;break;}
            }
            if(!empty){uint32_t nonce=(uint32_t)(((H<<8)|L)-P0);printf("CANDIDATE nonce=%u H=%llu L=%d\n",nonce,(unsigned long long)H,L);fflush(stdout);}
        }
    }
    return 0;
}
