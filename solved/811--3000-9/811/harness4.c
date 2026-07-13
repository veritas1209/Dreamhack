// harness.c -- map -3000.exe, register .pdata, hook terminators, run cipher.
// build: x86_64-w64-mingw32-gcc -O2 harness.c -o harness.exe
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>

static unsigned char* gbase;
typedef void (*enc_t)(void* ctx, void* blk);
static enc_t ENC; static void* CTX;
typedef void (*op_t)(void*,void*,unsigned long long);
static op_t OP;
static jmp_buf JB;
static void (*real_cxxthrow)(void*,void*);
static int throwlog=0;

static int hx(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static void hex2b(const char*h,unsigned char*o,int n){for(int i=0;i<n;i++)o[i]=(hx(h[2*i])<<4)|hx(h[2*i+1]);}
static void b2hex(const unsigned char*b,int n,char*o){const char*d="0123456789abcdef";for(int i=0;i<n;i++){o[2*i]=d[b[i]>>4];o[2*i+1]=d[b[i]&15];}o[2*n]=0;}
static const char* strip0(const char*s){while(*s=='0'&&*(s+1))s++;return s;}

// ---- hooked terminators (ms_abi is default on mingw-w64 x64) ----
static void my_exit(int c){ printf("[HOOK] exit(%d)\n",c); fflush(stdout); longjmp(JB,100+(c&0xff)); }
static void my_abort(void){ printf("[HOOK] abort()\n"); fflush(stdout); longjmp(JB,2); }
static void my_terminate(void){ printf("[HOOK] terminate()\n"); fflush(stdout); longjmp(JB,3); }
static void my_invalid(const wchar_t*a,const wchar_t*b,const wchar_t*c,unsigned d,uintptr_t e){ (void)a;(void)b;(void)c;(void)d;(void)e; printf("[HOOK] invalid_parameter\n"); fflush(stdout); longjmp(JB,4); }
static void my_xlength(const char*s){ printf("[HOOK] _Xlength_error(%s)\n",s?s:"?"); fflush(stdout); longjmp(JB,5); }
static void my_xbadalloc(void){ printf("[HOOK] _Xbad_alloc\n"); fflush(stdout); longjmp(JB,6); }
static void my_purecall(void){ printf("[HOOK] purecall\n"); fflush(stdout); longjmp(JB,7); }
static void my_cxxthrow(void*o,void*i){
    ULONG_PTR p[4];
    p[0]=0x19930520;            // EH_MAGIC_NUMBER1
    p[1]=(ULONG_PTR)o;          // exception object
    p[2]=(ULONG_PTR)i;          // ThrowInfo
    p[3]=(ULONG_PTR)gbase;      // throw image base (the fix)
    if(throwlog++<3){printf("[HOOK] raise throwinfo=%p base=%p\n",i,(void*)gbase);fflush(stdout);}
    RaiseException(0xE06D7363, EXCEPTION_NONCONTINUABLE, 4, p);
}

static FARPROC hookFor(const char* nm, FARPROC real){
    if(!strcmp(nm,"exit")||!strcmp(nm,"_exit")||!strcmp(nm,"_Exit")||!strcmp(nm,"quick_exit")) return (FARPROC)my_exit;
    if(!strcmp(nm,"abort")) return (FARPROC)my_abort;
    if(strstr(nm,"terminate")) return (FARPROC)my_terminate;
    if(strstr(nm,"invalid_parameter")) return (FARPROC)my_invalid;
    if(!strcmp(nm,"_Xlength_error")) return (FARPROC)my_xlength;
    if(!strcmp(nm,"_Xbad_alloc")) return (FARPROC)my_xbadalloc;
    if(!strcmp(nm,"_purecall")) return (FARPROC)my_purecall;
    if(!strcmp(nm,"_CxxThrowException")){ real_cxxthrow=(void(*)(void*,void*))real; return (FARPROC)my_cxxthrow; }
    return real;
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep){
    DWORD code=ep->ExceptionRecord->ExceptionCode;
    static int ncpp=0,noth=0;
    if(code==0xE06D7363){ if(ncpp<3){printf("[veh] C++ throw #%d at %p\n",ncpp,ep->ExceptionRecord->ExceptionAddress);fflush(stdout);} ncpp++; return EXCEPTION_CONTINUE_SEARCH; }
    if(noth<12){printf("[veh] EXC %08lx at %p (cpp=%d)\n",(unsigned long)code,ep->ExceptionRecord->ExceptionAddress,ncpp);fflush(stdout);} noth++;
    return EXCEPTION_CONTINUE_SEARCH;
}

static void* mapPE(const char* path){
    FILE* f=fopen(path,"rb"); if(!f){printf("ERR open\n");return NULL;}
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char* raw=malloc(sz); fread(raw,1,sz,f); fclose(f);
    IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)raw;
    IMAGE_NT_HEADERS64* nt=(IMAGE_NT_HEADERS64*)(raw+dos->e_lfanew);
    SIZE_T imgsz=nt->OptionalHeader.SizeOfImage; ULONGLONG want=nt->OptionalHeader.ImageBase;
    unsigned char* base=VirtualAlloc((LPVOID)want,imgsz,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    if(!base) base=VirtualAlloc(NULL,imgsz,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    if(!base){printf("ERR valloc\n");return NULL;}
    memcpy(base,raw,nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sec=IMAGE_FIRST_SECTION(nt);
    for(int i=0;i<nt->FileHeader.NumberOfSections;i++) if(sec[i].SizeOfRawData) memcpy(base+sec[i].VirtualAddress,raw+sec[i].PointerToRawData,sec[i].SizeOfRawData);
    ULONGLONG delta=(ULONGLONG)base-want;
    if(delta){ IMAGE_DATA_DIRECTORY rd=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if(rd.Size){ unsigned char* p=base+rd.VirtualAddress,*end=p+rd.Size;
            while(p<end){ IMAGE_BASE_RELOCATION* br=(IMAGE_BASE_RELOCATION*)p; if(!br->SizeOfBlock)break;
                int cnt=(br->SizeOfBlock-sizeof(*br))/2; WORD* e=(WORD*)(p+sizeof(*br));
                for(int k=0;k<cnt;k++) if((e[k]>>12)==IMAGE_REL_BASED_DIR64){ *(ULONGLONG*)(base+br->VirtualAddress+(e[k]&0xfff))+=delta; }
                p+=br->SizeOfBlock; } } }
    IMAGE_DATA_DIRECTORY id=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(id.Size){ IMAGE_IMPORT_DESCRIPTOR* imp=(IMAGE_IMPORT_DESCRIPTOR*)(base+id.VirtualAddress);
        for(;imp->Name;imp++){ char* dll=(char*)(base+imp->Name); HMODULE h=LoadLibraryA(dll); if(!h)printf("ERR loadlib %s\n",dll);
            ULONGLONG* oft=(ULONGLONG*)(base+(imp->OriginalFirstThunk?imp->OriginalFirstThunk:imp->FirstThunk));
            ULONGLONG* ft=(ULONGLONG*)(base+imp->FirstThunk);
            for(;*oft;oft++,ft++){ FARPROC pr; const char* nm="";
                if(*oft & 0x8000000000000000ULL){ pr=GetProcAddress(h,(LPCSTR)(*oft&0xffff)); }
                else { IMAGE_IMPORT_BY_NAME* ibn=(IMAGE_IMPORT_BY_NAME*)(base+(*oft&0x7fffffff)); nm=ibn->Name; pr=GetProcAddress(h,nm); }
                *ft=(ULONGLONG)hookFor(nm,pr);
            } } }
    IMAGE_DATA_DIRECTORY ed=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if(ed.Size){ RUNTIME_FUNCTION* rf=(RUNTIME_FUNCTION*)(base+ed.VirtualAddress); DWORD n=ed.Size/sizeof(RUNTIME_FUNCTION);
        if(!RtlAddFunctionTable(rf,n,(DWORD64)base)) printf("WARN AddFunctionTable failed\n"); else printf("[pdata %lu entries registered]\n",(unsigned long)n); }
    // NOTE: do NOT touch security cookie (0xd008) -- file default is self-consistent.
    gbase=base; return base;
}
static void initCtx(){ ((void(*)(void))(gbase+0x1000))(); }
static int encAt(int p,const unsigned char* in,unsigned char* out){
    unsigned char junk[16]; memset(junk,0,16);
    if(setjmp(JB)){ return 0; }
    initCtx(); for(int k=0;k<p;k++) ENC(CTX,junk); memcpy(out,in,16); ENC(CTX,out); return 1;
}
static int nameAt(int p,char* out){
    unsigned char junk[16]; memset(junk,0,16);
    if(setjmp(JB)){ strcpy(out,"<exc>"); return 0; }
    initCtx(); for(int k=0;k<=p;k++) ENC(CTX,junk);
    unsigned long long q8=*(unsigned long long*)((char*)CTX+8),q0=*(unsigned long long*)((char*)CTX+0);
    sprintf(out,"%llx%llx",q8,q0); return 1;
}

const char* K1pt[11]={"433a5c615c496b327a77455148667763","657059794e476642353159626d777841","736352757a4f6c384735554242427069","41383459724e627542684f776338666a","4f574f724f7764385337426131366a37","70474c6f753353487656357574673739","62673136714d54536c34663238675a6c","32436550767a5a61714c586a34737872","76584663716747784b68315a58667542","65435474326e6c6c5a704b4b674f4178","4d6936336a4f5a675738326b2e657865"};
const char* K1ct[11]={"09a844691b4017ea397f17fdcd0b7c83","ee61d286a83144b7df1f6c856cb079b6","45a75ecb1e1579d7a16cb723a7032d8b","75d956fcf7d60975cf1a6f2c4d2149cf","250c43aa15ea91c7faf05bb7a6e96c82","c3f2e4506c350667bb42cbbb317ca107","c5329bfa5319dca6e821f55141ae47aa","044ea4ec3ad3925a5495d9b11bc010c9","9dea76fed44c780b7c01811578c79c97","eb3accc715a4addc0c9f43fa34b51fa9","c51575a7212a9e567f861ace2aa5517d"};
const char* CH[][2]={
{"2ac847ee6b4ac9fcff68f59c2f8673ba","4628f5cbb34b474a2b29339d9c6ab94d"},{"2e3cf890688cac0452de8a75d90e44a8","6f39adabc6c5f9a12ddfa9c12da822c6"},
{"5dfb005def07e285c215b963a99b039b","2e67658010f91a1b74f704b9663ea161"},{"69c11b1ae97620a29c3fc3afc501fec0","246afd961f40ee7f25c290203d881715"},
{"69ce2693185f136d5515ed1e6b7e353b","ec2cb4d54b5f7e60c71d3378f2bcb32e"},{"78b1acfd1b24f5b1ce0dd10840c57c3c","da6c494a6800e40bce51d3f94b43e596"},
{"804fb7c2d9cdb5c9c782d4325e2b6bfa","aabbe164a3bb0886069de12990f862f0"},{"82bf7701b9ef6b8152bb829700b514ed","26a50df51c71aefe1521d7fa8b3e5820"},
{"83cd6a4db43ba0e6529aea4e66e9b8a0","ce8d4bb035f36b8d105184a5179455a6"},{"067462ef3031db357158baef573cc1b6","ca4a30465f9ad07fa7e2bad814be93dd"},
{"b06943e12cc3891bbd0fe2723d76200d","849acb5deb38a287f732dc218f51f54f"},{"b6a3f9ec2c372f287f27b4a4076a439c","dc382e3b4f2930d9c34bc1d22f8778ca"},
{"c36a029d88b3e7f28f5735cbbfca209f","e474cfd68cd7f795953bb53bd5033706"},{"c36ad652dfd883a95378f0790346f8e3","f9d21663a681cc9bce9d9b79430fcc19"},
{"d9b00993afdea0237eef7ff92b812bc7","d70f519b4429dcb833b6095cf2ea7284"},{"db56d0aff495c4e635fcdbd911139e5e","e55053221442a864ce7406581f5633c1"},
{"e878601474359131c5e2be1e252cd753","782c91b46457edec1aeef36e2f3ca509"},{"ec88acecd0e01246626855c4838b1a0b","fdc8ca63628e153a529303b23d4536d1"},
{"f0f3480ce4fcfd385ca657e0959f5dec","236e4aab1b9fc01778487393fd69c9b9"}};
#define NCH 19
#define MAXP 30

int main(int argc,char**argv){
    setvbuf(stdout,NULL,_IONBF,0);
    AddVectoredExceptionHandler(1,veh);
    const char* path=argc>1?argv[1]:"-3000.exe";
    if(!mapPE(path)) return 1;
    ENC=(enc_t)(gbase+0x1fb0); CTX=(void*)(gbase+0xd9e8); OP=(op_t)(gbase+0x1ed0);
    printf("MAPPED base=%p\n",(void*)gbase);

    printf("=== SELFTEST ===\n");
    int pass=1;
    if(setjmp(JB)==0){
        initCtx(); printf("[init done]\n");
        unsigned char blk[16]; char nm[64];
        for(int p=0;p<11;p++){
            hex2b(K1pt[p],blk,16); ENC(CTX,blk);
            char got[33]; b2hex(blk,16,got);
            unsigned long long q8=*(unsigned long long*)((char*)CTX+8),q0=*(unsigned long long*)((char*)CTX+0);
            sprintf(nm,"%llx%llx",q8,q0);
            int ok=!strcmp(got,K1ct[p]); if(!ok)pass=0;
            printf("p%-2d ct=%s %s name=%s\n",p,got,ok?"OK":"BAD",nm);
        }
    } else { printf("[SELFTEST aborted by hook]\n"); pass=0; }
    printf("SELFTEST %s\n",pass?"PASS":"FAIL");
    if(!pass){ printf("=== stop (fix selftest first) ===\n"); return 0; }

    static unsigned char K[320][16];
    if(setjmp(JB)){ printf("[exc]\n"); return 0; }
    initCtx(); memcpy(K[0],CTX,16);
    for(int m=1;m<320;m++){ OP(CTX,CTX,10); memcpy(K[m],CTX,16); }
    printf("Kcheck %s\n", *(unsigned long long*)(K[16]+0)==0xc215b963a99b039bULL?"OK":"?");

    unsigned char TB[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    char hh[33];

    // (1) ctx-dependence: op4/6/8 on TB at K[0],K[16],K[32]
    printf("=== CTX DEPENDENCE ===\n");
    for(int t=0;t<3;t++){ int tag=(int[]){4,6,8}[t];
        for(int ki=0; ki<3; ki++){ int kk=(int[]){0,16,32}[ki];
            unsigned char b[16]; memcpy(b,TB,16);
            memcpy((char*)CTX,K[kk],16); OP(CTX,b,tag);
            b2hex(b,16,hh); printf("op%d @K[%d] = %s\n",tag,kk,hh);
        }
    }
    // (2) period: smallest k with op^k(TB)==TB (ctx fixed at K[0])
    printf("=== PERIOD (ctx=K[0]) ===\n");
    for(int t=0;t<3;t++){ int tag=(int[]){4,6,8}[t];
        unsigned char b[16]; memcpy(b,TB,16); int found=0;
        for(int k=1;k<=1024;k++){ memcpy((char*)CTX,K[0],16); OP(CTX,b,tag);
            if(!memcmp(b,TB,16)){ printf("op%d period=%d\n",tag,k); found=1; break; } }
        if(!found) printf("op%d period>1024\n",tag);
    }
    // (3) diffusion at K[0]: op(0) and op(e_i)^op(0)
    printf("=== DIFFUSION (ctx=K[0]) ===\n");
    for(int t=0;t<3;t++){ int tag=(int[]){4,6,8}[t];
        unsigned char z[16]={0},o0[16]; memcpy(o0,z,16);
        memcpy((char*)CTX,K[0],16); OP(CTX,o0,tag);
        b2hex(o0,16,hh); printf("op%d(0)=%s\n",tag,hh);
        for(int i=0;i<16;i++){ unsigned char b[16]={0}; b[i]=0x01;
            memcpy((char*)CTX,K[0],16); OP(CTX,b,tag);
            for(int j=0;j<16;j++) b[j]^=o0[j];
            b2hex(b,16,hh); printf("op%d d[%2d]=%s\n",tag,i,hh);
        }
    }
    printf("=== END ===\n"); return 0;
}
