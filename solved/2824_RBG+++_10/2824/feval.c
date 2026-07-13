/* feval.c  --  fast range evaluation of F(x) for RBG+++ solver.
 *
 * Computes F(x) = Res_Y( M_R(Y), M_L(x^{s_res} Y) )  for x in [lo, hi),
 * where M_L / M_R are the monic characteristic polynomials of the products
 * prod_{i in pos} W_i^{s_i}  and  prod_{i in neg} W_i^{|s_i|},
 * each W_i a root of the cubic  W^3 + x W - c_i x = 0  over GF(p).
 *
 * p is a 137-bit prime -> 3 x 64-bit limbs.  Arithmetic is Montgomery (R = 2^192).
 * The whole per-point pipeline (square-and-multiply in the cubic ring, power sums,
 * Newton's identities, subresultant Euclid) matches solve.sage's python reference.
 *
 * Build:  gcc -O3 -march=native -fopenmp -shared -fPIC -o feval.so feval.c
 * Call:   via ctypes (see feval.py wrapper).
 *
 * Limitations: side degree D_side = 3^{n_side} must satisfy D_side <= MAXD.
 * With balanced 4+4 splits D_side = 81, well within MAXD.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#ifdef _OPENMP
#include <omp.h>
#endif

typedef unsigned __int128 u128;
typedef uint64_t u64;

#define NL 3            /* limbs (3*64 = 192 >= 137) */
#define MAXD 730        /* max side char-poly degree (3^6 = 729 headroom) */

typedef struct { u64 v[NL]; } fp;   /* Montgomery-domain residue mod p */

/* ---- global modulus context (set once per solve via feval_setup) ---- */
static u64  P[NL];        /* modulus, little-endian limbs */
static u64  NP;           /* -P^{-1} mod 2^64            */
static fp   R2;           /* R^2 mod P (to enter Montgomery domain) */
static fp   ONE;          /* 1 in Montgomery domain */
static fp   INVK[MAXD+1]; /* INVK[k] = 1/k in Montgomery domain (k depends only on P) */

/* ---------- multiprecision helpers on NL-limb little-endian ---------- */
static int geP(const u64 *a){                 /* a >= P ? */
    for(int i=NL-1;i>=0;i--){ if(a[i]!=P[i]) return a[i]>P[i]; }
    return 1;
}
static void subP(u64 *a){                      /* a -= P (assumes a>=P) */
    u128 br=0;
    for(int i=0;i<NL;i++){ u128 t=(u128)a[i]-(P[i]+ (u64)br); a[i]=(u64)t; br=(t>> 127)&1; }
}
/* Montgomery multiplication: r = a*b*R^{-1} mod P  (CIOS) */
static void mont_mul(fp *r,const fp *a,const fp *b){
    u64 t[NL+2]; memset(t,0,sizeof(t));
    for(int i=0;i<NL;i++){
        /* t += a[i]*b */
        u128 carry=0;
        for(int j=0;j<NL;j++){
            u128 s=(u128)a->v[i]*b->v[j] + t[j] + carry;
            t[j]=(u64)s; carry=s>>64;
        }
        u128 s=(u128)t[NL]+carry; t[NL]=(u64)s; t[NL+1]+=(u64)(s>>64);
        /* m = t[0]*NP mod 2^64 ; t += m*P ; t >>= 64 */
        u64 m=(u64)((u128)t[0]*NP);
        carry=0;
        for(int j=0;j<NL;j++){
            u128 s2=(u128)m*P[j] + t[j] + carry;
            t[j]=(u64)s2; carry=s2>>64;
        }
        s=(u128)t[NL]+carry; t[NL]=(u64)s; t[NL+1]+=(u64)(s>>64);
        for(int j=0;j<=NL;j++) t[j]=t[j+1];   /* shift down one limb */
        t[NL+1]=0;
    }
    for(int i=0;i<NL;i++) r->v[i]=t[i];
    /* t may hold an extra top limb in t[NL]; fold by conditional subtract */
    if(t[NL] || geP(r->v)) subP(r->v);
}
static inline void fp_add(fp *r,const fp *a,const fp *b){
    u128 c=0;
    for(int i=0;i<NL;i++){ u128 s=(u128)a->v[i]+b->v[i]+c; r->v[i]=(u64)s; c=s>>64; }
    if(c || geP(r->v)) subP(r->v);
}
static inline void fp_sub(fp *r,const fp *a,const fp *b){
    u128 br=0; u64 tmp[NL];
    for(int i=0;i<NL;i++){ u128 t=(u128)a->v[i]-b->v[i]-(u64)br; tmp[i]=(u64)t; br=(t>>127)&1; }
    if(br){ u128 c=0; for(int i=0;i<NL;i++){ u128 s=(u128)tmp[i]+P[i]+c; tmp[i]=(u64)s; c=s>>64; } }
    for(int i=0;i<NL;i++) r->v[i]=tmp[i];
}
static inline void fp_set0(fp *r){ memset(r->v,0,sizeof(r->v)); }
static inline int  fp_iszero(const fp *a){ return (a->v[0]|a->v[1]|a->v[2])==0; }

/* to/from Montgomery */
static void to_mont(fp *r,const u64 *a){ fp t; memcpy(t.v,a,sizeof(t.v)); mont_mul(r,&t,&R2); }
static void from_mont(u64 *r,const fp *a){ fp one; fp_set0(&one); one.v[0]=1; fp t; mont_mul(&t,a,&one); memcpy(r,t.v,sizeof(t.v)); }

/* modular inverse via Fermat: a^{P-2}.  P-2 supplied as limbs (little-endian). */
static u64 PM2[NL];
static void fp_inv(fp *r,const fp *a){
    fp res=ONE, base=*a;
    for(int i=0;i<NL;i++){
        u64 e=PM2[i];
        for(int b=0;b<64;b++){
            if(e&1) mont_mul(&res,&res,&base);
            mont_mul(&base,&base,&base);
            e>>=1;
        }
    }
    *r=res;
}

/* =====================================================================
 *  cubic-ring elements: [a0,a1,a2] = a0 + a1 W + a2 W^2, with
 *  W^3 = c*x - x*W   (from W^3 + xW - cx = 0).   x, cx are fp (Montgomery).
 * ===================================================================== */
typedef struct { fp a[3]; } cub;

static void cub_mul(cub *r,const cub *A,const cub *B,const fp *x,const fp *cx){
    fp t[5]; for(int i=0;i<5;i++) fp_set0(&t[i]);
    for(int i=0;i<3;i++){
        if(fp_iszero(&A->a[i])) continue;
        for(int j=0;j<3;j++){
            fp p; mont_mul(&p,&A->a[i],&B->a[j]);
            fp_add(&t[i+j],&t[i+j],&p);
        }
    }
    /* reduce W^4 then W^3 */
    for(int d=4; d>=3; d--){
        if(fp_iszero(&t[d])) continue;
        fp tt=t[d]; fp_set0(&t[d]);
        fp p1; mont_mul(&p1,&tt,cx);  fp_add(&t[d-3],&t[d-3],&p1);   /* + cx * W^{d-3} */
        fp p2; mont_mul(&p2,&tt,x);   fp_sub(&t[d-2],&t[d-2],&p2);   /* - x  * W^{d-2} */
    }
    r->a[0]=t[0]; r->a[1]=t[1]; r->a[2]=t[2];
}
/* W^a mod cubic, square-and-multiply */
static void cub_pow(cub *r,u64 a,const fp *x,const fp *cx){
    cub res, base;
    fp_set0(&res.a[0]); res.a[0]=ONE; fp_set0(&res.a[1]); fp_set0(&res.a[2]);
    fp_set0(&base.a[0]); fp_set0(&base.a[1]); base.a[1]=ONE; fp_set0(&base.a[2]); /* W */
    while(a){
        if(a&1) cub_mul(&res,&res,&base,x,cx);
        a>>=1;
        if(a) cub_mul(&base,&base,&base,x,cx);
    }
    *r=res;
}

/* =====================================================================
 *  characteristic polynomial of  prod_i W_i^{a_i}  over the 3 cubic roots.
 *  Returns monic coeffs mc[0..D] (mc[D]=1), degree D = 3^{nitems}.
 *  Power sums:  p_k = trace( (prod rho_i)^k ), rho_i = W_i^{a_i} class,
 *  Newton -> elementary symmetric -> char poly (mc[i] = (-1)^i e_i).
 * ===================================================================== */
/* trace of a cubic-ring element u = u0 + u1 W + u2 W^2 :
 *   tr(1)=3, tr(W)=0, tr(W^2) = -2x  (power sums of roots of W^3+xW-cx).
 *   e1=0, e2=x, e3=cx  =>  p1=0, p2=-2x, so tr = 3 u0 + 0*u1 + (-2x) u2. */
static void ring_trace(fp *out,const cub *u,const fp *x){
    fp three; fp_set0(&three); three.v[0]=3; fp t3; to_mont(&t3,three.v);
    fp r; mont_mul(&r,&u->a[0],&t3);           /* 3*u0 */
    fp two; fp_set0(&two); two.v[0]=2; fp t2; to_mont(&t2,two.v);
    fp m2x; mont_mul(&m2x,x,&t2);              /* 2x   */
    fp term; mont_mul(&term,&u->a[2],&m2x);    /* 2x*u2 */
    fp_sub(&r,&r,&term);                       /* 3u0 - 2x u2 */
    *out=r;
}

static void side_charpoly(fp *mc,int *Dout,
                          const u64 *ai,const fp *cxi,int nitems,
                          const fp *x)
{
    int D=1; for(int i=0;i<nitems;i++) D*=3;
    *Dout=D;
    /* power sums p_1..p_D of the product's conjugates.
       Build incrementally: current running product element 'cur' (=prod rho_i^k step),
       but we need conjugate power sums.  Use the per-factor char polys composed by
       multiplication of conjugate sets -> equivalently accumulate p_k as the trace of
       the k-th power of the product element under the regular representation.
       We mirror the python: for each factor, precompute rho=W^{a}, then the product
       of conjugates; here we accumulate p_k = prod over factors of (their k-th
       power-sum contribution) is NOT separable, so we instead track the running
       product element and take traces of its powers.  */
    /* running product element in the tensor of cubic rings is heavy; instead we use
       the same trick as python _side: multiply the *power-sum generating* data.
       python builds Pp[k] = prod_i tr(rho_i^k-in-its-own-ring) ??? -- no.
       We replicate python exactly: Pp[k] = prod_i ( trace_i(rho_i^k) ) is wrong.
       python: cur *= rho each k, Pp[k]*= trace(cur) per factor with cur in factor i.  */
    /* --- exact replication of python _side_charpoly --- */
    static __thread fp Pp[MAXD+1];
    for(int k=0;k<=D;k++) Pp[k]=ONE;
    for(int f=0; f<nitems; f++){
        cub rho; cub_pow(&rho,ai[f],x,&cxi[f]);
        cub cur; fp_set0(&cur.a[0]); cur.a[0]=ONE; fp_set0(&cur.a[1]); fp_set0(&cur.a[2]);
        for(int k=1;k<=D;k++){
            cub_mul(&cur,&cur,&rho,x,&cxi[f]);
            fp tr; ring_trace(&tr,&cur,x);
            mont_mul(&Pp[k],&Pp[k],&tr);
        }
    }
    /* Newton -> elementary symmetric e[0..D], e[0]=1 */
    static __thread fp e[MAXD+1];
    e[0]=ONE;
    for(int k=1;k<=D;k++){
        fp acc; fp_set0(&acc);
        for(int i=1;i<=k;i++){
            fp term; mont_mul(&term,&e[k-i],&Pp[i]);
            if(i&1) fp_add(&acc,&acc,&term); else fp_sub(&acc,&acc,&term);
        }
        /* e[k] = acc / k  (1/k precomputed) */
        mont_mul(&e[k],&acc,&INVK[k]);
    }
    /* mc[i] = (-1)^i e[i]  (monic, degree D) */
    for(int i=0;i<=D;i++){
        if(i&1){ fp_set0(&mc[i]); fp_sub(&mc[i],&mc[i],&e[i]); }
        else mc[i]=e[i];
    }
}

/* resultant of two univariate polys over GF(p) via Euclidean algorithm.
   a[0..da] high-to-low? We store low-to-high (a[0] constant). Return fp. */
static void poly_norm(fp *a,int *da){ while(*da>0 && fp_iszero(&a[*da])) (*da)--; }

static void resultant(fp *out, fp *A,int da, fp *B,int db){
    /* work on copies, coeffs low..high */
    fp res=ONE;
    fp *a=A; fp *b=B;
    int sgn=0;
    while(db>0){
        /* pseudo/exact division: reduce a mod b (monic-normalize b) */
        /* make b monic */
        fp binv; fp_inv(&binv,&b[db]);
        /* r = a mod b */
        static __thread fp r[2*MAXD+4];
        for(int i=0;i<=da;i++) r[i]=a[i];
        int dr=da;
        for(int i=dr; i>=db; i--){
            if(fp_iszero(&r[i])) continue;
            fp f; mont_mul(&f,&r[i],&binv);      /* leading factor */
            for(int j=0;j<=db;j++){
                fp t; mont_mul(&t,&f,&b[j]);
                fp_sub(&r[i-db+j],&r[i-db+j],&t);
            }
        }
        int ndr=db-1; poly_norm(r,&ndr);
        /* res *= lead(b)^(da-ndr) * (-1)^(da*db) ; then (a,b)=(b,r) */
        int e=da-ndr;
        fp lb=b[db], p=ONE;
        for(int k=0;k<e;k++) mont_mul(&p,&p,&lb);
        mont_mul(&res,&res,&p);
        if((da*db)&1) { fp_set0(&p); fp_sub(&res,&p,&res); }  /* negate */
        /* swap */
        static __thread fp tmp[2*MAXD+4];
        for(int i=0;i<=db;i++) tmp[i]=b[i];
        int dtmp=db;
        for(int i=0;i<=ndr;i++) b[i]=r[i];
        db=ndr;
        for(int i=0;i<=dtmp;i++) a[i]=tmp[i];
        da=dtmp;
        if(fp_iszero(&b[db]) && db==0){ /* r==0 => resultant 0 */
            fp_set0(out); return;
        }
    }
    if(db<0){ fp_set0(out); return; }
    /* b is constant b[0]; res *= b[0]^da */
    fp p=ONE;
    for(int k=0;k<da;k++) mont_mul(&p,&p,&b[0]);
    mont_mul(&res,&res,&p);
    *out=res;
}

/* =====================================================================
 *  public API
 * ===================================================================== */

/* setup modulus.  p_limbs, r2_limbs, pm2_limbs little-endian; np = -p^{-1} mod 2^64 */
void feval_setup(const u64 *p_limbs,const u64 *r2_limbs,const u64 *pm2_limbs,u64 np){
    memcpy(P,p_limbs,sizeof(P));
    NP=np;
    memcpy(PM2,pm2_limbs,sizeof(PM2));
    memcpy(R2.v,r2_limbs,sizeof(R2.v));
    fp one; fp_set0(&one); one.v[0]=1; to_mont(&ONE,one.v);
    /* ONE currently = to_mont(1) but to_mont uses R2 & mont_mul which needs ONE only in fp_inv;
       recompute cleanly: */
    fp t; memcpy(t.v,one.v,sizeof(t.v)); mont_mul(&ONE,&t,&R2);
    /* precompute 1/k for k=1..MAXD (used by Newton's identities) */
    for(int k=1;k<=MAXD;k++){
        fp kk; fp_set0(&kk); kk.v[0]=(u64)k; fp km; to_mont(&km,kk.v);
        fp_inv(&INVK[k],&km);
    }
}

/* evaluate F at x = lo .. hi-1 (ordinary integers), writing results (ordinary ints,
 * NL limbs each) into out[(x-lo)*NL ...].
 * cs_limbs: nitems_total * NL  (the c_i, ordinary ints mod p)
 * s: signed exponents; s_res: the relation's x-exponent.
 */
void feval_range(u64 lo,u64 hi,
                 const u64 *cs_limbs,const long *s,int nitems,long s_res,
                 u64 order_lo,   /* (p-1) low 64 bits, for x^{s_res} exponent reduction sign */
                 u64 *out)
{
    /* split indices by sign */
    int pos_idx[64], neg_idx[64], npos=0, nneg=0;
    long apos[64], aneg[64];
    for(int i=0;i<nitems;i++){
        if(s[i]>0){ pos_idx[npos]=i; apos[npos]=s[i]; npos++; }
        else if(s[i]<0){ neg_idx[nneg]=i; aneg[nneg]=-s[i]; nneg++; }
    }
    long sres=s_res;
    int swap = (sres<0);
    if(swap){ sres=-sres; /* swap pos/neg roles */ }

    #pragma omp parallel for schedule(dynamic, 4096)
    for(long xi=(long)lo; xi<(long)hi; xi++){
        /* x in Montgomery */
        fp x; { u64 xb[NL]={ (u64)xi,0,0 }; to_mont(&x,xb); }
        if(xi==0){ u64 z[NL]={0,0,0}; memcpy(&out[((u64)xi-lo)*NL],z,sizeof(z)); continue; }
        /* cx_i = c_i * x for each factor */
        fp cx[64];
        for(int i=0;i<nitems;i++){ fp c; to_mont(&c,&cs_limbs[(size_t)i*NL]); mont_mul(&cx[i],&c,&x); }

        /* left = pos side, right = neg side (or swapped) */
        int *L = swap? neg_idx : pos_idx; int nL = swap? nneg : npos; long *aL = swap? aneg : apos;
        int *Rr= swap? pos_idx : neg_idx; int nR = swap? npos : nneg; long *aR = swap? apos : aneg;

        u64  aLv[64]; fp cxL[64]; for(int i=0;i<nL;i++){ aLv[i]=(u64)aL[i]; cxL[i]=cx[L[i]]; }
        u64  aRv[64]; fp cxR[64]; for(int i=0;i<nR;i++){ aRv[i]=(u64)aR[i]; cxR[i]=cx[Rr[i]]; }

        static __thread fp ML[MAXD+1], MR[MAXD+1];
        int DL, DR;
        if(nL==0){ DL=1; ML[0]=ONE; { fp z; fp_set0(&z); fp_sub(&ML[0], &z, &ONE);} ML[1]=ONE; } /* Y-1 */
        else side_charpoly(ML,&DL,aLv,cxL,nL,&x);
        if(nR==0){ DR=1; { fp z; fp_set0(&z); fp_sub(&MR[0], &z, &ONE);} MR[1]=ONE; }             /* Y-1 */
        else side_charpoly(MR,&DR,aRv,cxR,nR,&x);

        /* xs = x^{sres} ; substitute Y -> xs*Y into ML:  ML[i] *= xs^{DL-i} */
        fp xs=ONE; { fp b=x; long e=sres; while(e){ if(e&1) mont_mul(&xs,&xs,&b); mont_mul(&b,&b,&b); e>>=1; } }
        static __thread fp MLs[MAXD+1];
        fp pw=ONE; /* xs^0 */
        for(int i=DL;i>=0;i--){ mont_mul(&MLs[i],&ML[i],&pw); mont_mul(&pw,&pw,&xs); }

        fp r; resultant(&r, MR,DR, MLs,DL);   /* sign may differ from python by a unit; roots identical */
        u64 ro[NL]; from_mont(ro,&r);
        memcpy(&out[((u64)xi-lo)*NL], ro, sizeof(ro));
    }
}
