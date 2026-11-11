#!/usr/bin/env python3
"""vmpcheck.py — 判断 .ncx 里的函数是否真被 VMP 虚拟化

判据（按可靠性排序）：
  ① 解出 .ncx 明文 → 找函数序言
     · 普通编译：大量 `sub sp,sp,#N` + `stp x29,x30,[sp,#M]`
     · VMP 后：函数体变成「VM 帧 sub sp,#0xc0 级」+ bl 解释器，
       原算法的循环/查表/判断指令全部消失
  ② 解释器特征：VMP 生成的 runtime 会有一大段分派循环
     （ldrb w?, [x?, x?] + br x? 或 casel 风格跳转表）
  ③ 体积比：VMP 后单函数 .o 涨 10~20 倍（nox 实测 1280→22720）

用法: python3 vmpcheck.py <libnc.so> <apk>

⚠️ 2026-11-11 修正：下面②③两条判据在「有/无 VMP 两版都被锁箱」时会失效 ——
   · `.ncx` 大小会**反向**（实测无 VMP 版反而大 240B）
   · so 里的目标常量熵高，有锁箱就搜不到，跟 VMP 无关
   可靠判据只有两条：
     · `RUST_LOG=amice=debug` 里 VmVirtualize 是否出现过
     · 对照组 `.text` / `.rodata` 体积差
   详见 docs/so层防御/VMP接入交接-2026-11-11.md §4.3.1。
本脚本用于「单个产物自查」——解出 .ncx 看函数序言是否符合 VMP wrapper 特征。
"""
import struct, zlib, hashlib, hmac, sys, re, math
from collections import Counter

def sect(so):
    shoff=struct.unpack_from('<Q',so,0x28)[0]; shent=struct.unpack_from('<H',so,0x3a)[0]
    shnum=struct.unpack_from('<H',so,0x3c)[0]; shstr=struct.unpack_from('<H',so,0x3e)[0]
    sh=lambda k: struct.unpack_from('<IIQQQQIIQQ',so,shoff+k*shent)
    st=sh(shstr)[4]; out={}
    for k in range(shnum):
        s=sh(k); nm=so[st+s[0]:so.index(b'\0',st+s[0])].decode('latin1')
        out[nm]={'off':s[4],'size':s[5],'addr':s[3]}
    return out

def ent(b):
    if not b: return 0.0
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def unlock(so, apk, sec):
    i=apk.rfind(b'PK\x05\x06'); cd=struct.unpack_from('<I',apk,i+16)[0]
    sb=struct.unpack_from('<Q',apk,cd-24)[0]; ss=cd-sb-8
    p,end,pair=ss+8,cd-24,None
    while p<end:
        pl=struct.unpack_from('<Q',apk,p)[0]; pid=struct.unpack_from('<I',apk,p+8)[0]
        if pid in (0xf05368c0,0x7109871a): pair=apk[p+12:p+8+pl]
        p+=8+pl
    def lp(b,o):
        n=struct.unpack_from('<I',b,o)[0]; return b[o+4:o+4+n],o+4+n
    sg,_=lp(pair,0); s0,_=lp(sg,0); sd,_=lp(s0,0); _,o=lp(sd,0)
    cs,_=lp(sd,o); cert,_=lp(cs,0)
    csha=hashlib.sha256(cert).digest()
    T=sec['.text']; span=min(0x4000,T['size']); rg=so[T['off']:T['off']+span]
    ikm=struct.pack('>I',zlib.crc32(rg)&0xFFFFFFFF)+rg[:16]+rg[-16:]
    SALT=bytes([0x6e,0x63,0x1f,0x2b,0x7a,0x44,0x91,0xd8,0x03,0x5c,0xe6,0x18,0xaf,0x72,0x39,0xc4])
    prk=hmac.new(SALT,ikm,hashlib.sha256).digest()
    bk=hmac.new(prk,b'nc-boot-v1'+b'\x01',hashlib.sha256).digest()[:16]
    def rc4(key,data):
        S=list(range(256)); j=0
        for i2 in range(256):
            j=(j+S[i2]+key[i2%len(key)])&0xFF; S[i2],S[j]=S[j],S[i2]
        out=bytearray(); a=b=0
        for x in data:
            a=(a+1)&0xFF; b=(b+S[a])&0xFF; S[a],S[b]=S[b],S[a]
            out.append(x^S[(S[a]+S[b])&0xFF])
        return bytes(out)
    ncks=so[sec['.ncks']['off']:sec['.ncks']['off']+sec['.ncks']['size']]
    dec=ncks[:8]+rc4(bk,ncks[8:])
    r32=lambda o: struct.unpack_from('<I',dec,o)[0]
    FRAG=[1,0,2,3,0,1,3,2]; fr=dec[104:112]
    xk=bytes((((fr[FRAG[k]*2]|(fr[FRAG[k]*2+1]<<8))>>(0 if k<4 else 8))&0xFF) for k in range(8))
    ks=bytes(dec[8+k]^xk[k&7] for k in range(16))
    sc=zlib.crc32(so[T['off']:T['off']+r32(40)])&0xFFFFFFFF
    kse=bytes(ks[k]^((sc>>((k&3)*8))&0xFF) for k in range(16))
    def ctr(key,dom,d):
        out=bytearray(d); n=len(out); c=0; off=0
        while off<n:
            kk=hashlib.sha256(key+bytes([dom])+struct.pack('<I',c)).digest()
            b2=min(32,n-off)
            for j2 in range(b2): out[off+j2]^=kk[j2]
            off+=b2; c+=1
        return bytes(out)
    H=sec['.ncxhr']; master=ctr(kse,0x02,so[H['off']:H['off']+r32(100)])
    def hkdf(i_,s,info,n):
        pr=hmac.new(s,i_,hashlib.sha256).digest(); ok=b''; t=b''; k2=1
        while len(ok)<n:
            t=hmac.new(pr,t+info+bytes([k2]),hashlib.sha256).digest(); ok+=t; k2+=1
        return ok[:n]
    nd=rc4(bk,so[sec['.nck']['off']:sec['.nck']['off']+sec['.nck']['size']])
    psha=nd[80:88]
    import zipfile
    import io
    ax=zipfile.ZipFile(io.BytesIO(apk)).read('AndroidManifest.xml').decode('utf-16-le','ignore')
    pkg=None
    for c in set(re.findall(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,}", ax)):
        if hashlib.sha256(c.encode()).digest()[:8]==psha: pkg=c; break
    if not pkg: raise SystemExit('包名未匹配')
    kso=hkdf(master,csha,('nc-so-v1'+pkg).encode(),16)
    ncx=so[sec['.ncx']['off']:sec['.ncx']['off']+sec['.ncx']['size']]
    return pkg, rc4(kso,ncx)

def main():
    so=open(sys.argv[1],'rb').read(); apk=open(sys.argv[2],'rb').read()
    sec=sect(so)
    pkg,ncx=unlock(so,apk,sec)
    print(f'pkg={pkg}  .ncx={len(ncx):,} B  熵={ent(ncx):.3f}')
    # 反汇编统计
    n=len(ncx)//4
    subs=0; stps=0; bls=0; ldrsb=0
    for i in range(n):
        w=struct.unpack_from('<I',ncx,i*4)[0]
        if (w&0xFF8003FF)==0xD10003FF: subs+=1
        if (w&0xFFC07FFF)==0xA9007BFD: stps+=1
        if (w&0xFC000000)==0x94000000: bls+=1
        # VM 分派常见：ldrb w?, [x?, x?]  (0x38606800 类)
        if (w&0xFFC00000)==0x39400000 or (w&0xFFE00C00)==0x38600800: ldrsb+=1
    print(f'  sub sp 序言: {subs}   stp x29,x30: {stps}   bl: {bls}   字节加载(分派候选): {ldrsb}')
    print()
    for nm in ('onCreate','attachBaseContext','onConfigurationChanged','k'):
        print(f'  .rodata 有 "{nm}" 字符串: {nm.encode() in so}')
    print()
    # 关键判据：VMP 会把函数体换成「小帧 + bl 解释器」
    print('判据解读:')
    print(f'  普通编译的 .ncx: sub sp 序言数 ≈ 函数数，stp x29,x30 也相近')
    print(f'  VMP 后: 函数本体只剩 sub sp,#0xc0 级帧 + bl 解释器，')
    print(f'          原算法的循环/查表指令消失，bl 指向同一解释器入口')
    open('/data/data/com.termux/files/home/rev/ncx_vmp.bin','wb').write(ncx)
    print('\n已解出 ncx_vmp.bin')

main()
