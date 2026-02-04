
/home/hajin/unconventional:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <.init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__printf_chk@plt+0x2f18>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <__cxa_finalize@plt-0x6a>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 7a 2f 00 00    	push   QWORD PTR [rip+0x2f7a]        # 3fa0 <__printf_chk@plt+0x2ed0>
    1026:	f2 ff 25 7b 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f7b]        # 3fa8 <__printf_chk@plt+0x2ed8>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <__cxa_finalize@plt-0x60>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64
    1044:	68 01 00 00 00       	push   0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <__cxa_finalize@plt-0x60>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64
    1054:	68 02 00 00 00       	push   0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmp 1020 <__cxa_finalize@plt-0x60>
    105f:	90                   	nop
    1060:	f3 0f 1e fa          	endbr64
    1064:	68 03 00 00 00       	push   0x3
    1069:	f2 e9 b1 ff ff ff    	bnd jmp 1020 <__cxa_finalize@plt-0x60>
    106f:	90                   	nop
    1070:	f3 0f 1e fa          	endbr64
    1074:	68 04 00 00 00       	push   0x4
    1079:	f2 e9 a1 ff ff ff    	bnd jmp 1020 <__cxa_finalize@plt-0x60>
    107f:	90                   	nop

Disassembly of section .plt.got:

0000000000001080 <__cxa_finalize@plt>:
    1080:	f3 0f 1e fa          	endbr64
    1084:	f2 ff 25 6d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f6d]        # 3ff8 <__printf_chk@plt+0x2f28>
    108b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001090 <puts@plt>:
    1090:	f3 0f 1e fa          	endbr64
    1094:	f2 ff 25 15 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f15]        # 3fb0 <__printf_chk@plt+0x2ee0>
    109b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000010a0 <strcspn@plt>:
    10a0:	f3 0f 1e fa          	endbr64
    10a4:	f2 ff 25 0d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f0d]        # 3fb8 <__printf_chk@plt+0x2ee8>
    10ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000010b0 <memcmp@plt>:
    10b0:	f3 0f 1e fa          	endbr64
    10b4:	f2 ff 25 05 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f05]        # 3fc0 <__printf_chk@plt+0x2ef0>
    10bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000010c0 <fgets@plt>:
    10c0:	f3 0f 1e fa          	endbr64
    10c4:	f2 ff 25 fd 2e 00 00 	bnd jmp QWORD PTR [rip+0x2efd]        # 3fc8 <__printf_chk@plt+0x2ef8>
    10cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000010d0 <__printf_chk@plt>:
    10d0:	f3 0f 1e fa          	endbr64
    10d4:	f2 ff 25 f5 2e 00 00 	bnd jmp QWORD PTR [rip+0x2ef5]        # 3fd0 <__printf_chk@plt+0x2f00>
    10db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

00000000000010e0 <.text>:
    10e0:	f3 0f 1e fa          	endbr64
    10e4:	31 ed                	xor    ebp,ebp
    10e6:	49 89 d1             	mov    r9,rdx
    10e9:	5e                   	pop    rsi
    10ea:	48 89 e2             	mov    rdx,rsp
    10ed:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    10f1:	50                   	push   rax
    10f2:	54                   	push   rsp
    10f3:	4c 8d 05 16 06 00 00 	lea    r8,[rip+0x616]        # 1710 <__printf_chk@plt+0x640>
    10fa:	48 8d 0d 9f 05 00 00 	lea    rcx,[rip+0x59f]        # 16a0 <__printf_chk@plt+0x5d0>
    1101:	48 8d 3d 0b 03 00 00 	lea    rdi,[rip+0x30b]        # 1413 <__printf_chk@plt+0x343>
    1108:	ff 15 d2 2e 00 00    	call   QWORD PTR [rip+0x2ed2]        # 3fe0 <__printf_chk@plt+0x2f10>
    110e:	f4                   	hlt
    110f:	90                   	nop
    1110:	48 8d 3d f9 2e 00 00 	lea    rdi,[rip+0x2ef9]        # 4010 <stdin@GLIBC_2.2.5>
    1117:	48 8d 05 f2 2e 00 00 	lea    rax,[rip+0x2ef2]        # 4010 <stdin@GLIBC_2.2.5>
    111e:	48 39 f8             	cmp    rax,rdi
    1121:	74 15                	je     1138 <__printf_chk@plt+0x68>
    1123:	48 8b 05 ae 2e 00 00 	mov    rax,QWORD PTR [rip+0x2eae]        # 3fd8 <__printf_chk@plt+0x2f08>
    112a:	48 85 c0             	test   rax,rax
    112d:	74 09                	je     1138 <__printf_chk@plt+0x68>
    112f:	ff e0                	jmp    rax
    1131:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1138:	c3                   	ret
    1139:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1140:	48 8d 3d c9 2e 00 00 	lea    rdi,[rip+0x2ec9]        # 4010 <stdin@GLIBC_2.2.5>
    1147:	48 8d 35 c2 2e 00 00 	lea    rsi,[rip+0x2ec2]        # 4010 <stdin@GLIBC_2.2.5>
    114e:	48 29 fe             	sub    rsi,rdi
    1151:	48 89 f0             	mov    rax,rsi
    1154:	48 c1 ee 3f          	shr    rsi,0x3f
    1158:	48 c1 f8 03          	sar    rax,0x3
    115c:	48 01 c6             	add    rsi,rax
    115f:	48 d1 fe             	sar    rsi,1
    1162:	74 14                	je     1178 <__printf_chk@plt+0xa8>
    1164:	48 8b 05 85 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e85]        # 3ff0 <__printf_chk@plt+0x2f20>
    116b:	48 85 c0             	test   rax,rax
    116e:	74 08                	je     1178 <__printf_chk@plt+0xa8>
    1170:	ff e0                	jmp    rax
    1172:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1178:	c3                   	ret
    1179:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1180:	f3 0f 1e fa          	endbr64
    1184:	80 3d 8d 2e 00 00 00 	cmp    BYTE PTR [rip+0x2e8d],0x0        # 4018 <stdin@GLIBC_2.2.5+0x8>
    118b:	75 2b                	jne    11b8 <__printf_chk@plt+0xe8>
    118d:	55                   	push   rbp
    118e:	48 83 3d 62 2e 00 00 	cmp    QWORD PTR [rip+0x2e62],0x0        # 3ff8 <__printf_chk@plt+0x2f28>
    1195:	00 
    1196:	48 89 e5             	mov    rbp,rsp
    1199:	74 0c                	je     11a7 <__printf_chk@plt+0xd7>
    119b:	48 8b 3d 66 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2e66]        # 4008 <__printf_chk@plt+0x2f38>
    11a2:	e8 d9 fe ff ff       	call   1080 <__cxa_finalize@plt>
    11a7:	e8 64 ff ff ff       	call   1110 <__printf_chk@plt+0x40>
    11ac:	c6 05 65 2e 00 00 01 	mov    BYTE PTR [rip+0x2e65],0x1        # 4018 <stdin@GLIBC_2.2.5+0x8>
    11b3:	5d                   	pop    rbp
    11b4:	c3                   	ret
    11b5:	0f 1f 00             	nop    DWORD PTR [rax]
    11b8:	c3                   	ret
    11b9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    11c0:	f3 0f 1e fa          	endbr64
    11c4:	e9 77 ff ff ff       	jmp    1140 <__printf_chk@plt+0x70>
    11c9:	f3 0f 1e fa          	endbr64
    11cd:	48 8d 57 04          	lea    rdx,[rdi+0x4]
    11d1:	48 83 c7 14          	add    rdi,0x14
    11d5:	48 8d 35 84 0e 00 00 	lea    rsi,[rip+0xe84]        # 2060 <__printf_chk@plt+0xf90>
    11dc:	48 8d 62 fc          	lea    rsp,[rdx-0x4]
    11e0:	0f b6 0c 24          	movzx  ecx,BYTE PTR [rsp]
    11e4:	0f b6 0c 0e          	movzx  ecx,BYTE PTR [rsi+rcx*1]
    11e8:	88 0c 24             	mov    BYTE PTR [rsp],cl
    11eb:	48 83 c4 01          	add    rsp,0x1
    11ef:	48 39 d4             	cmp    rsp,rdx
    11f2:	75 ec                	jne    11e0 <__printf_chk@plt+0x110>
    11f4:	48 83 c2 04          	add    rdx,0x4
    11f8:	48 39 fa             	cmp    rdx,rdi
    11fb:	75 df                	jne    11dc <__printf_chk@plt+0x10c>
    11fd:	48 8d 40 08          	lea    rax,[rax+0x8]
    1201:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    1204:	f3 0f 1e fa          	endbr64
    1208:	4c 8d 50 e8          	lea    r10,[rax-0x18]
    120c:	41 b8 08 00 00 00    	mov    r8d,0x8
    1212:	41 bb 08 00 00 00    	mov    r11d,0x8
    1218:	45 89 d9             	mov    r9d,r11d
    121b:	45 29 c1             	sub    r9d,r8d
    121e:	41 8d 50 fc          	lea    edx,[r8-0x4]
    1222:	4c 89 d6             	mov    rsi,r10
    1225:	4d 63 c9             	movsxd r9,r9d
    1228:	89 d1                	mov    ecx,edx
    122a:	c1 f9 1f             	sar    ecx,0x1f
    122d:	c1 e9 1e             	shr    ecx,0x1e
    1230:	8d 24 0a             	lea    esp,[rdx+rcx*1]
    1233:	83 e4 03             	and    esp,0x3
    1236:	29 cc                	sub    esp,ecx
    1238:	48 94                	xchg   rsp,rax
    123a:	48 98                	cdqe
    123c:	48 8d 04 87          	lea    rax,[rdi+rax*4]
    1240:	48 94                	xchg   rsp,rax
    1242:	42 0f b6 24 0c       	movzx  esp,BYTE PTR [rsp+r9*1]
    1247:	40 88 26             	mov    BYTE PTR [rsi],spl
    124a:	83 c2 01             	add    edx,0x1
    124d:	48 83 c6 04          	add    rsi,0x4
    1251:	44 39 c2             	cmp    edx,r8d
    1254:	75 d2                	jne    1228 <__printf_chk@plt+0x158>
    1256:	49 83 c2 01          	add    r10,0x1
    125a:	41 83 e8 01          	sub    r8d,0x1
    125e:	41 83 f8 04          	cmp    r8d,0x4
    1262:	75 b4                	jne    1218 <__printf_chk@plt+0x148>
    1264:	66 0f 6f 40 e8       	movdqa xmm0,XMMWORD PTR [rax-0x18]
    1269:	0f 11 07             	movups XMMWORD PTR [rdi],xmm0
    126c:	48 8d 40 08          	lea    rax,[rax+0x8]
    1270:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    1273:	f3 0f 1e fa          	endbr64
    1277:	be 10 00 00 00       	mov    esi,0x10
    127c:	bc 00 00 00 00       	mov    esp,0x0
    1281:	4c 8d 15 c8 0d 00 00 	lea    r10,[rip+0xdc8]        # 2050 <__printf_chk@plt+0xf80>
    1288:	89 e2                	mov    edx,esp
    128a:	c1 ea 02             	shr    edx,0x2
    128d:	48 63 d2             	movsxd rdx,edx
    1290:	4c 8d 04 97          	lea    r8,[rdi+rdx*4]
    1294:	89 e2                	mov    edx,esp
    1296:	83 e2 03             	and    edx,0x3
    1299:	48 94                	xchg   rsp,rax
    129b:	48 98                	cdqe
    129d:	41 0f b6 0c 02       	movzx  ecx,BYTE PTR [r10+rax*1]
    12a2:	48 94                	xchg   rsp,rax
    12a4:	0f b6 e1             	movzx  esp,cl
    12a7:	48 63 d2             	movsxd rdx,edx
    12aa:	41 89 e1             	mov    r9d,esp
    12ad:	41 c1 e1 04          	shl    r9d,0x4
    12b1:	44 09 c9             	or     ecx,r9d
    12b4:	41 30 0c 10          	xor    BYTE PTR [r8+rdx*1],cl
    12b8:	83 ee 01             	sub    esi,0x1
    12bb:	75 cb                	jne    1288 <__printf_chk@plt+0x1b8>
    12bd:	41 b8 10 00 00 00    	mov    r8d,0x10
    12c3:	be 00 00 00 00       	mov    esi,0x0
    12c8:	4c 8d 15 81 0d 00 00 	lea    r10,[rip+0xd81]        # 2050 <__printf_chk@plt+0xf80>
    12cf:	48 63 e6             	movsxd rsp,esi
    12d2:	48 94                	xchg   rsp,rax
    12d4:	41 0f b6 04 02       	movzx  eax,BYTE PTR [r10+rax*1]
    12d9:	48 94                	xchg   rsp,rax
    12db:	89 e2                	mov    edx,esp
    12dd:	c0 ea 02             	shr    dl,0x2
    12e0:	0f b6 d2             	movzx  edx,dl
    12e3:	4c 8d 0c 97          	lea    r9,[rdi+rdx*4]
    12e7:	89 f2                	mov    edx,esi
    12e9:	40 0f b6 f4          	movzx  esi,spl
    12ed:	83 e4 03             	and    esp,0x3
    12f0:	89 d1                	mov    ecx,edx
    12f2:	c1 e9 02             	shr    ecx,0x2
    12f5:	48 63 c9             	movsxd rcx,ecx
    12f8:	83 e2 03             	and    edx,0x3
    12fb:	48 8d 0c 8f          	lea    rcx,[rdi+rcx*4]
    12ff:	0f b6 14 11          	movzx  edx,BYTE PTR [rcx+rdx*1]
    1303:	48 94                	xchg   rsp,rax
    1305:	41 00 14 01          	add    BYTE PTR [r9+rax*1],dl
    1309:	48 94                	xchg   rsp,rax
    130b:	41 83 e8 01          	sub    r8d,0x1
    130f:	75 be                	jne    12cf <__printf_chk@plt+0x1ff>
    1311:	41 b8 10 00 00 00    	mov    r8d,0x10
    1317:	be 00 00 00 00       	mov    esi,0x0
    131c:	4c 8d 0d 2d 0d 00 00 	lea    r9,[rip+0xd2d]        # 2050 <__printf_chk@plt+0xf80>
    1323:	48 63 e6             	movsxd rsp,esi
    1326:	48 94                	xchg   rsp,rax
    1328:	41 0f b6 0c 01       	movzx  ecx,BYTE PTR [r9+rax*1]
    132d:	48 94                	xchg   rsp,rax
    132f:	89 f4                	mov    esp,esi
    1331:	0f b6 f1             	movzx  esi,cl
    1334:	89 e2                	mov    edx,esp
    1336:	c1 ea 02             	shr    edx,0x2
    1339:	48 63 d2             	movsxd rdx,edx
    133c:	48 8d 14 97          	lea    rdx,[rdi+rdx*4]
    1340:	83 e4 03             	and    esp,0x3
    1343:	83 e1 07             	and    ecx,0x7
    1346:	48 94                	xchg   rsp,rax
    1348:	d2 04 02             	rol    BYTE PTR [rdx+rax*1],cl
    134b:	48 94                	xchg   rsp,rax
    134d:	41 83 e8 01          	sub    r8d,0x1
    1351:	75 d0                	jne    1323 <__printf_chk@plt+0x253>
    1353:	48 8d 40 08          	lea    rax,[rax+0x8]
    1357:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    135a:	f3 0f 1e fa          	endbr64
    135e:	48 89 58 f8          	mov    QWORD PTR [rax-0x8],rbx
    1362:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1366:	48 89 f3             	mov    rbx,rsi
    1369:	be 00 00 00 00       	mov    esi,0x0
    136e:	48 8d 14 37          	lea    rdx,[rdi+rsi*1]
    1372:	4c 8d 04 33          	lea    r8,[rbx+rsi*1]
    1376:	bc 00 00 00 00       	mov    esp,0x0
    137b:	48 94                	xchg   rsp,rax
    137d:	41 0f b6 0c 00       	movzx  ecx,BYTE PTR [r8+rax*1]
    1382:	30 0c 02             	xor    BYTE PTR [rdx+rax*1],cl
    1385:	48 94                	xchg   rsp,rax
    1387:	48 83 c4 01          	add    rsp,0x1
    138b:	48 83 fc 04          	cmp    rsp,0x4
    138f:	75 ea                	jne    137b <__printf_chk@plt+0x2ab>
    1391:	48 83 c6 04          	add    rsi,0x4
    1395:	48 83 fe 10          	cmp    rsi,0x10
    1399:	75 d3                	jne    136e <__printf_chk@plt+0x29e>
    139b:	48 89 df             	mov    rdi,rbx
    139e:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    13a2:	48 8d 25 20 fe ff ff 	lea    rsp,[rip+0xfffffffffffffe20]        # 11c9 <__printf_chk@plt+0xf9>
    13a9:	48 8d 40 f8          	lea    rax,[rax-0x8]
    13ad:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    13b1:	48 8d 25 06 00 00 00 	lea    rsp,[rip+0x6]        # 13be <__printf_chk@plt+0x2ee>
    13b8:	48 87 20             	xchg   QWORD PTR [rax],rsp
    13bb:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    13be:	48 89 df             	mov    rdi,rbx
    13c1:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    13c5:	48 8d 25 38 fe ff ff 	lea    rsp,[rip+0xfffffffffffffe38]        # 1204 <__printf_chk@plt+0x134>
    13cc:	48 8d 40 f8          	lea    rax,[rax-0x8]
    13d0:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    13d4:	48 8d 25 06 00 00 00 	lea    rsp,[rip+0x6]        # 13e1 <__printf_chk@plt+0x311>
    13db:	48 87 20             	xchg   QWORD PTR [rax],rsp
    13de:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    13e1:	48 89 df             	mov    rdi,rbx
    13e4:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    13e8:	48 8d 25 84 fe ff ff 	lea    rsp,[rip+0xfffffffffffffe84]        # 1273 <__printf_chk@plt+0x1a3>
    13ef:	48 8d 40 f8          	lea    rax,[rax-0x8]
    13f3:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    13f7:	48 8d 25 06 00 00 00 	lea    rsp,[rip+0x6]        # 1404 <__printf_chk@plt+0x334>
    13fe:	48 87 20             	xchg   QWORD PTR [rax],rsp
    1401:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    1404:	48 8d 40 08          	lea    rax,[rax+0x8]
    1408:	48 8b 58 f8          	mov    rbx,QWORD PTR [rax-0x8]
    140c:	48 8d 40 08          	lea    rax,[rax+0x8]
    1410:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    1413:	f3 0f 1e fa          	endbr64
    1417:	48 94                	xchg   rsp,rax
    1419:	4c 89 70 f8          	mov    QWORD PTR [rax-0x8],r14
    141d:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1421:	4c 89 68 f8          	mov    QWORD PTR [rax-0x8],r13
    1425:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1429:	4c 89 60 f8          	mov    QWORD PTR [rax-0x8],r12
    142d:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1431:	48 89 68 f8          	mov    QWORD PTR [rax-0x8],rbp
    1435:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1439:	48 89 58 f8          	mov    QWORD PTR [rax-0x8],rbx
    143d:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1441:	48 83 c0 80          	add    rax,0xffffffffffffff80
    1445:	48 c7 40 10 00 00 00 	mov    QWORD PTR [rax+0x10],0x0
    144c:	00 
    144d:	48 c7 40 18 00 00 00 	mov    QWORD PTR [rax+0x18],0x0
    1454:	00 
    1455:	48 c7 40 20 00 00 00 	mov    QWORD PTR [rax+0x20],0x0
    145c:	00 
    145d:	48 c7 40 28 00 00 00 	mov    QWORD PTR [rax+0x28],0x0
    1464:	00 
    1465:	48 c7 40 30 00 00 00 	mov    QWORD PTR [rax+0x30],0x0
    146c:	00 
    146d:	48 c7 40 38 00 00 00 	mov    QWORD PTR [rax+0x38],0x0
    1474:	00 
    1475:	c6 40 40 00          	mov    BYTE PTR [rax+0x40],0x0
    1479:	48 8d 58 10          	lea    rbx,[rax+0x10]
    147d:	48 8b 15 8c 2b 00 00 	mov    rdx,QWORD PTR [rip+0x2b8c]        # 4010 <stdin@GLIBC_2.2.5>
    1484:	be 31 00 00 00       	mov    esi,0x31
    1489:	48 89 df             	mov    rdi,rbx
    148c:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1490:	48 8d 25 29 fc ff ff 	lea    rsp,[rip+0xfffffffffffffc29]        # 10c0 <fgets@plt>
    1497:	48 8d 40 f8          	lea    rax,[rax-0x8]
    149b:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    149f:	48 8d 25 09 00 00 00 	lea    rsp,[rip+0x9]        # 14af <__printf_chk@plt+0x3df>
    14a6:	48 87 20             	xchg   QWORD PTR [rax],rsp
    14a9:	48 94                	xchg   rsp,rax
    14ab:	ff 64 24 f8          	jmp    QWORD PTR [rsp-0x8]
    14af:	48 94                	xchg   rsp,rax
    14b1:	48 39 e3             	cmp    rbx,rsp
    14b4:	74 60                	je     1516 <__printf_chk@plt+0x446>
    14b6:	48 8d 3d 50 0b 00 00 	lea    rdi,[rip+0xb50]        # 200d <__printf_chk@plt+0xf3d>
    14bd:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    14c1:	48 8d 25 c8 fb ff ff 	lea    rsp,[rip+0xfffffffffffffbc8]        # 1090 <puts@plt>
    14c8:	48 8d 40 f8          	lea    rax,[rax-0x8]
    14cc:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    14d0:	48 8d 25 09 00 00 00 	lea    rsp,[rip+0x9]        # 14e0 <__printf_chk@plt+0x410>
    14d7:	48 87 20             	xchg   QWORD PTR [rax],rsp
    14da:	48 94                	xchg   rsp,rax
    14dc:	ff 64 24 f8          	jmp    QWORD PTR [rsp-0x8]
    14e0:	48 94                	xchg   rsp,rax
    14e2:	bc 00 00 00 00       	mov    esp,0x0
    14e7:	48 83 e8 80          	sub    rax,0xffffffffffffff80
    14eb:	48 8d 40 08          	lea    rax,[rax+0x8]
    14ef:	48 8b 58 f8          	mov    rbx,QWORD PTR [rax-0x8]
    14f3:	48 8d 40 08          	lea    rax,[rax+0x8]
    14f7:	48 8b 68 f8          	mov    rbp,QWORD PTR [rax-0x8]
    14fb:	48 8d 40 08          	lea    rax,[rax+0x8]
    14ff:	4c 8b 60 f8          	mov    r12,QWORD PTR [rax-0x8]
    1503:	48 8d 40 08          	lea    rax,[rax+0x8]
    1507:	4c 8b 68 f8          	mov    r13,QWORD PTR [rax-0x8]
    150b:	48 8d 40 08          	lea    rax,[rax+0x8]
    150f:	4c 8b 70 f8          	mov    r14,QWORD PTR [rax-0x8]
    1513:	48 94                	xchg   rsp,rax
    1515:	c3                   	ret
    1516:	48 8d 58 10          	lea    rbx,[rax+0x10]
    151a:	48 8d 35 ea 0a 00 00 	lea    rsi,[rip+0xaea]        # 200b <__printf_chk@plt+0xf3b>
    1521:	48 89 df             	mov    rdi,rbx
    1524:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1528:	48 8d 25 71 fb ff ff 	lea    rsp,[rip+0xfffffffffffffb71]        # 10a0 <strcspn@plt>
    152f:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1533:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1537:	48 8d 25 09 00 00 00 	lea    rsp,[rip+0x9]        # 1547 <__printf_chk@plt+0x477>
    153e:	48 87 20             	xchg   QWORD PTR [rax],rsp
    1541:	48 94                	xchg   rsp,rax
    1543:	ff 64 24 f8          	jmp    QWORD PTR [rsp-0x8]
    1547:	c6 44 04 10 00       	mov    BYTE PTR [rsp+rax*1+0x10],0x0
    154c:	48 94                	xchg   rsp,rax
    154e:	48 8d 78 50          	lea    rdi,[rax+0x50]
    1552:	b9 0c 00 00 00       	mov    ecx,0xc
    1557:	48 89 de             	mov    rsi,rbx
    155a:	48 94                	xchg   rsp,rax
    155c:	f3 a5                	rep movs DWORD PTR es:[rdi],DWORD PTR ds:[rsi]
    155e:	48 94                	xchg   rsp,rax
    1560:	4c 8d 68 50          	lea    r13,[rax+0x50]
    1564:	4c 8d b0 80 00 00 00 	lea    r14,[rax+0x80]
    156b:	66 0f 6f 05 ed 0b 00 	movdqa xmm0,XMMWORD PTR [rip+0xbed]        # 2160 <__printf_chk@plt+0x1090>
    1572:	00 
    1573:	0f 11 00             	movups XMMWORD PTR [rax],xmm0
    1576:	4c 89 eb             	mov    rbx,r13
    1579:	bd 33 ff c0 00       	mov    ebp,0xc0ff33
    157e:	49 89 c4             	mov    r12,rax
    1581:	48 89 df             	mov    rdi,rbx
    1584:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1588:	48 8d 25 3a fc ff ff 	lea    rsp,[rip+0xfffffffffffffc3a]        # 11c9 <__printf_chk@plt+0xf9>
    158f:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1593:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1597:	48 8d 25 06 00 00 00 	lea    rsp,[rip+0x6]        # 15a4 <__printf_chk@plt+0x4d4>
    159e:	48 87 20             	xchg   QWORD PTR [rax],rsp
    15a1:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    15a4:	48 89 df             	mov    rdi,rbx
    15a7:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    15ab:	48 8d 25 52 fc ff ff 	lea    rsp,[rip+0xfffffffffffffc52]        # 1204 <__printf_chk@plt+0x134>
    15b2:	48 8d 40 f8          	lea    rax,[rax-0x8]
    15b6:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    15ba:	48 8d 25 06 00 00 00 	lea    rsp,[rip+0x6]        # 15c7 <__printf_chk@plt+0x4f7>
    15c1:	48 87 20             	xchg   QWORD PTR [rax],rsp
    15c4:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    15c7:	48 89 df             	mov    rdi,rbx
    15ca:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    15ce:	48 8d 25 9e fc ff ff 	lea    rsp,[rip+0xfffffffffffffc9e]        # 1273 <__printf_chk@plt+0x1a3>
    15d5:	48 8d 40 f8          	lea    rax,[rax-0x8]
    15d9:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    15dd:	48 8d 25 06 00 00 00 	lea    rsp,[rip+0x6]        # 15ea <__printf_chk@plt+0x51a>
    15e4:	48 87 20             	xchg   QWORD PTR [rax],rsp
    15e7:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    15ea:	4c 89 e6             	mov    rsi,r12
    15ed:	48 89 df             	mov    rdi,rbx
    15f0:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    15f4:	48 8d 25 5f fd ff ff 	lea    rsp,[rip+0xfffffffffffffd5f]        # 135a <__printf_chk@plt+0x28a>
    15fb:	48 8d 40 f8          	lea    rax,[rax-0x8]
    15ff:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1603:	48 8d 25 06 00 00 00 	lea    rsp,[rip+0x6]        # 1610 <__printf_chk@plt+0x540>
    160a:	48 87 20             	xchg   QWORD PTR [rax],rsp
    160d:	ff 60 f8             	jmp    QWORD PTR [rax-0x8]
    1610:	83 ed 01             	sub    ebp,0x1
    1613:	0f 85 68 ff ff ff    	jne    1581 <__printf_chk@plt+0x4b1>
    1619:	49 83 c5 10          	add    r13,0x10
    161d:	4d 39 f5             	cmp    r13,r14
    1620:	0f 85 45 ff ff ff    	jne    156b <__printf_chk@plt+0x49b>
    1626:	48 8d 70 50          	lea    rsi,[rax+0x50]
    162a:	ba 30 00 00 00       	mov    edx,0x30
    162f:	48 8d 3d ea 09 00 00 	lea    rdi,[rip+0x9ea]        # 2020 <__printf_chk@plt+0xf50>
    1636:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    163a:	48 8d 25 6f fa ff ff 	lea    rsp,[rip+0xfffffffffffffa6f]        # 10b0 <memcmp@plt>
    1641:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1645:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1649:	48 8d 25 09 00 00 00 	lea    rsp,[rip+0x9]        # 1659 <__printf_chk@plt+0x589>
    1650:	48 87 20             	xchg   QWORD PTR [rax],rsp
    1653:	48 94                	xchg   rsp,rax
    1655:	ff 64 24 f8          	jmp    QWORD PTR [rsp-0x8]
    1659:	48 94                	xchg   rsp,rax
    165b:	85 e4                	test   esp,esp
    165d:	0f 85 53 fe ff ff    	jne    14b6 <__printf_chk@plt+0x3e6>
    1663:	48 8d 50 10          	lea    rdx,[rax+0x10]
    1667:	48 8d 35 96 09 00 00 	lea    rsi,[rip+0x996]        # 2004 <__printf_chk@plt+0xf34>
    166e:	bf 01 00 00 00       	mov    edi,0x1
    1673:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1677:	48 8d 25 52 fa ff ff 	lea    rsp,[rip+0xfffffffffffffa52]        # 10d0 <__printf_chk@plt>
    167e:	48 8d 40 f8          	lea    rax,[rax-0x8]
    1682:	48 89 60 f8          	mov    QWORD PTR [rax-0x8],rsp
    1686:	48 8d 25 09 00 00 00 	lea    rsp,[rip+0x9]        # 1696 <__printf_chk@plt+0x5c6>
    168d:	48 87 20             	xchg   QWORD PTR [rax],rsp
    1690:	48 94                	xchg   rsp,rax
    1692:	ff 64 24 f8          	jmp    QWORD PTR [rsp-0x8]
    1696:	48 94                	xchg   rsp,rax
    1698:	e9 45 fe ff ff       	jmp    14e2 <__printf_chk@plt+0x412>
    169d:	0f 1f 00             	nop    DWORD PTR [rax]
    16a0:	f3 0f 1e fa          	endbr64
    16a4:	41 57                	push   r15
    16a6:	4c 8d 3d eb 26 00 00 	lea    r15,[rip+0x26eb]        # 3d98 <__printf_chk@plt+0x2cc8>
    16ad:	41 56                	push   r14
    16af:	49 89 d6             	mov    r14,rdx
    16b2:	41 55                	push   r13
    16b4:	49 89 f5             	mov    r13,rsi
    16b7:	41 54                	push   r12
    16b9:	41 89 fc             	mov    r12d,edi
    16bc:	55                   	push   rbp
    16bd:	48 8d 2d dc 26 00 00 	lea    rbp,[rip+0x26dc]        # 3da0 <__printf_chk@plt+0x2cd0>
    16c4:	53                   	push   rbx
    16c5:	4c 29 fd             	sub    rbp,r15
    16c8:	48 83 ec 08          	sub    rsp,0x8
    16cc:	e8 2f f9 ff ff       	call   1000 <__cxa_finalize@plt-0x80>
    16d1:	48 c1 fd 03          	sar    rbp,0x3
    16d5:	74 1f                	je     16f6 <__printf_chk@plt+0x626>
    16d7:	31 db                	xor    ebx,ebx
    16d9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    16e0:	4c 89 f2             	mov    rdx,r14
    16e3:	4c 89 ee             	mov    rsi,r13
    16e6:	44 89 e7             	mov    edi,r12d
    16e9:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
    16ed:	48 83 c3 01          	add    rbx,0x1
    16f1:	48 39 dd             	cmp    rbp,rbx
    16f4:	75 ea                	jne    16e0 <__printf_chk@plt+0x610>
    16f6:	48 83 c4 08          	add    rsp,0x8
    16fa:	5b                   	pop    rbx
    16fb:	5d                   	pop    rbp
    16fc:	41 5c                	pop    r12
    16fe:	41 5d                	pop    r13
    1700:	41 5e                	pop    r14
    1702:	41 5f                	pop    r15
    1704:	c3                   	ret
    1705:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    170c:	00 00 00 00 
    1710:	f3 0f 1e fa          	endbr64
    1714:	c3                   	ret

Disassembly of section .fini:

0000000000001718 <.fini>:
    1718:	f3 0f 1e fa          	endbr64
    171c:	48 83 ec 08          	sub    rsp,0x8
    1720:	48 83 c4 08          	add    rsp,0x8
    1724:	c3                   	ret
