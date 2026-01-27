
layer_1.elf:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <.init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 d1 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd1]        # 403fe0 <_DYNAMIC+0x1d8>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 403ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 403ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401030:	f3 0f 1e fa          	endbr64
  401034:	68 00 00 00 00       	push   0x0
  401039:	e9 e2 ff ff ff       	jmp    401020 <_init+0x20>
  40103e:	66 90                	xchg   ax,ax
  401040:	f3 0f 1e fa          	endbr64
  401044:	68 01 00 00 00       	push   0x1
  401049:	e9 d2 ff ff ff       	jmp    401020 <_init+0x20>
  40104e:	66 90                	xchg   ax,ax
  401050:	f3 0f 1e fa          	endbr64
  401054:	68 02 00 00 00       	push   0x2
  401059:	e9 c2 ff ff ff       	jmp    401020 <_init+0x20>
  40105e:	66 90                	xchg   ax,ax
  401060:	f3 0f 1e fa          	endbr64
  401064:	68 03 00 00 00       	push   0x3
  401069:	e9 b2 ff ff ff       	jmp    401020 <_init+0x20>
  40106e:	66 90                	xchg   ax,ax

Disassembly of section .plt.sec:

0000000000401070 <_init+0x70>:
  401070:	f3 0f 1e fa          	endbr64
  401074:	ff 25 86 2f 00 00    	jmp    QWORD PTR [rip+0x2f86]        # 404000 <_GLOBAL_OFFSET_TABLE_+0x18>
  40107a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  401080:	f3 0f 1e fa          	endbr64
  401084:	ff 25 7e 2f 00 00    	jmp    QWORD PTR [rip+0x2f7e]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x20>
  40108a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  401090:	f3 0f 1e fa          	endbr64
  401094:	ff 25 76 2f 00 00    	jmp    QWORD PTR [rip+0x2f76]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x28>
  40109a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  4010a0:	f3 0f 1e fa          	endbr64
  4010a4:	ff 25 6e 2f 00 00    	jmp    QWORD PTR [rip+0x2f6e]        # 404018 <_GLOBAL_OFFSET_TABLE_+0x30>
  4010aa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

00000000004010b0 <.text>:
  4010b0:	f3 0f 1e fa          	endbr64
  4010b4:	31 ed                	xor    ebp,ebp
  4010b6:	49 89 d1             	mov    r9,rdx
  4010b9:	5e                   	pop    rsi
  4010ba:	48 89 e2             	mov    rdx,rsp
  4010bd:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  4010c1:	50                   	push   rax
  4010c2:	54                   	push   rsp
  4010c3:	45 31 c0             	xor    r8d,r8d
  4010c6:	31 c9                	xor    ecx,ecx
  4010c8:	48 c7 c7 cb 11 40 00 	mov    rdi,0x4011cb
  4010cf:	ff 15 03 2f 00 00    	call   QWORD PTR [rip+0x2f03]        # 403fd8 <_DYNAMIC+0x1d0>
  4010d5:	f4                   	hlt
  4010d6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4010dd:	00 00 00 
  4010e0:	f3 0f 1e fa          	endbr64
  4010e4:	c3                   	ret
  4010e5:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4010ec:	00 00 00 
  4010ef:	90                   	nop
  4010f0:	b8 38 40 40 00       	mov    eax,0x404038
  4010f5:	48 3d 38 40 40 00    	cmp    rax,0x404038
  4010fb:	74 13                	je     401110 <deregister_tm_clones+0x20>
  4010fd:	b8 00 00 00 00       	mov    eax,0x0
  401102:	48 85 c0             	test   rax,rax
  401105:	74 09                	je     401110 <deregister_tm_clones+0x20>
  401107:	bf 38 40 40 00       	mov    edi,0x404038
  40110c:	ff e0                	jmp    rax
  40110e:	66 90                	xchg   ax,ax
  401110:	c3                   	ret
  401111:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401118:	00 00 00 00 
  40111c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401120:	be 38 40 40 00       	mov    esi,0x404038
  401125:	48 81 ee 38 40 40 00 	sub    rsi,0x404038
  40112c:	48 89 f0             	mov    rax,rsi
  40112f:	48 c1 ee 3f          	shr    rsi,0x3f
  401133:	48 c1 f8 03          	sar    rax,0x3
  401137:	48 01 c6             	add    rsi,rax
  40113a:	48 d1 fe             	sar    rsi,1
  40113d:	74 11                	je     401150 <register_tm_clones+0x30>
  40113f:	b8 00 00 00 00       	mov    eax,0x0
  401144:	48 85 c0             	test   rax,rax
  401147:	74 07                	je     401150 <register_tm_clones+0x30>
  401149:	bf 38 40 40 00       	mov    edi,0x404038
  40114e:	ff e0                	jmp    rax
  401150:	c3                   	ret
  401151:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401158:	00 00 00 00 
  40115c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401160:	f3 0f 1e fa          	endbr64
  401164:	80 3d cd 2e 00 00 00 	cmp    BYTE PTR [rip+0x2ecd],0x0        # 404038 <__TMC_END__>
  40116b:	75 13                	jne    401180 <__do_global_dtors_aux+0x20>
  40116d:	55                   	push   rbp
  40116e:	48 89 e5             	mov    rbp,rsp
  401171:	e8 7a ff ff ff       	call   4010f0 <deregister_tm_clones>
  401176:	c6 05 bb 2e 00 00 01 	mov    BYTE PTR [rip+0x2ebb],0x1        # 404038 <__TMC_END__>
  40117d:	5d                   	pop    rbp
  40117e:	c3                   	ret
  40117f:	90                   	nop
  401180:	c3                   	ret
  401181:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401188:	00 00 00 00 
  40118c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401190:	f3 0f 1e fa          	endbr64
  401194:	eb 8a                	jmp    401120 <register_tm_clones>
  401196:	f3 0f 1e fa          	endbr64
  40119a:	55                   	push   rbp
  40119b:	48 89 e5             	mov    rbp,rsp
  40119e:	48 83 ec 10          	sub    rsp,0x10
  4011a2:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
  4011a6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4011aa:	48 8d 50 04          	lea    rdx,[rax+0x4]
  4011ae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4011b2:	48 89 d6             	mov    rsi,rdx
  4011b5:	48 89 c7             	mov    rdi,rax
  4011b8:	e8 b6 00 00 00       	call   401273 <encrypt>
  4011bd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4011c1:	48 89 c7             	mov    rdi,rax
  4011c4:	e8 d9 01 00 00       	call   4013a2 <check>
  4011c9:	c9                   	leave
  4011ca:	c3                   	ret
  4011cb:	f3 0f 1e fa          	endbr64
  4011cf:	55                   	push   rbp
  4011d0:	48 89 e5             	mov    rbp,rsp
  4011d3:	48 83 ec 20          	sub    rsp,0x20
  4011d7:	89 7d ec             	mov    DWORD PTR [rbp-0x14],edi
  4011da:	48 89 75 e0          	mov    QWORD PTR [rbp-0x20],rsi
  4011de:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  4011e5:	00 00 
  4011e7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4011eb:	31 c0                	xor    eax,eax
  4011ed:	83 7d ec 02          	cmp    DWORD PTR [rbp-0x14],0x2
  4011f1:	74 0e                	je     401201 <main+0x36>
  4011f3:	48 8b 05 36 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e36]        # 404030 <wrong>
  4011fa:	89 c7                	mov    edi,eax
  4011fc:	e8 9f fe ff ff       	call   4010a0 <_init+0xa0>
  401201:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
  401205:	48 83 c0 08          	add    rax,0x8
  401209:	48 8b 00             	mov    rax,QWORD PTR [rax]
  40120c:	48 89 c7             	mov    rdi,rax
  40120f:	e8 6c fe ff ff       	call   401080 <_init+0x80>
  401214:	48 83 f8 08          	cmp    rax,0x8
  401218:	74 0e                	je     401228 <main+0x5d>
  40121a:	48 8b 05 0f 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e0f]        # 404030 <wrong>
  401221:	89 c7                	mov    edi,eax
  401223:	e8 78 fe ff ff       	call   4010a0 <_init+0xa0>
  401228:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
  40122c:	48 83 c0 08          	add    rax,0x8
  401230:	48 8b 08             	mov    rcx,QWORD PTR [rax]
  401233:	48 8d 45 f0          	lea    rax,[rbp-0x10]
  401237:	ba 08 00 00 00       	mov    edx,0x8
  40123c:	48 89 ce             	mov    rsi,rcx
  40123f:	48 89 c7             	mov    rdi,rax
  401242:	e8 29 fe ff ff       	call   401070 <_init+0x70>
  401247:	48 8d 45 f0          	lea    rax,[rbp-0x10]
  40124b:	48 89 c7             	mov    rdi,rax
  40124e:	e8 43 ff ff ff       	call   401196 <flagchecker>
  401253:	84 c0                	test   al,al
  401255:	74 0e                	je     401265 <main+0x9a>
  401257:	48 8b 05 e2 2d 00 00 	mov    rax,QWORD PTR [rip+0x2de2]        # 404040 <correct>
  40125e:	89 c7                	mov    edi,eax
  401260:	e8 3b fe ff ff       	call   4010a0 <_init+0xa0>
  401265:	48 8b 05 c4 2d 00 00 	mov    rax,QWORD PTR [rip+0x2dc4]        # 404030 <wrong>
  40126c:	89 c7                	mov    edi,eax
  40126e:	e8 2d fe ff ff       	call   4010a0 <_init+0xa0>
  401273:	f3 0f 1e fa          	endbr64
  401277:	55                   	push   rbp
  401278:	48 89 e5             	mov    rbp,rsp
  40127b:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
  40127f:	48 89 75 c0          	mov    QWORD PTR [rbp-0x40],rsi
  401283:	c7 45 ec d5 1b f4 2b 	mov    DWORD PTR [rbp-0x14],0x2bf41bd5
  40128a:	c7 45 f0 57 94 1a 83 	mov    DWORD PTR [rbp-0x10],0x831a9457
  401291:	c7 45 f4 01 b9 67 f1 	mov    DWORD PTR [rbp-0xc],0xf167b901
  401298:	c7 45 f8 5f cf 7d b1 	mov    DWORD PTR [rbp-0x8],0xb17dcf5f
  40129f:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  4012a3:	8b 00                	mov    eax,DWORD PTR [rax]
  4012a5:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
  4012a8:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  4012ac:	8b 00                	mov    eax,DWORD PTR [rax]
  4012ae:	89 45 e0             	mov    DWORD PTR [rbp-0x20],eax
  4012b1:	c7 45 e4 00 00 00 00 	mov    DWORD PTR [rbp-0x1c],0x0
  4012b8:	c7 45 fc b9 79 37 9e 	mov    DWORD PTR [rbp-0x4],0x9e3779b9
  4012bf:	c7 45 e8 00 00 00 00 	mov    DWORD PTR [rbp-0x18],0x0
  4012c6:	e9 b8 00 00 00       	jmp    401383 <encrypt+0x110>
  4012cb:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
  4012ce:	c1 e0 04             	shl    eax,0x4
  4012d1:	89 c2                	mov    edx,eax
  4012d3:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
  4012d6:	c1 e8 05             	shr    eax,0x5
  4012d9:	31 c2                	xor    edx,eax
  4012db:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
  4012de:	8d 0c 02             	lea    ecx,[rdx+rax*1]
  4012e1:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
  4012e4:	83 e0 03             	and    eax,0x3
  4012e7:	85 c0                	test   eax,eax
  4012e9:	74 25                	je     401310 <encrypt+0x9d>
  4012eb:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
  4012ee:	83 e0 03             	and    eax,0x3
  4012f1:	83 f8 01             	cmp    eax,0x1
  4012f4:	74 15                	je     40130b <encrypt+0x98>
  4012f6:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
  4012f9:	83 e0 03             	and    eax,0x3
  4012fc:	83 f8 02             	cmp    eax,0x2
  4012ff:	75 05                	jne    401306 <encrypt+0x93>
  401301:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
  401304:	eb 0d                	jmp    401313 <encrypt+0xa0>
  401306:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
  401309:	eb 08                	jmp    401313 <encrypt+0xa0>
  40130b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
  40130e:	eb 03                	jmp    401313 <encrypt+0xa0>
  401310:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
  401313:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
  401316:	01 d0                	add    eax,edx
  401318:	31 c8                	xor    eax,ecx
  40131a:	01 45 dc             	add    DWORD PTR [rbp-0x24],eax
  40131d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  401320:	01 45 e4             	add    DWORD PTR [rbp-0x1c],eax
  401323:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
  401326:	c1 e0 04             	shl    eax,0x4
  401329:	89 c2                	mov    edx,eax
  40132b:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
  40132e:	c1 e8 05             	shr    eax,0x5
  401331:	31 c2                	xor    edx,eax
  401333:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
  401336:	8d 0c 02             	lea    ecx,[rdx+rax*1]
  401339:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
  40133c:	25 00 18 00 00       	and    eax,0x1800
  401341:	85 c0                	test   eax,eax
  401343:	74 2d                	je     401372 <encrypt+0xff>
  401345:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
  401348:	25 00 18 00 00       	and    eax,0x1800
  40134d:	3d 00 08 00 00       	cmp    eax,0x800
  401352:	74 19                	je     40136d <encrypt+0xfa>
  401354:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
  401357:	25 00 18 00 00       	and    eax,0x1800
  40135c:	3d 00 10 00 00       	cmp    eax,0x1000
  401361:	75 05                	jne    401368 <encrypt+0xf5>
  401363:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
  401366:	eb 0d                	jmp    401375 <encrypt+0x102>
  401368:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
  40136b:	eb 08                	jmp    401375 <encrypt+0x102>
  40136d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
  401370:	eb 03                	jmp    401375 <encrypt+0x102>
  401372:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
  401375:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
  401378:	01 d0                	add    eax,edx
  40137a:	31 c8                	xor    eax,ecx
  40137c:	01 45 e0             	add    DWORD PTR [rbp-0x20],eax
  40137f:	83 45 e8 01          	add    DWORD PTR [rbp-0x18],0x1
  401383:	83 7d e8 1f          	cmp    DWORD PTR [rbp-0x18],0x1f
  401387:	0f 86 3e ff ff ff    	jbe    4012cb <encrypt+0x58>
  40138d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  401391:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
  401394:	89 10                	mov    DWORD PTR [rax],edx
  401396:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  40139a:	8b 55 e0             	mov    edx,DWORD PTR [rbp-0x20]
  40139d:	89 10                	mov    DWORD PTR [rax],edx
  40139f:	90                   	nop
  4013a0:	5d                   	pop    rbp
  4013a1:	c3                   	ret
  4013a2:	f3 0f 1e fa          	endbr64
  4013a6:	55                   	push   rbp
  4013a7:	48 89 e5             	mov    rbp,rsp
  4013aa:	48 83 ec 30          	sub    rsp,0x30
  4013ae:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
  4013b2:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  4013b9:	00 00 
  4013bb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4013bf:	31 c0                	xor    eax,eax
  4013c1:	48 b8 d5 34 bd 0e f9 	movabs rax,0x1e5cc8f90ebd34d5
  4013c8:	c8 5c 1e 
  4013cb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  4013cf:	c6 45 eb 00          	mov    BYTE PTR [rbp-0x15],0x0
  4013d3:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
  4013da:	eb 1e                	jmp    4013fa <check+0x58>
  4013dc:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
  4013df:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
  4013e3:	48 01 d0             	add    rax,rdx
  4013e6:	0f b6 10             	movzx  edx,BYTE PTR [rax]
  4013e9:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
  4013ec:	0f b6 44 05 f0       	movzx  eax,BYTE PTR [rbp+rax*1-0x10]
  4013f1:	31 d0                	xor    eax,edx
  4013f3:	08 45 eb             	or     BYTE PTR [rbp-0x15],al
  4013f6:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
  4013fa:	83 7d ec 07          	cmp    DWORD PTR [rbp-0x14],0x7
  4013fe:	76 dc                	jbe    4013dc <check+0x3a>
  401400:	80 7d eb 00          	cmp    BYTE PTR [rbp-0x15],0x0
  401404:	0f 94 c0             	sete   al
  401407:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  40140b:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
  401412:	00 00 
  401414:	74 05                	je     40141b <check+0x79>
  401416:	e8 75 fc ff ff       	call   401090 <_init+0x90>
  40141b:	c9                   	leave
  40141c:	c3                   	ret

Disassembly of section .fini:

0000000000401420 <.fini>:
  401420:	f3 0f 1e fa          	endbr64
  401424:	48 83 ec 08          	sub    rsp,0x8
  401428:	48 83 c4 08          	add    rsp,0x8
  40142c:	c3                   	ret

Disassembly of section LOAD:

000000000205b000 <LOAD>:
	...
