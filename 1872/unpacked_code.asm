
unpacked_code.bin:     file format binary


Disassembly of section .data:
# -----------------------------데이터 영역----------------------------------------





00007ffff7faf000 <.data>:
	...
    7ffff7faf028:	01 00                	add    DWORD PTR [rax],eax
    7ffff7faf02a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf02c:	12 00                	adc    al,BYTE PTR [rax]
    7ffff7faf02e:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf030:	c3                   	ret
    7ffff7faf031:	43 00 00             	rex.XB add BYTE PTR [r8],al
    7ffff7faf034:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf036:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf038:	02 00                	add    al,BYTE PTR [rax]
    7ffff7faf03a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf03c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf03e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf040:	10 00                	adc    BYTE PTR [rax],al
    7ffff7faf042:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf044:	12 00                	adc    al,BYTE PTR [rax]
    7ffff7faf046:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf048:	dc 38                	fdivr  QWORD PTR [rax]
    7ffff7faf04a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf04c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf04e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf050:	e7 0a                	out    0xa,eax
    7ffff7faf052:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf054:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf056:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf058:	1b 00                	sbb    eax,DWORD PTR [rax]
    7ffff7faf05a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf05c:	12 00                	adc    al,BYTE PTR [rax]
    7ffff7faf05e:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf060:	c3                   	ret
    7ffff7faf061:	43 00 00             	rex.XB add BYTE PTR [r8],al
    7ffff7faf064:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf066:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf068:	02 00                	add    al,BYTE PTR [rax]
    7ffff7faf06a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf06c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf06e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf070:	2f                   	(bad)
    7ffff7faf071:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf073:	00 12                	add    BYTE PTR [rdx],dl
    7ffff7faf075:	00 08                	add    BYTE PTR [rax],cl
    7ffff7faf077:	00 80 23 00 00 00    	add    BYTE PTR [rax+0x23],al
    7ffff7faf07d:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf07f:	00 3b                	add    BYTE PTR [rbx],bh
	...
    7ffff7faf0b5:	5f                   	pop    rdi
    7ffff7faf0b6:	55                   	push   rbp
    7ffff7faf0b7:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    7ffff7faf0b8:	77 69                	ja     0x7ffff7faf123
    7ffff7faf0ba:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    7ffff7faf0bb:	64 5f                	fs pop rdi
    7ffff7faf0bd:	52                   	push   rdx
    7ffff7faf0be:	65 73 75             	gs jae 0x7ffff7faf136
    7ffff7faf0c1:	6d                   	ins    DWORD PTR es:[rdi],dx
    7ffff7faf0c2:	65 00 5f 62          	add    BYTE PTR gs:[rdi+0x62],bl
    7ffff7faf0c6:	61                   	(bad)
    7ffff7faf0c7:	73 6d                	jae    0x7ffff7faf136
    7ffff7faf0c9:	5f                   	pop    rdi
    7ffff7faf0ca:	6d                   	ins    DWORD PTR es:[rdi],dx
    7ffff7faf0cb:	61                   	(bad)
    7ffff7faf0cc:	69 6e 00 72 75 73 74 	imul   ebp,DWORD PTR [rsi+0x0],0x74737572
    7ffff7faf0d3:	5f                   	pop    rdi
    7ffff7faf0d4:	65 68 5f 70 65 72    	gs push 0x7265705f
    7ffff7faf0da:	73 6f                	jae    0x7ffff7faf14b
    7ffff7faf0dc:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    7ffff7faf0dd:	61                   	(bad)
    7ffff7faf0de:	6c                   	ins    BYTE PTR es:[rdi],dx
    7ffff7faf0df:	69 74 79 00 5f 62 61 	imul   esi,DWORD PTR [rcx+rdi*2+0x0],0x7361625f
    7ffff7faf0e6:	73 
    7ffff7faf0e7:	6d                   	ins    DWORD PTR es:[rdi],dx
    7ffff7faf0e8:	5f                   	pop    rdi
    7ffff7faf0e9:	73 74                	jae    0x7ffff7faf15f
    7ffff7faf0eb:	61                   	(bad)
    7ffff7faf0ec:	72 74                	jb     0x7ffff7faf162
    7ffff7faf0ee:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf0f0:	b8 9b 00 00 00       	mov    eax,0x9b
    7ffff7faf0f5:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf0f7:	00 08                	add    BYTE PTR [rax],cl
    7ffff7faf0f9:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf0fb:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf0fd:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf0ff:	00 f8                	add    al,bh
    7ffff7faf101:	04 00                	add    al,0x0
    7ffff7faf103:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf105:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf107:	00 c8                	add    al,cl
    7ffff7faf109:	9b                   	fwait
    7ffff7faf10a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf10c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf10e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf110:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf112:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf114:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf116:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf118:	b8 04 00 00 00       	mov    eax,0x4
    7ffff7faf11d:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf11f:	00 d8                	add    al,bl
    7ffff7faf121:	9b                   	fwait
    7ffff7faf122:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf124:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf126:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf128:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf12a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf12c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf12e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf130:	98                   	cwde
    7ffff7faf131:	04 00                	add    al,0x0
    7ffff7faf133:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf135:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf137:	00 e8                	add    al,ch
    7ffff7faf139:	9b                   	fwait
    7ffff7faf13a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf13c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf13e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf140:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf142:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf144:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf146:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf148:	78 04                	js     0x7ffff7faf14e
    7ffff7faf14a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf14c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf14e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf150:	f8                   	clc
    7ffff7faf151:	9b                   	fwait
    7ffff7faf152:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf154:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf156:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf158:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf15a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf15c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf15e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf160:	74 45                	je     0x7ffff7faf1a7
    7ffff7faf162:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf164:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf166:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf168:	00 9c 00 00 00 00 00 	add    BYTE PTR [rax+rax*1+0x0],bl
    7ffff7faf16f:	00 08                	add    BYTE PTR [rax],cl
    7ffff7faf171:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf173:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf175:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf177:	00 8d 45 00 00 00    	add    BYTE PTR [rbp+0x45],cl
    7ffff7faf17d:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf17f:	00 08                	add    BYTE PTR [rax],cl
    7ffff7faf181:	9c                   	pushf
    7ffff7faf182:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf184:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf186:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf188:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf18a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf18c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf18e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf190:	a9 45 00 00 00       	test   eax,0x45
    7ffff7faf195:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf197:	00 10                	add    BYTE PTR [rax],dl
    7ffff7faf199:	9c                   	pushf
    7ffff7faf19a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf19c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf19e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1a0:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf1a2:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1a4:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1a6:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1a8:	c3                   	ret
    7ffff7faf1a9:	43 00 00             	rex.XB add BYTE PTR [r8],al
    7ffff7faf1ac:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1ae:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1b0:	e8 9c 00 00 00       	call   0x7ffff7faf251
    7ffff7faf1b5:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1b7:	00 08                	add    BYTE PTR [rax],cl
    7ffff7faf1b9:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1bb:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1bd:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1bf:	00 41 9a             	add    BYTE PTR [rcx-0x66],al
    7ffff7faf1c2:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1c4:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1c6:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1c8:	f0 9c                	lock pushf
    7ffff7faf1ca:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1cc:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1ce:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1d0:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf1d2:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1d4:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1d6:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1d8:	3c 9a                	cmp    al,0x9a
    7ffff7faf1da:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1dc:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1de:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1e0:	f8                   	clc
    7ffff7faf1e1:	9c                   	pushf
    7ffff7faf1e2:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1e4:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1e6:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1e8:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf1ea:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1ec:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1ee:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1f0:	0d 9a 00 00 00       	or     eax,0x9a
    7ffff7faf1f5:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1f7:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1f9:	9d                   	popf
    7ffff7faf1fa:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1fc:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf1fe:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf200:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf202:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf204:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf206:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf208:	aa                   	stos   BYTE PTR es:[rdi],al
    7ffff7faf209:	99                   	cdq
    7ffff7faf20a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf20c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf20e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf210:	08 9d 00 00 00 00    	or     BYTE PTR [rbp+0x0],bl
    7ffff7faf216:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf218:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf21a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf21c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf21e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf220:	df 99 00 00 00 00    	fistp  WORD PTR [rcx+0x0]
    7ffff7faf226:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf228:	10 9d 00 00 00 00    	adc    BYTE PTR [rbp+0x0],bl
    7ffff7faf22e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf230:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf232:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf234:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf236:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf238:	2a 9b 00 00 00 00    	sub    bl,BYTE PTR [rbx+0x0]
    7ffff7faf23e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf240:	18 9d 00 00 00 00    	sbb    BYTE PTR [rbp+0x0],bl
    7ffff7faf246:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf248:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf24a:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf24c:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf24e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf250:	b2 9a                	mov    dl,0x9a
    7ffff7faf252:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf254:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf256:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf258:	20 9d 00 00 00 00    	and    BYTE PTR [rbp+0x0],bl
    7ffff7faf25e:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf260:	08 00                	or     BYTE PTR [rax],al
    7ffff7faf262:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf264:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf266:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf268:	2f                   	(bad)
    7ffff7faf269:	9b                   	fwait
	...
    7ffff7faf2b6:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf2b8:	c7 41 00 00 c1 41 00 	mov    DWORD PTR [rcx+0x0],0x41c100
    7ffff7faf2bf:	00 c1                	add    cl,al
    7ffff7faf2c1:	41 00 00             	add    BYTE PTR [r8],al
    7ffff7faf2c4:	c1 41 00 00          	rol    DWORD PTR [rcx+0x0],0x0
    7ffff7faf2c8:	c1 41 00 00          	rol    DWORD PTR [rcx+0x0],0x0
    7ffff7faf2cc:	c1 41 00 00          	rol    DWORD PTR [rcx+0x0],0x0
    7ffff7faf2d0:	c1 41 00 00          	rol    DWORD PTR [rcx+0x0],0x0
    7ffff7faf2d4:	b1 41                	mov    cl,0x41
    7ffff7faf2d6:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf2d8:	b9 41 00 00 be       	mov    ecx,0xbe000041
    7ffff7faf2dd:	41 00 00             	add    BYTE PTR [r8],al
    7ffff7faf2e0:	01 00                	add    DWORD PTR [rax],eax
	...
    7ffff7faf2ee:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf2f0:	01 00                	add    DWORD PTR [rax],eax
    7ffff7faf2f2:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf2f4:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf2f6:	00 00                	add    BYTE PTR [rax],al
    7ffff7faf2f8:	40 ce                	rex (bad)
    7ffff7faf2fa:	22 4b 1a             	and    cl,BYTE PTR [rbx+0x1a]
    7ffff7faf2fd:	68 3c ee a1 9c       	push   0xffffffff9ca1ee3c
    7ffff7faf302:	77 05                	ja     0x7ffff7faf309
    7ffff7faf304:	11 ca                	adc    edx,ecx
    7ffff7faf306:	8f                   	(bad)
    7ffff7faf307:	8c 2e                	mov    WORD PTR [rsi],gs
    7ffff7faf309:	4b 8f                	rex.WXB (bad)
    7ffff7faf30b:	cb                   	retf
    7ffff7faf30c:	f9                   	stc
    7ffff7faf30d:	38 95 af 39 86 9c    	cmp    BYTE PTR [rbp-0x6379c651],dl
    7ffff7faf313:	81 55 dd a2 a4 ec 82 	adc    DWORD PTR [rbp-0x23],0x82eca4a2
    7ffff7faf31a:	d7                   	xlat   BYTE PTR ds:[rbx]
    7ffff7faf31b:	5b                   	pop    rbx
    7ffff7faf31c:	20 63 c7             	and    BYTE PTR [rbx-0x39],ah
    7ffff7faf31f:	23 05 b8 83 ca a6    	and    eax,DWORD PTR [rip+0xffffffffa6ca83b8]        # 0x7fff9ec576dd
    7ffff7faf325:	91                   	xchg   ecx,eax
    7ffff7faf326:	df f0                	fcomip st,st(0)
    7ffff7faf328:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    7ffff7faf329:	e0 f5                	loopne 0x7ffff7faf320
    7ffff7faf32b:	b9 72 f0 5f 07       	mov    ecx,0x75ff072
    7ffff7faf330:	db 2d 15 d0 4d 98    	fld    TBYTE PTR [rip+0xffffffff984dd015]        # 0x7fff9048c34b
    7ffff7faf336:	cc                   	int3
    7ffff7faf337:	a6                   	cmps   BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
    7ffff7faf338:	2c 9a                	sub    al,0x9a
    7ffff7faf33a:	37                   	(bad)
    7ffff7faf33b:	00 78 79             	add    BYTE PTR [rax+0x79],bh
    7ffff7faf33e:	c1 63 c4 81          	shl    DWORD PTR [rbx-0x3c],0x81
    7ffff7faf342:	55                   	push   rbp
    7ffff7faf343:	7d 78                	jge    0x7ffff7faf3bd
    7ffff7faf345:	12 4c 96 e9          	adc    cl,BYTE PTR [rsi+rdx*4-0x17]
    7ffff7faf349:	af                   	scas   eax,DWORD PTR es:[rdi]
    7ffff7faf34a:	c3                   	ret
    7ffff7faf34b:	01 60 28             	add    DWORD PTR [rax+0x28],esp
    7ffff7faf34e:	df 5c cc 50          	fistp  WORD PTR [rsp+rcx*8+0x50]
    7ffff7faf352:	b6 d0                	mov    dh,0xd0
    7ffff7faf354:	70 d1                	jo     0x7ffff7faf327
    7ffff7faf356:	4b 93                	rex.WXB xchg r11,rax
    7ffff7faf358:	f1                   	int1
    7ffff7faf359:	08 1a                	or     BYTE PTR [rdx],bl
    7ffff7faf35b:	51                   	push   rcx
    7ffff7faf35c:	0d 0d c2 2d 62       	or     eax,0x622dc20d
    7ffff7faf361:	0c 86                	or     al,0x86
    7ffff7faf363:	34 cd                	xor    al,0xcd
    7ffff7faf365:	dc cc                	fmul   st(4),st
    7ffff7faf367:	de 28                	fisubr WORD PTR [rax]
    7ffff7faf369:	d8 b9 33 8c 6e f9    	fdivr  DWORD PTR [rcx-0x69173cd]
    7ffff7faf36f:	a4                   	movs   BYTE PTR es:[rdi],BYTE PTR ds:[rsi]



    7ffff7faf370:	58                   	pop    rax
    7ffff7faf371:	4e 55                	rex.WRX push rbp
    7ffff7faf373:	59                   	pop    rcx
    7ffff7faf374:	33 54 46 5f          	xor    edx,DWORD PTR [rsi+rax*2+0x5f]
    7ffff7faf378:	a0 9d e6 3b 04 f4 60 	movabs al,ds:0xa91c60f4043be69d
    7ffff7faf37f:	1c a9 
    7ffff7faf381:	41 8b a9 dc db d5 89 	mov    ebp,DWORD PTR [r9-0x762a2424]
    7ffff7faf388:	a1 14 e0 cc e8 0d 67 	movabs eax,ds:0x6e79670de8cce014
    7ffff7faf38f:	79 6e 
    7ffff7faf391:	a2 e0 d0 74 23 2e 42 	movabs ds:0x7257422e2374d0e0,al
    7ffff7faf398:	57 72 
    7ffff7faf39a:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    7ffff7faf39b:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    7ffff7faf39c:	67 43 6f             	rex.XB outs dx,DWORD PTR ds:[esi]
    7ffff7faf39f:	72 72                	jb     0x7ffff7faf413
    7ffff7faf3a1:	65 63 74 56 69       	movsxd esi,DWORD PTR gs:[rsi+rdx*2+0x69]
    7ffff7faf3a6:	72 74                	jb     0x7ffff7faf41c
    7ffff7faf3a8:	75 61                	jne    0x7ffff7faf40b
    7ffff7faf3aa:	6c                   	ins    BYTE PTR es:[rdi],dx
    7ffff7faf3ab:	41 6c                	rex.B ins BYTE PTR es:[rdi],dx
    7ffff7faf3ad:	6c                   	ins    BYTE PTR es:[rdi],dx
    7ffff7faf3ae:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    7ffff7faf3af:	63 00                	movsxd eax,DWORD PTR [rax]
    7ffff7faf3b1:	56                   	push   rsi
    7ffff7faf3b2:	69 72 74 75 61 6c 46 	imul   esi,DWORD PTR [rdx+0x74],0x466c6175
    7ffff7faf3b9:	72 65                	jb     0x7ffff7faf420
    7ffff7faf3bb:	65 00 47 65          	add    BYTE PTR gs:[rdi+0x65],al
    7ffff7faf3bf:	74 53                	je     0x7ffff7faf414
    7ffff7faf3c1:	74 64                	je     0x7ffff7faf427
    7ffff7faf3c3:	48 61                	rex.W (bad)
    7ffff7faf3c5:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    7ffff7faf3c6:	64 6c                	fs ins BYTE PTR es:[rdi],dx
    7ffff7faf3c8:	65 00 52 65          	add    BYTE PTR gs:[rdx+0x65],dl
    7ffff7faf3cc:	61                   	(bad)
    7ffff7faf3cd:	64 46 69 6c 65 00 57 	imul   r13d,DWORD PTR fs:[rbp+r12*2+0x0],0x74697257
    7ffff7faf3d4:	72 69 74 
    7ffff7faf3d7:	65 46 69 6c 65 00 47 	imul   r13d,DWORD PTR gs:[rbp+r12*2+0x0],0x4f746547
    7ffff7faf3de:	65 74 4f 
    7ffff7faf3e1:	76 65                	jbe    0x7ffff7faf448
    7ffff7faf3e3:	72 6c                	jb     0x7ffff7faf451
    7ffff7faf3e5:	61                   	(bad)
    7ffff7faf3e6:	70 70                	jo     0x7ffff7faf458
    7ffff7faf3e8:	65 64 52             	gs fs push rdx
    7ffff7faf3eb:	65 73 75             	gs jae 0x7ffff7faf463
    7ffff7faf3ee:	6c                   	ins    BYTE PTR es:[rdi],dx
    7ffff7faf3ef:	74 00                	je     0x7ffff7faf3f1
    7ffff7faf3f1:	47                   	rex.RXB
    7ffff7faf3f2:	65 74 4c             	gs je  0x7ffff7faf441
    7ffff7faf3f5:	61                   	(bad)
    7ffff7faf3f6:	73 74                	jae    0x7ffff7faf46c
    7ffff7faf3f8:	45 72 72             	rex.RB jb 0x7ffff7faf46d
    7ffff7faf3fb:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    7ffff7faf3fc:	72 00                	jb     0x7ffff7faf3fe
    7ffff7faf3fe:	53                   	push   rbx
    7ffff7faf3ff:	65 74 43             	gs je  0x7ffff7faf445
    7ffff7faf402:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    7ffff7faf403:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    7ffff7faf404:	73 6f                	jae    0x7ffff7faf475
    7ffff7faf406:	6c                   	ins    BYTE PTR es:[rdi],dx
    7ffff7faf407:	65 43 50             	gs rex.XB push r8
    7ffff7faf40a:	00 53 65             	add    BYTE PTR [rbx+0x65],dl
    7ffff7faf40d:	74 43                	je     0x7ffff7faf452
    7ffff7faf40f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    7ffff7faf410:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    7ffff7faf411:	73 6f                	jae    0x7ffff7faf482
    7ffff7faf413:	6c                   	ins    BYTE PTR es:[rdi],dx
    7ffff7faf414:	65 4f 75 74          	gs rex.WRXB jne 0x7ffff7faf48c
    7ffff7faf418:	70 75                	jo     0x7ffff7faf48f
    7ffff7faf41a:	74 43                	je     0x7ffff7faf45f
    7ffff7faf41c:	50                   	push   rax
	...
    7ffff7fb11fd:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb11ff:	00 f9                	add    cl,bh
    7ffff7fb1201:	48 89 cb             	mov    rbx,rcx
    7ffff7fb1204:	73 07                	jae    0x7ffff7fb120d
    7ffff7fb1206:	48 85 db             	test   rbx,rbx
    7ffff7fb1209:	74 02                	je     0x7ffff7fb120d
    7ffff7fb120b:	eb 0c                	jmp    0x7ffff7fb1219
    7ffff7fb120d:	48 83 ec 48          	sub    rsp,0x48
    7ffff7fb1211:	6a 03                	push   0x3
    7ffff7fb1213:	6a 02                	push   0x2
    7ffff7fb1215:	48 8d 1c 24          	lea    rbx,[rsp]
    7ffff7fb1219:	51                   	push   rcx
    7ffff7fb121a:	48 8d 3d 5f dc ff ff 	lea    rdi,[rip+0xffffffffffffdc5f]        # 0x7ffff7faee80
    7ffff7fb1221:	48 8d 35 70 78 00 00 	lea    rsi,[rip+0x7870]        # 0x7ffff7fb8a98
    7ffff7fb1228:	48 89 7b 20          	mov    QWORD PTR [rbx+0x20],rdi
    7ffff7fb122c:	e8 17 22 00 00       	call   0x7ffff7fb3448
    7ffff7fb1231:	48 89 df             	mov    rdi,rbx
    7ffff7fb1234:	e8 6d 22 00 00       	call   0x7ffff7fb34a6
    7ffff7fb1239:	59                   	pop    rcx
    7ffff7fb123a:	c3                   	ret
    7ffff7fb123b:	41 57                	push   r15
    7ffff7fb123d:	41 56                	push   r14
    7ffff7fb123f:	41 55                	push   r13
    7ffff7fb1241:	41 54                	push   r12
    7ffff7fb1243:	53                   	push   rbx
    7ffff7fb1244:	49 89 d6             	mov    r14,rdx
    7ffff7fb1247:	49 89 f7             	mov    r15,rsi
    7ffff7fb124a:	48 89 fb             	mov    rbx,rdi
    7ffff7fb124d:	4c 8b 2d 14 79 00 00 	mov    r13,QWORD PTR [rip+0x7914]        # 0x7ffff7fb8b68
    7ffff7fb1254:	48 8b bb 00 00 01 00 	mov    rdi,QWORD PTR [rbx+0x10000]
    7ffff7fb125b:	4d 85 f6             	test   r14,r14
    7ffff7fb125e:	74 4f                	je     0x7ffff7fb12af
    7ffff7fb1260:	41 bc 00 00 01 00    	mov    r12d,0x10000
    7ffff7fb1266:	49 29 fc             	sub    r12,rdi
    7ffff7fb1269:	48 01 df             	add    rdi,rbx
    7ffff7fb126c:	4d 39 e6             	cmp    r14,r12
    7ffff7fb126f:	4d 0f 42 e6          	cmovb  r12,r14
    7ffff7fb1273:	4c 89 fe             	mov    rsi,r15
    7ffff7fb1276:	4c 89 e2             	mov    rdx,r12
    7ffff7fb1279:	41 ff d5             	call   r13
    7ffff7fb127c:	48 8b 83 00 00 01 00 	mov    rax,QWORD PTR [rbx+0x10000]
    7ffff7fb1283:	4a 8d 0c 20          	lea    rcx,[rax+r12*1]
    7ffff7fb1287:	48 89 8b 00 00 01 00 	mov    QWORD PTR [rbx+0x10000],rcx
    7ffff7fb128e:	4d 29 e6             	sub    r14,r12
    7ffff7fb1291:	4d 01 e7             	add    r15,r12
    7ffff7fb1294:	4c 01 e0             	add    rax,r12
    7ffff7fb1297:	48 05 00 00 ff ff    	add    rax,0xffffffffffff0000
    7ffff7fb129d:	48 3d fe ff fe ff    	cmp    rax,0xfffffffffffefffe
    7ffff7fb12a3:	77 af                	ja     0x7ffff7fb1254
    7ffff7fb12a5:	48 89 df             	mov    rdi,rbx
    7ffff7fb12a8:	e8 64 01 00 00       	call   0x7ffff7fb1411
    7ffff7fb12ad:	eb a5                	jmp    0x7ffff7fb1254
    7ffff7fb12af:	c6 04 3b 0a          	mov    BYTE PTR [rbx+rdi*1],0xa
    7ffff7fb12b3:	48 ff 83 00 00 01 00 	inc    QWORD PTR [rbx+0x10000]
    7ffff7fb12ba:	5b                   	pop    rbx
    7ffff7fb12bb:	41 5c                	pop    r12
    7ffff7fb12bd:	41 5d                	pop    r13
    7ffff7fb12bf:	41 5e                	pop    r14
    7ffff7fb12c1:	41 5f                	pop    r15
    7ffff7fb12c3:	c3                   	ret
    7ffff7fb12c4:	48 85 ff             	test   rdi,rdi
    7ffff7fb12c7:	74 11                	je     0x7ffff7fb12da
    7ffff7fb12c9:	48 89 f8             	mov    rax,rdi
    7ffff7fb12cc:	6a 01                	push   0x1
    7ffff7fb12ce:	5a                   	pop    rdx
    7ffff7fb12cf:	48 89 f7             	mov    rdi,rsi
    7ffff7fb12d2:	48 89 c6             	mov    rsi,rax
    7ffff7fb12d5:	e9 34 20 00 00       	jmp    0x7ffff7fb330e
    7ffff7fb12da:	c3                   	ret
    7ffff7fb12db:	41 57                	push   r15
    7ffff7fb12dd:	41 56                	push   r14
    7ffff7fb12df:	41 55                	push   r13
    7ffff7fb12e1:	41 54                	push   r12
    7ffff7fb12e3:	53                   	push   rbx
    7ffff7fb12e4:	48 89 d3             	mov    rbx,rdx
    7ffff7fb12e7:	49 89 f6             	mov    r14,rsi
    7ffff7fb12ea:	49 89 ff             	mov    r15,rdi
    7ffff7fb12ed:	48 89 d0             	mov    rax,rdx
    7ffff7fb12f0:	48 c1 e8 03          	shr    rax,0x3
    7ffff7fb12f4:	48 01 d0             	add    rax,rdx
    7ffff7fb12f7:	48 83 c0 02          	add    rax,0x2
    7ffff7fb12fb:	49 bc ff ff ff ff ff 	movabs r12,0x3ffffffffffffff
    7ffff7fb1302:	ff ff 03 
    7ffff7fb1305:	4c 39 e0             	cmp    rax,r12
    7ffff7fb1308:	4c 0f 42 e0          	cmovb  r12,rax
    7ffff7fb130c:	4c 89 e7             	mov    rdi,r12
    7ffff7fb130f:	e8 b7 50 00 00       	call   0x7ffff7fb63cb
    7ffff7fb1314:	49 89 c5             	mov    r13,rax
    7ffff7fb1317:	48 8d 14 dd 00 00 00 	lea    rdx,[rbx*8+0x0]
    7ffff7fb131e:	00 
    7ffff7fb131f:	48 89 c7             	mov    rdi,rax
    7ffff7fb1322:	4c 89 f6             	mov    rsi,r14
    7ffff7fb1325:	ff 15 3d 78 00 00    	call   QWORD PTR [rip+0x783d]        # 0x7ffff7fb8b68
    7ffff7fb132b:	4d 89 2f             	mov    QWORD PTR [r15],r13
    7ffff7fb132e:	49 89 5f 08          	mov    QWORD PTR [r15+0x8],rbx
    7ffff7fb1332:	4d 89 67 10          	mov    QWORD PTR [r15+0x10],r12
    7ffff7fb1336:	5b                   	pop    rbx
    7ffff7fb1337:	41 5c                	pop    r12
    7ffff7fb1339:	41 5d                	pop    r13
    7ffff7fb133b:	41 5e                	pop    r14
    7ffff7fb133d:	41 5f                	pop    r15
    7ffff7fb133f:	c3                   	ret
    7ffff7fb1340:	55                   	push   rbp
    7ffff7fb1341:	41 57                	push   r15
    7ffff7fb1343:	41 56                	push   r14
    7ffff7fb1345:	41 55                	push   r13
    7ffff7fb1347:	41 54                	push   r12
    7ffff7fb1349:	53                   	push   rbx
    7ffff7fb134a:	50                   	push   rax
    7ffff7fb134b:	49 89 d6             	mov    r14,rdx
    7ffff7fb134e:	49 89 f7             	mov    r15,rsi
    7ffff7fb1351:	48 89 fb             	mov    rbx,rdi
    7ffff7fb1354:	48 8b 37             	mov    rsi,QWORD PTR [rdi]
    7ffff7fb1357:	4c 8b 6f 10          	mov    r13,QWORD PTR [rdi+0x10]
    7ffff7fb135b:	48 89 f0             	mov    rax,rsi
    7ffff7fb135e:	4c 29 e8             	sub    rax,r13
    7ffff7fb1361:	48 39 d0             	cmp    rax,rdx
    7ffff7fb1364:	72 2a                	jb     0x7ffff7fb1390
    7ffff7fb1366:	48 8b 7b 08          	mov    rdi,QWORD PTR [rbx+0x8]
    7ffff7fb136a:	4b 8d 2c 2e          	lea    rbp,[r14+r13*1]
    7ffff7fb136e:	4c 01 ef             	add    rdi,r13
    7ffff7fb1371:	4c 89 fe             	mov    rsi,r15
    7ffff7fb1374:	4c 89 f2             	mov    rdx,r14
    7ffff7fb1377:	ff 15 eb 77 00 00    	call   QWORD PTR [rip+0x77eb]        # 0x7ffff7fb8b68
    7ffff7fb137d:	48 89 6b 10          	mov    QWORD PTR [rbx+0x10],rbp
    7ffff7fb1381:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb1385:	5b                   	pop    rbx
    7ffff7fb1386:	41 5c                	pop    r12
    7ffff7fb1388:	41 5d                	pop    r13
    7ffff7fb138a:	41 5e                	pop    r14
    7ffff7fb138c:	41 5f                	pop    r15
    7ffff7fb138e:	5d                   	pop    rbp
    7ffff7fb138f:	c3                   	ret
    7ffff7fb1390:	4b 8d 2c 2e          	lea    rbp,[r14+r13*1]
    7ffff7fb1394:	48 8d 04 36          	lea    rax,[rsi+rsi*1]
    7ffff7fb1398:	48 39 e8             	cmp    rax,rbp
    7ffff7fb139b:	48 0f 46 c5          	cmovbe rax,rbp
    7ffff7fb139f:	48 83 f8 09          	cmp    rax,0x9
    7ffff7fb13a3:	6a 08                	push   0x8
    7ffff7fb13a5:	41 5c                	pop    r12
    7ffff7fb13a7:	4c 0f 43 e0          	cmovae r12,rax
    7ffff7fb13ab:	48 85 f6             	test   rsi,rsi
    7ffff7fb13ae:	74 11                	je     0x7ffff7fb13c1
    7ffff7fb13b0:	48 8b 7b 08          	mov    rdi,QWORD PTR [rbx+0x8]
    7ffff7fb13b4:	6a 01                	push   0x1
    7ffff7fb13b6:	5a                   	pop    rdx
    7ffff7fb13b7:	4c 89 e1             	mov    rcx,r12
    7ffff7fb13ba:	e8 58 1f 00 00       	call   0x7ffff7fb3317
    7ffff7fb13bf:	eb 08                	jmp    0x7ffff7fb13c9
    7ffff7fb13c1:	4c 89 e7             	mov    rdi,r12
    7ffff7fb13c4:	e8 3a 00 00 00       	call   0x7ffff7fb1403
    7ffff7fb13c9:	48 89 c7             	mov    rdi,rax
    7ffff7fb13cc:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb13d0:	4c 89 23             	mov    QWORD PTR [rbx],r12
    7ffff7fb13d3:	eb 99                	jmp    0x7ffff7fb136e
    7ffff7fb13d5:	55                   	push   rbp
    7ffff7fb13d6:	41 56                	push   r14
    7ffff7fb13d8:	53                   	push   rbx
    7ffff7fb13d9:	89 f5                	mov    ebp,esi
    7ffff7fb13db:	48 89 fb             	mov    rbx,rdi
    7ffff7fb13de:	4c 8b 77 10          	mov    r14,QWORD PTR [rdi+0x10]
    7ffff7fb13e2:	4c 3b 37             	cmp    r14,QWORD PTR [rdi]
    7ffff7fb13e5:	75 08                	jne    0x7ffff7fb13ef
    7ffff7fb13e7:	48 89 df             	mov    rdi,rbx
    7ffff7fb13ea:	e8 31 1f 00 00       	call   0x7ffff7fb3320
    7ffff7fb13ef:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
    7ffff7fb13f3:	42 88 2c 30          	mov    BYTE PTR [rax+r14*1],bpl
    7ffff7fb13f7:	49 ff c6             	inc    r14
    7ffff7fb13fa:	4c 89 73 10          	mov    QWORD PTR [rbx+0x10],r14
    7ffff7fb13fe:	5b                   	pop    rbx
    7ffff7fb13ff:	41 5e                	pop    r14
    7ffff7fb1401:	5d                   	pop    rbp
    7ffff7fb1402:	c3                   	ret
    7ffff7fb1403:	8a 05 f7 7e 00 00    	mov    al,BYTE PTR [rip+0x7ef7]        # 0x7ffff7fb9300
    7ffff7fb1409:	6a 01                	push   0x1
    7ffff7fb140b:	5e                   	pop    rsi
    7ffff7fb140c:	e9 f4 1e 00 00       	jmp    0x7ffff7fb3305
    7ffff7fb1411:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb1415:	4c 8b 87 00 00 01 00 	mov    r8,QWORD PTR [rdi+0x10000]
    7ffff7fb141c:	48 8b 05 d5 7e 00 00 	mov    rax,QWORD PTR [rip+0x7ed5]        # 0x7ffff7fb92f8
    7ffff7fb1423:	6a 01                	push   0x1
    7ffff7fb1425:	59                   	pop    rcx
    7ffff7fb1426:	48 89 fa             	mov    rdx,rdi
    7ffff7fb1429:	ff 50 50             	call   QWORD PTR [rax+0x50]
    7ffff7fb142c:	48 83 a7 00 00 01 00 	and    QWORD PTR [rdi+0x10000],0x0
    7ffff7fb1433:	00 
    7ffff7fb1434:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb1438:	c3                   	ret
    7ffff7fb1439:	48 8b 46 08          	mov    rax,QWORD PTR [rsi+0x8]
    7ffff7fb143d:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
    7ffff7fb1441:	48 89 ca             	mov    rdx,rcx
    7ffff7fb1444:	48 f7 da             	neg    rdx
    7ffff7fb1447:	48 0f 48 d1          	cmovs  rdx,rcx
    7ffff7fb144b:	48 83 fa 03          	cmp    rdx,0x3
    7ffff7fb144f:	73 0a                	jae    0x7ffff7fb145b
    7ffff7fb1451:	48 89 c2             	mov    rdx,rax
    7ffff7fb1454:	48 8b 06             	mov    rax,QWORD PTR [rsi]
    7ffff7fb1457:	31 f6                	xor    esi,esi
    7ffff7fb1459:	eb 08                	jmp    0x7ffff7fb1463
    7ffff7fb145b:	4c 8b 06             	mov    r8,QWORD PTR [rsi]
    7ffff7fb145e:	6a 01                	push   0x1
    7ffff7fb1460:	5e                   	pop    rsi
    7ffff7fb1461:	31 d2                	xor    edx,edx
    7ffff7fb1463:	48 85 c9             	test   rcx,rcx
    7ffff7fb1466:	0f 9e 07             	setle  BYTE PTR [rdi]
    7ffff7fb1469:	48 89 77 10          	mov    QWORD PTR [rdi+0x10],rsi
    7ffff7fb146d:	4c 89 47 18          	mov    QWORD PTR [rdi+0x18],r8
    7ffff7fb1471:	48 89 47 20          	mov    QWORD PTR [rdi+0x20],rax
    7ffff7fb1475:	48 89 57 28          	mov    QWORD PTR [rdi+0x28],rdx
    7ffff7fb1479:	c3                   	ret
    7ffff7fb147a:	41 57                	push   r15
    7ffff7fb147c:	41 56                	push   r14
    7ffff7fb147e:	41 54                	push   r12
    7ffff7fb1480:	53                   	push   rbx
    7ffff7fb1481:	50                   	push   rax
    7ffff7fb1482:	48 89 f0             	mov    rax,rsi
    7ffff7fb1485:	4c 8b 7e 10          	mov    r15,QWORD PTR [rsi+0x10]
    7ffff7fb1489:	4c 89 fe             	mov    rsi,r15
    7ffff7fb148c:	48 f7 de             	neg    rsi
    7ffff7fb148f:	49 0f 48 f7          	cmovs  rsi,r15
    7ffff7fb1493:	48 89 fb             	mov    rbx,rdi
    7ffff7fb1496:	4c 8b 30             	mov    r14,QWORD PTR [rax]
    7ffff7fb1499:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
    7ffff7fb149d:	48 83 fe 03          	cmp    rsi,0x3
    7ffff7fb14a1:	73 15                	jae    0x7ffff7fb14b8
    7ffff7fb14a3:	49 89 c4             	mov    r12,rax
    7ffff7fb14a6:	4c 89 f7             	mov    rdi,r14
    7ffff7fb14a9:	e8 55 67 00 00       	call   0x7ffff7fb7c03
    7ffff7fb14ae:	31 c9                	xor    ecx,ecx
    7ffff7fb14b0:	4c 89 f0             	mov    rax,r14
    7ffff7fb14b3:	4c 89 e6             	mov    rsi,r12
    7ffff7fb14b6:	eb 03                	jmp    0x7ffff7fb14bb
    7ffff7fb14b8:	6a 01                	push   0x1
    7ffff7fb14ba:	59                   	pop    rcx
    7ffff7fb14bb:	4d 85 ff             	test   r15,r15
    7ffff7fb14be:	0f 9e 03             	setle  BYTE PTR [rbx]
    7ffff7fb14c1:	48 89 4b 10          	mov    QWORD PTR [rbx+0x10],rcx
    7ffff7fb14c5:	4c 89 73 18          	mov    QWORD PTR [rbx+0x18],r14
    7ffff7fb14c9:	48 89 43 20          	mov    QWORD PTR [rbx+0x20],rax
    7ffff7fb14cd:	48 89 73 28          	mov    QWORD PTR [rbx+0x28],rsi
    7ffff7fb14d1:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb14d5:	5b                   	pop    rbx
    7ffff7fb14d6:	41 5c                	pop    r12
    7ffff7fb14d8:	41 5e                	pop    r14
    7ffff7fb14da:	41 5f                	pop    r15
    7ffff7fb14dc:	c3                   	ret
    7ffff7fb14dd:	4c 8b 46 10          	mov    r8,QWORD PTR [rsi+0x10]
    7ffff7fb14e1:	4c 89 c0             	mov    rax,r8
    7ffff7fb14e4:	48 f7 d8             	neg    rax
    7ffff7fb14e7:	4c 89 c1             	mov    rcx,r8
    7ffff7fb14ea:	48 0f 49 c8          	cmovns rcx,rax
    7ffff7fb14ee:	48 83 f1 01          	xor    rcx,0x1
    7ffff7fb14f2:	48 0b 0e             	or     rcx,QWORD PTR [rsi]
    7ffff7fb14f5:	0f 95 c1             	setne  cl
    7ffff7fb14f8:	4d 85 c0             	test   r8,r8
    7ffff7fb14fb:	41 0f 9e c0          	setle  r8b
    7ffff7fb14ff:	41 38 d0             	cmp    r8b,dl
    7ffff7fb1502:	74 08                	je     0x7ffff7fb150c
    7ffff7fb1504:	84 c9                	test   cl,cl
    7ffff7fb1506:	74 04                	je     0x7ffff7fb150c
    7ffff7fb1508:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb150c:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
    7ffff7fb1510:	48 89 47 10          	mov    QWORD PTR [rdi+0x10],rax
    7ffff7fb1514:	c5 f8 10 06          	vmovups xmm0,XMMWORD PTR [rsi]
    7ffff7fb1518:	c5 f8 11 07          	vmovups XMMWORD PTR [rdi],xmm0
    7ffff7fb151c:	c3                   	ret
    7ffff7fb151d:	53                   	push   rbx
    7ffff7fb151e:	48 89 fb             	mov    rbx,rdi
    7ffff7fb1521:	48 8b 77 08          	mov    rsi,QWORD PTR [rdi+0x8]
    7ffff7fb1525:	48 ff c6             	inc    rsi
    7ffff7fb1528:	e8 18 00 00 00       	call   0x7ffff7fb1545
    7ffff7fb152d:	48 8b 03             	mov    rax,QWORD PTR [rbx]
    7ffff7fb1530:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
    7ffff7fb1534:	48 c7 04 c8 01 00 00 	mov    QWORD PTR [rax+rcx*8],0x1
    7ffff7fb153b:	00 
    7ffff7fb153c:	48 ff c1             	inc    rcx
    7ffff7fb153f:	48 89 4b 08          	mov    QWORD PTR [rbx+0x8],rcx
    7ffff7fb1543:	5b                   	pop    rbx
    7ffff7fb1544:	c3                   	ret
    7ffff7fb1545:	48 83 fe 03          	cmp    rsi,0x3
    7ffff7fb1549:	72 2a                	jb     0x7ffff7fb1575
    7ffff7fb154b:	48 39 77 10          	cmp    QWORD PTR [rdi+0x10],rsi
    7ffff7fb154f:	73 24                	jae    0x7ffff7fb1575
    7ffff7fb1551:	48 89 f0             	mov    rax,rsi
    7ffff7fb1554:	48 c1 e8 03          	shr    rax,0x3
    7ffff7fb1558:	48 01 f0             	add    rax,rsi
    7ffff7fb155b:	48 83 c0 02          	add    rax,0x2
    7ffff7fb155f:	48 be ff ff ff ff ff 	movabs rsi,0x3ffffffffffffff
    7ffff7fb1566:	ff ff 03 
    7ffff7fb1569:	48 39 f0             	cmp    rax,rsi
    7ffff7fb156c:	48 0f 42 f0          	cmovb  rsi,rax
    7ffff7fb1570:	e9 c7 4d 00 00       	jmp    0x7ffff7fb633c
    7ffff7fb1575:	c3                   	ret
    7ffff7fb1576:	41 57                	push   r15
    7ffff7fb1578:	41 56                	push   r14
    7ffff7fb157a:	41 54                	push   r12
    7ffff7fb157c:	53                   	push   rbx
    7ffff7fb157d:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb1581:	48 89 fb             	mov    rbx,rdi
    7ffff7fb1584:	40 8a 3a             	mov    dil,BYTE PTR [rdx]
    7ffff7fb1587:	f6 06 01             	test   BYTE PTR [rsi],0x1
    7ffff7fb158a:	74 74                	je     0x7ffff7fb1600
    7ffff7fb158c:	48 8d 46 08          	lea    rax,[rsi+0x8]
    7ffff7fb1590:	40 f6 c7 01          	test   dil,0x1
    7ffff7fb1594:	0f 84 c7 00 00 00    	je     0x7ffff7fb1661
    7ffff7fb159a:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
    7ffff7fb159e:	4c 8b 42 10          	mov    r8,QWORD PTR [rdx+0x10]
    7ffff7fb15a2:	4c 39 c1             	cmp    rcx,r8
    7ffff7fb15a5:	0f 83 fb 00 00 00    	jae    0x7ffff7fb16a6
    7ffff7fb15ab:	4c 8b 76 08          	mov    r14,QWORD PTR [rsi+0x8]
    7ffff7fb15af:	4c 8b 7e 18          	mov    r15,QWORD PTR [rsi+0x18]
    7ffff7fb15b3:	48 83 c2 08          	add    rdx,0x8
    7ffff7fb15b7:	49 89 e4             	mov    r12,rsp
    7ffff7fb15ba:	4c 89 e7             	mov    rdi,r12
    7ffff7fb15bd:	48 89 d6             	mov    rsi,rdx
    7ffff7fb15c0:	4c 89 f2             	mov    rdx,r14
    7ffff7fb15c3:	e8 f8 02 00 00       	call   0x7ffff7fb18c0
    7ffff7fb15c8:	49 8b 44 24 10       	mov    rax,QWORD PTR [r12+0x10]
    7ffff7fb15cd:	48 8d 48 01          	lea    rcx,[rax+0x1]
    7ffff7fb15d1:	48 f7 c1 fd ff ff ff 	test   rcx,0xfffffffffffffffd
    7ffff7fb15d8:	75 07                	jne    0x7ffff7fb15e1
    7ffff7fb15da:	48 83 3c 24 00       	cmp    QWORD PTR [rsp],0x0
    7ffff7fb15df:	74 08                	je     0x7ffff7fb15e9
    7ffff7fb15e1:	48 f7 d8             	neg    rax
    7ffff7fb15e4:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
    7ffff7fb15e9:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb15ee:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
    7ffff7fb15f2:	c5 f8 10 04 24       	vmovups xmm0,XMMWORD PTR [rsp]
    7ffff7fb15f7:	c5 f8 11 03          	vmovups XMMWORD PTR [rbx],xmm0
    7ffff7fb15fb:	e9 bf 00 00 00       	jmp    0x7ffff7fb16bf
    7ffff7fb1600:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
    7ffff7fb1604:	48 8b 4e 18          	mov    rcx,QWORD PTR [rsi+0x18]
    7ffff7fb1608:	40 f6 c7 01          	test   dil,0x1
    7ffff7fb160c:	74 74                	je     0x7ffff7fb1682
    7ffff7fb160e:	48 83 c2 08          	add    rdx,0x8
    7ffff7fb1612:	49 89 e6             	mov    r14,rsp
    7ffff7fb1615:	4c 89 f7             	mov    rdi,r14
    7ffff7fb1618:	48 89 d6             	mov    rsi,rdx
    7ffff7fb161b:	48 89 c2             	mov    rdx,rax
    7ffff7fb161e:	e8 09 02 00 00       	call   0x7ffff7fb182c
    7ffff7fb1623:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
    7ffff7fb1627:	48 8d 48 01          	lea    rcx,[rax+0x1]
    7ffff7fb162b:	48 f7 c1 fd ff ff ff 	test   rcx,0xfffffffffffffffd
    7ffff7fb1632:	75 07                	jne    0x7ffff7fb163b
    7ffff7fb1634:	48 83 3c 24 00       	cmp    QWORD PTR [rsp],0x0
    7ffff7fb1639:	74 08                	je     0x7ffff7fb1643
    7ffff7fb163b:	48 f7 d8             	neg    rax
    7ffff7fb163e:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
    7ffff7fb1643:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb1648:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
    7ffff7fb164c:	c5 f8 10 04 24       	vmovups xmm0,XMMWORD PTR [rsp]
    7ffff7fb1651:	c5 f8 11 03          	vmovups XMMWORD PTR [rbx],xmm0
    7ffff7fb1655:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb1659:	5b                   	pop    rbx
    7ffff7fb165a:	41 5c                	pop    r12
    7ffff7fb165c:	41 5e                	pop    r14
    7ffff7fb165e:	41 5f                	pop    r15
    7ffff7fb1660:	c3                   	ret
    7ffff7fb1661:	4c 8b 42 10          	mov    r8,QWORD PTR [rdx+0x10]
    7ffff7fb1665:	48 8b 4a 18          	mov    rcx,QWORD PTR [rdx+0x18]
    7ffff7fb1669:	48 89 df             	mov    rdi,rbx
    7ffff7fb166c:	48 89 c6             	mov    rsi,rax
    7ffff7fb166f:	4c 89 c2             	mov    rdx,r8
    7ffff7fb1672:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb1676:	5b                   	pop    rbx
    7ffff7fb1677:	41 5c                	pop    r12
    7ffff7fb1679:	41 5e                	pop    r14
    7ffff7fb167b:	41 5f                	pop    r15
    7ffff7fb167d:	e9 aa 01 00 00       	jmp    0x7ffff7fb182c
    7ffff7fb1682:	4c 8b 4a 10          	mov    r9,QWORD PTR [rdx+0x10]
    7ffff7fb1686:	4c 8b 42 18          	mov    r8,QWORD PTR [rdx+0x18]
    7ffff7fb168a:	48 89 df             	mov    rdi,rbx
    7ffff7fb168d:	48 89 c6             	mov    rsi,rax
    7ffff7fb1690:	48 89 ca             	mov    rdx,rcx
    7ffff7fb1693:	4c 89 c9             	mov    rcx,r9
    7ffff7fb1696:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb169a:	5b                   	pop    rbx
    7ffff7fb169b:	41 5c                	pop    r12
    7ffff7fb169d:	41 5e                	pop    r14
    7ffff7fb169f:	41 5f                	pop    r15
    7ffff7fb16a1:	e9 d6 01 00 00       	jmp    0x7ffff7fb187c
    7ffff7fb16a6:	4c 8b 72 08          	mov    r14,QWORD PTR [rdx+0x8]
    7ffff7fb16aa:	4c 8b 7a 18          	mov    r15,QWORD PTR [rdx+0x18]
    7ffff7fb16ae:	48 89 df             	mov    rdi,rbx
    7ffff7fb16b1:	48 89 c6             	mov    rsi,rax
    7ffff7fb16b4:	4c 89 f2             	mov    rdx,r14
    7ffff7fb16b7:	4c 89 c1             	mov    rcx,r8
    7ffff7fb16ba:	e8 01 02 00 00       	call   0x7ffff7fb18c0
    7ffff7fb16bf:	4c 89 f7             	mov    rdi,r14
    7ffff7fb16c2:	4c 89 fe             	mov    rsi,r15
    7ffff7fb16c5:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb16c9:	5b                   	pop    rbx
    7ffff7fb16ca:	41 5c                	pop    r12
    7ffff7fb16cc:	41 5e                	pop    r14
    7ffff7fb16ce:	41 5f                	pop    r15
    7ffff7fb16d0:	e9 9b 4c 00 00       	jmp    0x7ffff7fb6370
    7ffff7fb16d5:	55                   	push   rbp
    7ffff7fb16d6:	41 57                	push   r15
    7ffff7fb16d8:	41 56                	push   r14
    7ffff7fb16da:	41 55                	push   r13
    7ffff7fb16dc:	41 54                	push   r12
    7ffff7fb16de:	53                   	push   rbx
    7ffff7fb16df:	48 83 ec 38          	sub    rsp,0x38
    7ffff7fb16e3:	48 89 fb             	mov    rbx,rdi
    7ffff7fb16e6:	8a 02                	mov    al,BYTE PTR [rdx]
    7ffff7fb16e8:	f6 06 01             	test   BYTE PTR [rsi],0x1
    7ffff7fb16eb:	74 51                	je     0x7ffff7fb173e
    7ffff7fb16ed:	4c 8b 7e 08          	mov    r15,QWORD PTR [rsi+0x8]
    7ffff7fb16f1:	4c 8b 76 10          	mov    r14,QWORD PTR [rsi+0x10]
    7ffff7fb16f5:	a8 01                	test   al,0x1
    7ffff7fb16f7:	0f 84 b2 00 00 00    	je     0x7ffff7fb17af
    7ffff7fb16fd:	4c 8b 6a 08          	mov    r13,QWORD PTR [rdx+0x8]
    7ffff7fb1701:	4c 8b 62 10          	mov    r12,QWORD PTR [rdx+0x10]
    7ffff7fb1705:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
    7ffff7fb170a:	48 89 ef             	mov    rdi,rbp
    7ffff7fb170d:	4d 39 e6             	cmp    r14,r12
    7ffff7fb1710:	0f 83 eb 00 00 00    	jae    0x7ffff7fb1801
    7ffff7fb1716:	4c 89 ee             	mov    rsi,r13
    7ffff7fb1719:	4c 89 e2             	mov    rdx,r12
    7ffff7fb171c:	e8 ba fb ff ff       	call   0x7ffff7fb12db
    7ffff7fb1721:	4c 8d 64 24 08       	lea    r12,[rsp+0x8]
    7ffff7fb1726:	4c 89 e7             	mov    rdi,r12
    7ffff7fb1729:	48 89 ee             	mov    rsi,rbp
    7ffff7fb172c:	4c 89 fa             	mov    rdx,r15
    7ffff7fb172f:	4c 89 f1             	mov    rcx,r14
    7ffff7fb1732:	e8 89 01 00 00       	call   0x7ffff7fb18c0
    7ffff7fb1737:	49 8b 44 24 10       	mov    rax,QWORD PTR [r12+0x10]
    7ffff7fb173c:	eb 3f                	jmp    0x7ffff7fb177d
    7ffff7fb173e:	4c 8b 7e 10          	mov    r15,QWORD PTR [rsi+0x10]
    7ffff7fb1742:	4c 8b 76 18          	mov    r14,QWORD PTR [rsi+0x18]
    7ffff7fb1746:	a8 01                	test   al,0x1
    7ffff7fb1748:	0f 84 8f 00 00 00    	je     0x7ffff7fb17dd
    7ffff7fb174e:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
    7ffff7fb1752:	48 8b 52 10          	mov    rdx,QWORD PTR [rdx+0x10]
    7ffff7fb1756:	4c 8d 64 24 20       	lea    r12,[rsp+0x20]
    7ffff7fb175b:	4c 89 e7             	mov    rdi,r12
    7ffff7fb175e:	e8 78 fb ff ff       	call   0x7ffff7fb12db
    7ffff7fb1763:	4c 8d 6c 24 08       	lea    r13,[rsp+0x8]
    7ffff7fb1768:	4c 89 ef             	mov    rdi,r13
    7ffff7fb176b:	4c 89 e6             	mov    rsi,r12
    7ffff7fb176e:	4c 89 fa             	mov    rdx,r15
    7ffff7fb1771:	4c 89 f1             	mov    rcx,r14
    7ffff7fb1774:	e8 b3 00 00 00       	call   0x7ffff7fb182c
    7ffff7fb1779:	49 8b 45 10          	mov    rax,QWORD PTR [r13+0x10]
    7ffff7fb177d:	48 8d 48 01          	lea    rcx,[rax+0x1]
    7ffff7fb1781:	48 f7 c1 fd ff ff ff 	test   rcx,0xfffffffffffffffd
    7ffff7fb1788:	75 08                	jne    0x7ffff7fb1792
    7ffff7fb178a:	48 83 7c 24 08 00    	cmp    QWORD PTR [rsp+0x8],0x0
    7ffff7fb1790:	74 08                	je     0x7ffff7fb179a
    7ffff7fb1792:	48 f7 d8             	neg    rax
    7ffff7fb1795:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
    7ffff7fb179a:	48 8b 44 24 18       	mov    rax,QWORD PTR [rsp+0x18]
    7ffff7fb179f:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
    7ffff7fb17a3:	c5 f8 10 44 24 08    	vmovups xmm0,XMMWORD PTR [rsp+0x8]
    7ffff7fb17a9:	c5 f8 11 03          	vmovups XMMWORD PTR [rbx],xmm0
    7ffff7fb17ad:	eb 6e                	jmp    0x7ffff7fb181d
    7ffff7fb17af:	4c 8b 62 10          	mov    r12,QWORD PTR [rdx+0x10]
    7ffff7fb17b3:	4c 8b 6a 18          	mov    r13,QWORD PTR [rdx+0x18]
    7ffff7fb17b7:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
    7ffff7fb17bc:	48 89 ef             	mov    rdi,rbp
    7ffff7fb17bf:	4c 89 fe             	mov    rsi,r15
    7ffff7fb17c2:	4c 89 f2             	mov    rdx,r14
    7ffff7fb17c5:	e8 11 fb ff ff       	call   0x7ffff7fb12db
    7ffff7fb17ca:	48 89 df             	mov    rdi,rbx
    7ffff7fb17cd:	48 89 ee             	mov    rsi,rbp
    7ffff7fb17d0:	4c 89 e2             	mov    rdx,r12
    7ffff7fb17d3:	4c 89 e9             	mov    rcx,r13
    7ffff7fb17d6:	e8 51 00 00 00       	call   0x7ffff7fb182c
    7ffff7fb17db:	eb 40                	jmp    0x7ffff7fb181d
    7ffff7fb17dd:	48 8b 4a 10          	mov    rcx,QWORD PTR [rdx+0x10]
    7ffff7fb17e1:	4c 8b 42 18          	mov    r8,QWORD PTR [rdx+0x18]
    7ffff7fb17e5:	48 89 df             	mov    rdi,rbx
    7ffff7fb17e8:	4c 89 fe             	mov    rsi,r15
    7ffff7fb17eb:	4c 89 f2             	mov    rdx,r14
    7ffff7fb17ee:	48 83 c4 38          	add    rsp,0x38
    7ffff7fb17f2:	5b                   	pop    rbx
    7ffff7fb17f3:	41 5c                	pop    r12
    7ffff7fb17f5:	41 5d                	pop    r13
    7ffff7fb17f7:	41 5e                	pop    r14
    7ffff7fb17f9:	41 5f                	pop    r15
    7ffff7fb17fb:	5d                   	pop    rbp
    7ffff7fb17fc:	e9 7b 00 00 00       	jmp    0x7ffff7fb187c
    7ffff7fb1801:	4c 89 fe             	mov    rsi,r15
    7ffff7fb1804:	4c 89 f2             	mov    rdx,r14
    7ffff7fb1807:	e8 cf fa ff ff       	call   0x7ffff7fb12db
    7ffff7fb180c:	48 89 df             	mov    rdi,rbx
    7ffff7fb180f:	48 89 ee             	mov    rsi,rbp
    7ffff7fb1812:	4c 89 ea             	mov    rdx,r13
    7ffff7fb1815:	4c 89 e1             	mov    rcx,r12
    7ffff7fb1818:	e8 a3 00 00 00       	call   0x7ffff7fb18c0
    7ffff7fb181d:	48 83 c4 38          	add    rsp,0x38
    7ffff7fb1821:	5b                   	pop    rbx
    7ffff7fb1822:	41 5c                	pop    r12
    7ffff7fb1824:	41 5d                	pop    r13
    7ffff7fb1826:	41 5e                	pop    r14
    7ffff7fb1828:	41 5f                	pop    r15
    7ffff7fb182a:	5d                   	pop    rbp
    7ffff7fb182b:	c3                   	ret
    7ffff7fb182c:	41 56                	push   r14
    7ffff7fb182e:	53                   	push   rbx
    7ffff7fb182f:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb1833:	48 89 f3             	mov    rbx,rsi
    7ffff7fb1836:	48 8b 06             	mov    rax,QWORD PTR [rsi]
    7ffff7fb1839:	48 8b 76 08          	mov    rsi,QWORD PTR [rsi+0x8]
    7ffff7fb183d:	48 29 10             	sub    QWORD PTR [rax],rdx
    7ffff7fb1840:	49 89 fe             	mov    r14,rdi
    7ffff7fb1843:	48 19 48 08          	sbb    QWORD PTR [rax+0x8],rcx
    7ffff7fb1847:	73 10                	jae    0x7ffff7fb1859
    7ffff7fb1849:	48 83 c6 fe          	add    rsi,0xfffffffffffffffe
    7ffff7fb184d:	48 83 c0 10          	add    rax,0x10
    7ffff7fb1851:	48 89 c7             	mov    rdi,rax
    7ffff7fb1854:	e8 65 47 00 00       	call   0x7ffff7fb5fbe
    7ffff7fb1859:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    7ffff7fb185d:	48 89 e6             	mov    rsi,rsp
    7ffff7fb1860:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb1864:	c5 f8 10 03          	vmovups xmm0,XMMWORD PTR [rbx]
    7ffff7fb1868:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb186c:	4c 89 f7             	mov    rdi,r14
    7ffff7fb186f:	e8 80 49 00 00       	call   0x7ffff7fb61f4
    7ffff7fb1874:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb1878:	5b                   	pop    rbx
    7ffff7fb1879:	41 5e                	pop    r14
    7ffff7fb187b:	c3                   	ret
    7ffff7fb187c:	48 29 ce             	sub    rsi,rcx
    7ffff7fb187f:	4c 19 c2             	sbb    rdx,r8
    7ffff7fb1882:	73 25                	jae    0x7ffff7fb18a9
    7ffff7fb1884:	31 c9                	xor    ecx,ecx
    7ffff7fb1886:	48 f7 de             	neg    rsi
    7ffff7fb1889:	48 19 d1             	sbb    rcx,rdx
    7ffff7fb188c:	0f 94 c0             	sete   al
    7ffff7fb188f:	0f b6 c0             	movzx  eax,al
    7ffff7fb1892:	6a 02                	push   0x2
    7ffff7fb1894:	41 58                	pop    r8
    7ffff7fb1896:	49 29 c0             	sub    r8,rax
    7ffff7fb1899:	48 83 c8 fe          	or     rax,0xfffffffffffffffe
    7ffff7fb189d:	48 89 ca             	mov    rdx,rcx
    7ffff7fb18a0:	48 09 f1             	or     rcx,rsi
    7ffff7fb18a3:	49 0f 44 c0          	cmove  rax,r8
    7ffff7fb18a7:	eb 0b                	jmp    0x7ffff7fb18b4
    7ffff7fb18a9:	48 83 fa 01          	cmp    rdx,0x1
    7ffff7fb18ad:	6a 02                	push   0x2
    7ffff7fb18af:	58                   	pop    rax
    7ffff7fb18b0:	48 83 d8 00          	sbb    rax,0x0
    7ffff7fb18b4:	48 89 37             	mov    QWORD PTR [rdi],rsi
    7ffff7fb18b7:	48 89 57 08          	mov    QWORD PTR [rdi+0x8],rdx
    7ffff7fb18bb:	48 89 47 10          	mov    QWORD PTR [rdi+0x10],rax
    7ffff7fb18bf:	c3                   	ret
    7ffff7fb18c0:	55                   	push   rbp
    7ffff7fb18c1:	41 57                	push   r15
    7ffff7fb18c3:	41 56                	push   r14
    7ffff7fb18c5:	41 55                	push   r13
    7ffff7fb18c7:	41 54                	push   r12
    7ffff7fb18c9:	53                   	push   rbx
    7ffff7fb18ca:	48 83 ec 68          	sub    rsp,0x68
    7ffff7fb18ce:	49 89 ce             	mov    r14,rcx
    7ffff7fb18d1:	49 89 d7             	mov    r15,rdx
    7ffff7fb18d4:	49 89 f4             	mov    r12,rsi
    7ffff7fb18d7:	48 89 fb             	mov    rbx,rdi
    7ffff7fb18da:	48 8b 76 08          	mov    rsi,QWORD PTR [rsi+0x8]
    7ffff7fb18de:	48 39 ce             	cmp    rsi,rcx
    7ffff7fb18e1:	0f 83 b1 00 00 00    	jae    0x7ffff7fb1998
    7ffff7fb18e7:	48 89 5c 24 08       	mov    QWORD PTR [rsp+0x8],rbx
    7ffff7fb18ec:	c4 c1 78 10 04 24    	vmovups xmm0,XMMWORD PTR [r12]
    7ffff7fb18f2:	4c 8d 6c 24 10       	lea    r13,[rsp+0x10]
    7ffff7fb18f7:	c4 c1 78 29 45 00    	vmovaps XMMWORD PTR [r13+0x0],xmm0
    7ffff7fb18fd:	49 8b 44 24 10       	mov    rax,QWORD PTR [r12+0x10]
    7ffff7fb1902:	49 89 45 10          	mov    QWORD PTR [r13+0x10],rax
    7ffff7fb1906:	49 8b 55 00          	mov    rdx,QWORD PTR [r13+0x0]
    7ffff7fb190a:	4d 8b 65 08          	mov    r12,QWORD PTR [r13+0x8]
    7ffff7fb190e:	4c 89 ff             	mov    rdi,r15
    7ffff7fb1911:	4c 89 e6             	mov    rsi,r12
    7ffff7fb1914:	4c 89 e1             	mov    rcx,r12
    7ffff7fb1917:	e8 84 47 00 00       	call   0x7ffff7fb60a0
    7ffff7fb191c:	88 44 24 07          	mov    BYTE PTR [rsp+0x7],al
    7ffff7fb1920:	4c 89 ef             	mov    rdi,r13
    7ffff7fb1923:	4c 89 f6             	mov    rsi,r14
    7ffff7fb1926:	e8 1a fc ff ff       	call   0x7ffff7fb1545
    7ffff7fb192b:	4d 29 e6             	sub    r14,r12
    7ffff7fb192e:	49 8b 5d 00          	mov    rbx,QWORD PTR [r13+0x0]
    7ffff7fb1932:	49 8b 6d 08          	mov    rbp,QWORD PTR [r13+0x8]
    7ffff7fb1936:	4b 8d 34 e7          	lea    rsi,[r15+r12*8]
    7ffff7fb193a:	48 8d 3c eb          	lea    rdi,[rbx+rbp*8]
    7ffff7fb193e:	4a 8d 14 f5 00 00 00 	lea    rdx,[r14*8+0x0]
    7ffff7fb1945:	00 
    7ffff7fb1946:	ff 15 1c 72 00 00    	call   QWORD PTR [rip+0x721c]        # 0x7ffff7fb8b68
    7ffff7fb194c:	49 01 ee             	add    r14,rbp
    7ffff7fb194f:	4d 89 75 08          	mov    QWORD PTR [r13+0x8],r14
    7ffff7fb1953:	80 7c 24 07 00       	cmp    BYTE PTR [rsp+0x7],0x0
    7ffff7fb1958:	74 0f                	je     0x7ffff7fb1969
    7ffff7fb195a:	4d 29 e6             	sub    r14,r12
    7ffff7fb195d:	4a 8d 3c e3          	lea    rdi,[rbx+r12*8]
    7ffff7fb1961:	4c 89 f6             	mov    rsi,r14
    7ffff7fb1964:	e8 55 46 00 00       	call   0x7ffff7fb5fbe
    7ffff7fb1969:	48 8b 44 24 20       	mov    rax,QWORD PTR [rsp+0x20]
    7ffff7fb196e:	48 8d 74 24 30       	lea    rsi,[rsp+0x30]
    7ffff7fb1973:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb1977:	c5 f8 28 44 24 10    	vmovaps xmm0,XMMWORD PTR [rsp+0x10]
    7ffff7fb197d:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb1981:	4c 8d 74 24 50       	lea    r14,[rsp+0x50]
    7ffff7fb1986:	4c 89 f7             	mov    rdi,r14
    7ffff7fb1989:	e8 66 48 00 00       	call   0x7ffff7fb61f4
    7ffff7fb198e:	6a 01                	push   0x1
    7ffff7fb1990:	5a                   	pop    rdx
    7ffff7fb1991:	48 8b 7c 24 08       	mov    rdi,QWORD PTR [rsp+0x8]
    7ffff7fb1996:	eb 3d                	jmp    0x7ffff7fb19d5
    7ffff7fb1998:	49 8b 3c 24          	mov    rdi,QWORD PTR [r12]
    7ffff7fb199c:	4c 89 fa             	mov    rdx,r15
    7ffff7fb199f:	4c 89 f1             	mov    rcx,r14
    7ffff7fb19a2:	e8 28 47 00 00       	call   0x7ffff7fb60cf
    7ffff7fb19a7:	89 c5                	mov    ebp,eax
    7ffff7fb19a9:	49 8b 44 24 10       	mov    rax,QWORD PTR [r12+0x10]
    7ffff7fb19ae:	48 8d 74 24 30       	lea    rsi,[rsp+0x30]
    7ffff7fb19b3:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb19b7:	c4 c1 78 10 04 24    	vmovups xmm0,XMMWORD PTR [r12]
    7ffff7fb19bd:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb19c1:	4c 8d 74 24 10       	lea    r14,[rsp+0x10]
    7ffff7fb19c6:	4c 89 f7             	mov    rdi,r14
    7ffff7fb19c9:	e8 26 48 00 00       	call   0x7ffff7fb61f4
    7ffff7fb19ce:	40 0f b6 d5          	movzx  edx,bpl
    7ffff7fb19d2:	48 89 df             	mov    rdi,rbx
    7ffff7fb19d5:	4c 89 f6             	mov    rsi,r14
    7ffff7fb19d8:	e8 00 fb ff ff       	call   0x7ffff7fb14dd
    7ffff7fb19dd:	48 83 c4 68          	add    rsp,0x68
    7ffff7fb19e1:	5b                   	pop    rbx
    7ffff7fb19e2:	41 5c                	pop    r12
    7ffff7fb19e4:	41 5d                	pop    r13
    7ffff7fb19e6:	41 5e                	pop    r14
    7ffff7fb19e8:	41 5f                	pop    r15
    7ffff7fb19ea:	5d                   	pop    rbp
    7ffff7fb19eb:	c3                   	ret
    7ffff7fb19ec:	41 56                	push   r14
    7ffff7fb19ee:	53                   	push   rbx
    7ffff7fb19ef:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb19f3:	48 89 f3             	mov    rbx,rsi
    7ffff7fb19f6:	48 8b 06             	mov    rax,QWORD PTR [rsi]
    7ffff7fb19f9:	48 8b 76 08          	mov    rsi,QWORD PTR [rsi+0x8]
    7ffff7fb19fd:	48 01 10             	add    QWORD PTR [rax],rdx
    7ffff7fb1a00:	49 89 fe             	mov    r14,rdi
    7ffff7fb1a03:	48 11 48 08          	adc    QWORD PTR [rax+0x8],rcx
    7ffff7fb1a07:	73 1c                	jae    0x7ffff7fb1a25
    7ffff7fb1a09:	48 83 c6 fe          	add    rsi,0xfffffffffffffffe
    7ffff7fb1a0d:	48 83 c0 10          	add    rax,0x10
    7ffff7fb1a11:	48 89 c7             	mov    rdi,rax
    7ffff7fb1a14:	e8 86 45 00 00       	call   0x7ffff7fb5f9f
    7ffff7fb1a19:	84 c0                	test   al,al
    7ffff7fb1a1b:	74 08                	je     0x7ffff7fb1a25
    7ffff7fb1a1d:	48 89 df             	mov    rdi,rbx
    7ffff7fb1a20:	e8 f8 fa ff ff       	call   0x7ffff7fb151d
    7ffff7fb1a25:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    7ffff7fb1a29:	48 89 e6             	mov    rsi,rsp
    7ffff7fb1a2c:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb1a30:	c5 f8 10 03          	vmovups xmm0,XMMWORD PTR [rbx]
    7ffff7fb1a34:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb1a38:	4c 89 f7             	mov    rdi,r14
    7ffff7fb1a3b:	e8 b4 47 00 00       	call   0x7ffff7fb61f4
    7ffff7fb1a40:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb1a44:	5b                   	pop    rbx
    7ffff7fb1a45:	41 5e                	pop    r14
    7ffff7fb1a47:	c3                   	ret
    7ffff7fb1a48:	41 56                	push   r14
    7ffff7fb1a4a:	53                   	push   rbx
    7ffff7fb1a4b:	48 83 ec 58          	sub    rsp,0x58
    7ffff7fb1a4f:	44 8a 0a             	mov    r9b,BYTE PTR [rdx]
    7ffff7fb1a52:	f6 06 01             	test   BYTE PTR [rsi],0x1
    7ffff7fb1a55:	74 42                	je     0x7ffff7fb1a99
    7ffff7fb1a57:	4c 8d 46 08          	lea    r8,[rsi+0x8]
    7ffff7fb1a5b:	41 f6 c1 01          	test   r9b,0x1
    7ffff7fb1a5f:	74 61                	je     0x7ffff7fb1ac2
    7ffff7fb1a61:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
    7ffff7fb1a65:	48 8b 42 10          	mov    rax,QWORD PTR [rdx+0x10]
    7ffff7fb1a69:	48 39 c1             	cmp    rcx,rax
    7ffff7fb1a6c:	0f 83 98 00 00 00    	jae    0x7ffff7fb1b0a
    7ffff7fb1a72:	48 83 c2 08          	add    rdx,0x8
    7ffff7fb1a76:	48 8b 5e 08          	mov    rbx,QWORD PTR [rsi+0x8]
    7ffff7fb1a7a:	4c 8b 76 18          	mov    r14,QWORD PTR [rsi+0x18]
    7ffff7fb1a7e:	48 8b 42 10          	mov    rax,QWORD PTR [rdx+0x10]
    7ffff7fb1a82:	48 89 e6             	mov    rsi,rsp
    7ffff7fb1a85:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb1a89:	c5 f8 10 02          	vmovups xmm0,XMMWORD PTR [rdx]
    7ffff7fb1a8d:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb1a91:	48 89 da             	mov    rdx,rbx
    7ffff7fb1a94:	e9 93 00 00 00       	jmp    0x7ffff7fb1b2c
    7ffff7fb1a99:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
    7ffff7fb1a9d:	48 8b 4e 18          	mov    rcx,QWORD PTR [rsi+0x18]
    7ffff7fb1aa1:	41 f6 c1 01          	test   r9b,0x1
    7ffff7fb1aa5:	74 46                	je     0x7ffff7fb1aed
    7ffff7fb1aa7:	4c 8b 42 18          	mov    r8,QWORD PTR [rdx+0x18]
    7ffff7fb1aab:	48 8d 74 24 20       	lea    rsi,[rsp+0x20]
    7ffff7fb1ab0:	4c 89 46 10          	mov    QWORD PTR [rsi+0x10],r8
    7ffff7fb1ab4:	c5 f8 10 42 08       	vmovups xmm0,XMMWORD PTR [rdx+0x8]
    7ffff7fb1ab9:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb1abd:	48 89 c2             	mov    rdx,rax
    7ffff7fb1ac0:	eb 1e                	jmp    0x7ffff7fb1ae0
    7ffff7fb1ac2:	c4 c1 78 10 00       	vmovups xmm0,XMMWORD PTR [r8]
    7ffff7fb1ac7:	48 8d 74 24 40       	lea    rsi,[rsp+0x40]
    7ffff7fb1acc:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb1ad0:	49 8b 40 10          	mov    rax,QWORD PTR [r8+0x10]
    7ffff7fb1ad4:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb1ad8:	48 8b 4a 18          	mov    rcx,QWORD PTR [rdx+0x18]
    7ffff7fb1adc:	48 8b 52 10          	mov    rdx,QWORD PTR [rdx+0x10]
    7ffff7fb1ae0:	e8 07 ff ff ff       	call   0x7ffff7fb19ec
    7ffff7fb1ae5:	48 83 c4 58          	add    rsp,0x58
    7ffff7fb1ae9:	5b                   	pop    rbx
    7ffff7fb1aea:	41 5e                	pop    r14
    7ffff7fb1aec:	c3                   	ret
    7ffff7fb1aed:	4c 8b 4a 10          	mov    r9,QWORD PTR [rdx+0x10]
    7ffff7fb1af1:	4c 8b 42 18          	mov    r8,QWORD PTR [rdx+0x18]
    7ffff7fb1af5:	48 89 c6             	mov    rsi,rax
    7ffff7fb1af8:	48 89 ca             	mov    rdx,rcx
    7ffff7fb1afb:	4c 89 c9             	mov    rcx,r9
    7ffff7fb1afe:	48 83 c4 58          	add    rsp,0x58
    7ffff7fb1b02:	5b                   	pop    rbx
    7ffff7fb1b03:	41 5e                	pop    r14
    7ffff7fb1b05:	e9 38 01 00 00       	jmp    0x7ffff7fb1c42
    7ffff7fb1b0a:	48 8b 5a 08          	mov    rbx,QWORD PTR [rdx+0x8]
    7ffff7fb1b0e:	4c 8b 72 18          	mov    r14,QWORD PTR [rdx+0x18]
    7ffff7fb1b12:	49 8b 48 10          	mov    rcx,QWORD PTR [r8+0x10]
    7ffff7fb1b16:	48 89 e6             	mov    rsi,rsp
    7ffff7fb1b19:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
    7ffff7fb1b1d:	c4 c1 78 10 00       	vmovups xmm0,XMMWORD PTR [r8]
    7ffff7fb1b22:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb1b26:	48 89 da             	mov    rdx,rbx
    7ffff7fb1b29:	48 89 c1             	mov    rcx,rax
    7ffff7fb1b2c:	e8 84 01 00 00       	call   0x7ffff7fb1cb5
    7ffff7fb1b31:	48 89 df             	mov    rdi,rbx
    7ffff7fb1b34:	4c 89 f6             	mov    rsi,r14
    7ffff7fb1b37:	48 83 c4 58          	add    rsp,0x58
    7ffff7fb1b3b:	5b                   	pop    rbx
    7ffff7fb1b3c:	41 5e                	pop    r14
    7ffff7fb1b3e:	e9 2d 48 00 00       	jmp    0x7ffff7fb6370
    7ffff7fb1b43:	55                   	push   rbp
    7ffff7fb1b44:	41 57                	push   r15
    7ffff7fb1b46:	41 56                	push   r14
    7ffff7fb1b48:	41 55                	push   r13
    7ffff7fb1b4a:	41 54                	push   r12
    7ffff7fb1b4c:	53                   	push   rbx
    7ffff7fb1b4d:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb1b51:	48 89 fb             	mov    rbx,rdi
    7ffff7fb1b54:	8a 02                	mov    al,BYTE PTR [rdx]
    7ffff7fb1b56:	f6 06 01             	test   BYTE PTR [rsi],0x1
    7ffff7fb1b59:	74 3f                	je     0x7ffff7fb1b9a
    7ffff7fb1b5b:	4c 8b 7e 08          	mov    r15,QWORD PTR [rsi+0x8]
    7ffff7fb1b5f:	4c 8b 76 10          	mov    r14,QWORD PTR [rsi+0x10]
    7ffff7fb1b63:	a8 01                	test   al,0x1
    7ffff7fb1b65:	74 60                	je     0x7ffff7fb1bc7
    7ffff7fb1b67:	4c 8b 6a 08          	mov    r13,QWORD PTR [rdx+0x8]
    7ffff7fb1b6b:	4c 8b 62 10          	mov    r12,QWORD PTR [rdx+0x10]
    7ffff7fb1b6f:	48 89 e5             	mov    rbp,rsp
    7ffff7fb1b72:	48 89 ef             	mov    rdi,rbp
    7ffff7fb1b75:	4d 39 e6             	cmp    r14,r12
    7ffff7fb1b78:	0f 83 99 00 00 00    	jae    0x7ffff7fb1c17
    7ffff7fb1b7e:	4c 89 ee             	mov    rsi,r13
    7ffff7fb1b81:	4c 89 e2             	mov    rdx,r12
    7ffff7fb1b84:	e8 52 f7 ff ff       	call   0x7ffff7fb12db
    7ffff7fb1b89:	48 89 df             	mov    rdi,rbx
    7ffff7fb1b8c:	48 89 ee             	mov    rsi,rbp
    7ffff7fb1b8f:	4c 89 fa             	mov    rdx,r15
    7ffff7fb1b92:	4c 89 f1             	mov    rcx,r14
    7ffff7fb1b95:	e9 94 00 00 00       	jmp    0x7ffff7fb1c2e
    7ffff7fb1b9a:	4c 8b 7e 10          	mov    r15,QWORD PTR [rsi+0x10]
    7ffff7fb1b9e:	4c 8b 76 18          	mov    r14,QWORD PTR [rsi+0x18]
    7ffff7fb1ba2:	a8 01                	test   al,0x1
    7ffff7fb1ba4:	74 4d                	je     0x7ffff7fb1bf3
    7ffff7fb1ba6:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
    7ffff7fb1baa:	48 8b 52 10          	mov    rdx,QWORD PTR [rdx+0x10]
    7ffff7fb1bae:	49 89 e4             	mov    r12,rsp
    7ffff7fb1bb1:	4c 89 e7             	mov    rdi,r12
    7ffff7fb1bb4:	e8 22 f7 ff ff       	call   0x7ffff7fb12db
    7ffff7fb1bb9:	48 89 df             	mov    rdi,rbx
    7ffff7fb1bbc:	4c 89 e6             	mov    rsi,r12
    7ffff7fb1bbf:	4c 89 fa             	mov    rdx,r15
    7ffff7fb1bc2:	4c 89 f1             	mov    rcx,r14
    7ffff7fb1bc5:	eb 25                	jmp    0x7ffff7fb1bec
    7ffff7fb1bc7:	4c 8b 62 10          	mov    r12,QWORD PTR [rdx+0x10]
    7ffff7fb1bcb:	4c 8b 6a 18          	mov    r13,QWORD PTR [rdx+0x18]
    7ffff7fb1bcf:	48 89 e5             	mov    rbp,rsp
    7ffff7fb1bd2:	48 89 ef             	mov    rdi,rbp
    7ffff7fb1bd5:	4c 89 fe             	mov    rsi,r15
    7ffff7fb1bd8:	4c 89 f2             	mov    rdx,r14
    7ffff7fb1bdb:	e8 fb f6 ff ff       	call   0x7ffff7fb12db
    7ffff7fb1be0:	48 89 df             	mov    rdi,rbx
    7ffff7fb1be3:	48 89 ee             	mov    rsi,rbp
    7ffff7fb1be6:	4c 89 e2             	mov    rdx,r12
    7ffff7fb1be9:	4c 89 e9             	mov    rcx,r13
    7ffff7fb1bec:	e8 fb fd ff ff       	call   0x7ffff7fb19ec
    7ffff7fb1bf1:	eb 40                	jmp    0x7ffff7fb1c33
    7ffff7fb1bf3:	48 8b 4a 10          	mov    rcx,QWORD PTR [rdx+0x10]
    7ffff7fb1bf7:	4c 8b 42 18          	mov    r8,QWORD PTR [rdx+0x18]
    7ffff7fb1bfb:	48 89 df             	mov    rdi,rbx
    7ffff7fb1bfe:	4c 89 fe             	mov    rsi,r15
    7ffff7fb1c01:	4c 89 f2             	mov    rdx,r14
    7ffff7fb1c04:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb1c08:	5b                   	pop    rbx
    7ffff7fb1c09:	41 5c                	pop    r12
    7ffff7fb1c0b:	41 5d                	pop    r13
    7ffff7fb1c0d:	41 5e                	pop    r14
    7ffff7fb1c0f:	41 5f                	pop    r15
    7ffff7fb1c11:	5d                   	pop    rbp
    7ffff7fb1c12:	e9 2b 00 00 00       	jmp    0x7ffff7fb1c42
    7ffff7fb1c17:	4c 89 fe             	mov    rsi,r15
    7ffff7fb1c1a:	4c 89 f2             	mov    rdx,r14
    7ffff7fb1c1d:	e8 b9 f6 ff ff       	call   0x7ffff7fb12db
    7ffff7fb1c22:	48 89 df             	mov    rdi,rbx
    7ffff7fb1c25:	48 89 ee             	mov    rsi,rbp
    7ffff7fb1c28:	4c 89 ea             	mov    rdx,r13
    7ffff7fb1c2b:	4c 89 e1             	mov    rcx,r12
    7ffff7fb1c2e:	e8 82 00 00 00       	call   0x7ffff7fb1cb5
    7ffff7fb1c33:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb1c37:	5b                   	pop    rbx
    7ffff7fb1c38:	41 5c                	pop    r12
    7ffff7fb1c3a:	41 5d                	pop    r13
    7ffff7fb1c3c:	41 5e                	pop    r14
    7ffff7fb1c3e:	41 5f                	pop    r15
    7ffff7fb1c40:	5d                   	pop    rbp
    7ffff7fb1c41:	c3                   	ret
    7ffff7fb1c42:	41 57                	push   r15
    7ffff7fb1c44:	41 56                	push   r14
    7ffff7fb1c46:	53                   	push   rbx
    7ffff7fb1c47:	48 83 ec 20          	sub    rsp,0x20
    7ffff7fb1c4b:	49 89 d6             	mov    r14,rdx
    7ffff7fb1c4e:	49 89 f7             	mov    r15,rsi
    7ffff7fb1c51:	48 89 fb             	mov    rbx,rdi
    7ffff7fb1c54:	49 01 cf             	add    r15,rcx
    7ffff7fb1c57:	4d 11 c6             	adc    r14,r8
    7ffff7fb1c5a:	73 39                	jae    0x7ffff7fb1c95
    7ffff7fb1c5c:	6a 05                	push   0x5
    7ffff7fb1c5e:	5f                   	pop    rdi
    7ffff7fb1c5f:	e8 67 47 00 00       	call   0x7ffff7fb63cb
    7ffff7fb1c64:	48 8d 74 24 08       	lea    rsi,[rsp+0x8]
    7ffff7fb1c69:	48 89 06             	mov    QWORD PTR [rsi],rax
    7ffff7fb1c6c:	48 c7 46 10 05 00 00 	mov    QWORD PTR [rsi+0x10],0x5
    7ffff7fb1c73:	00 
    7ffff7fb1c74:	4c 89 38             	mov    QWORD PTR [rax],r15
    7ffff7fb1c77:	4c 89 70 08          	mov    QWORD PTR [rax+0x8],r14
    7ffff7fb1c7b:	48 c7 40 10 01 00 00 	mov    QWORD PTR [rax+0x10],0x1
    7ffff7fb1c82:	00 
    7ffff7fb1c83:	48 c7 46 08 03 00 00 	mov    QWORD PTR [rsi+0x8],0x3
    7ffff7fb1c8a:	00 
    7ffff7fb1c8b:	48 89 df             	mov    rdi,rbx
    7ffff7fb1c8e:	e8 61 45 00 00       	call   0x7ffff7fb61f4
    7ffff7fb1c93:	eb 16                	jmp    0x7ffff7fb1cab
    7ffff7fb1c95:	49 83 fe 01          	cmp    r14,0x1
    7ffff7fb1c99:	6a 02                	push   0x2
    7ffff7fb1c9b:	58                   	pop    rax
    7ffff7fb1c9c:	48 83 d8 00          	sbb    rax,0x0
    7ffff7fb1ca0:	4c 89 3b             	mov    QWORD PTR [rbx],r15
    7ffff7fb1ca3:	4c 89 73 08          	mov    QWORD PTR [rbx+0x8],r14
    7ffff7fb1ca7:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
    7ffff7fb1cab:	48 83 c4 20          	add    rsp,0x20
    7ffff7fb1caf:	5b                   	pop    rbx
    7ffff7fb1cb0:	41 5e                	pop    r14
    7ffff7fb1cb2:	41 5f                	pop    r15
    7ffff7fb1cb4:	c3                   	ret
    7ffff7fb1cb5:	55                   	push   rbp
    7ffff7fb1cb6:	41 57                	push   r15
    7ffff7fb1cb8:	41 56                	push   r14
    7ffff7fb1cba:	41 55                	push   r13
    7ffff7fb1cbc:	41 54                	push   r12
    7ffff7fb1cbe:	53                   	push   rbx
    7ffff7fb1cbf:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb1cc3:	49 89 cc             	mov    r12,rcx
    7ffff7fb1cc6:	48 89 d3             	mov    rbx,rdx
    7ffff7fb1cc9:	49 89 f6             	mov    r14,rsi
    7ffff7fb1ccc:	48 89 7c 24 08       	mov    QWORD PTR [rsp+0x8],rdi
    7ffff7fb1cd1:	4c 8b 2e             	mov    r13,QWORD PTR [rsi]
    7ffff7fb1cd4:	48 8b 6e 08          	mov    rbp,QWORD PTR [rsi+0x8]
    7ffff7fb1cd8:	48 39 cd             	cmp    rbp,rcx
    7ffff7fb1cdb:	49 89 cf             	mov    r15,rcx
    7ffff7fb1cde:	4c 0f 42 fd          	cmovb  r15,rbp
    7ffff7fb1ce2:	4c 89 ef             	mov    rdi,r13
    7ffff7fb1ce5:	4c 89 fe             	mov    rsi,r15
    7ffff7fb1ce8:	4c 89 f9             	mov    rcx,r15
    7ffff7fb1ceb:	e8 ee 42 00 00       	call   0x7ffff7fb5fde
    7ffff7fb1cf0:	4c 39 e5             	cmp    rbp,r12
    7ffff7fb1cf3:	73 44                	jae    0x7ffff7fb1d39
    7ffff7fb1cf5:	4c 89 f7             	mov    rdi,r14
    7ffff7fb1cf8:	4c 89 e6             	mov    rsi,r12
    7ffff7fb1cfb:	88 44 24 07          	mov    BYTE PTR [rsp+0x7],al
    7ffff7fb1cff:	e8 41 f8 ff ff       	call   0x7ffff7fb1545
    7ffff7fb1d04:	4d 29 fc             	sub    r12,r15
    7ffff7fb1d07:	4d 8b 2e             	mov    r13,QWORD PTR [r14]
    7ffff7fb1d0a:	49 8b 6e 08          	mov    rbp,QWORD PTR [r14+0x8]
    7ffff7fb1d0e:	4a 8d 34 fb          	lea    rsi,[rbx+r15*8]
    7ffff7fb1d12:	48 8d 3c ed 00 00 00 	lea    rdi,[rbp*8+0x0]
    7ffff7fb1d19:	00 
    7ffff7fb1d1a:	4c 01 ef             	add    rdi,r13
    7ffff7fb1d1d:	4a 8d 14 e5 00 00 00 	lea    rdx,[r12*8+0x0]
    7ffff7fb1d24:	00 
    7ffff7fb1d25:	ff 15 3d 6e 00 00    	call   QWORD PTR [rip+0x6e3d]        # 0x7ffff7fb8b68
    7ffff7fb1d2b:	8a 44 24 07          	mov    al,BYTE PTR [rsp+0x7]
    7ffff7fb1d2f:	49 01 ec             	add    r12,rbp
    7ffff7fb1d32:	4d 89 66 08          	mov    QWORD PTR [r14+0x8],r12
    7ffff7fb1d36:	4c 89 e5             	mov    rbp,r12
    7ffff7fb1d39:	84 c0                	test   al,al
    7ffff7fb1d3b:	74 22                	je     0x7ffff7fb1d5f
    7ffff7fb1d3d:	4c 29 fd             	sub    rbp,r15
    7ffff7fb1d40:	4a 8d 3c fd 00 00 00 	lea    rdi,[r15*8+0x0]
    7ffff7fb1d47:	00 
    7ffff7fb1d48:	4c 01 ef             	add    rdi,r13
    7ffff7fb1d4b:	48 89 ee             	mov    rsi,rbp
    7ffff7fb1d4e:	e8 4c 42 00 00       	call   0x7ffff7fb5f9f
    7ffff7fb1d53:	84 c0                	test   al,al
    7ffff7fb1d55:	74 08                	je     0x7ffff7fb1d5f
    7ffff7fb1d57:	4c 89 f7             	mov    rdi,r14
    7ffff7fb1d5a:	e8 be f7 ff ff       	call   0x7ffff7fb151d
    7ffff7fb1d5f:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
    7ffff7fb1d63:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
    7ffff7fb1d68:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb1d6c:	c4 c1 78 10 06       	vmovups xmm0,XMMWORD PTR [r14]
    7ffff7fb1d71:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb1d75:	48 8b 7c 24 08       	mov    rdi,QWORD PTR [rsp+0x8]
    7ffff7fb1d7a:	e8 75 44 00 00       	call   0x7ffff7fb61f4
    7ffff7fb1d7f:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb1d83:	5b                   	pop    rbx
    7ffff7fb1d84:	41 5c                	pop    r12
    7ffff7fb1d86:	41 5d                	pop    r13
    7ffff7fb1d88:	41 5e                	pop    r14
    7ffff7fb1d8a:	41 5f                	pop    r15
    7ffff7fb1d8c:	5d                   	pop    rbp
    7ffff7fb1d8d:	c3                   	ret
    7ffff7fb1d8e:	55                   	push   rbp
    7ffff7fb1d8f:	41 57                	push   r15
    7ffff7fb1d91:	41 56                	push   r14
    7ffff7fb1d93:	53                   	push   rbx
    7ffff7fb1d94:	48 83 ec 78          	sub    rsp,0x78
    7ffff7fb1d98:	49 89 d6             	mov    r14,rdx
    7ffff7fb1d9b:	48 89 fb             	mov    rbx,rdi
    7ffff7fb1d9e:	4c 8d 7c 24 40       	lea    r15,[rsp+0x40]
    7ffff7fb1da3:	4c 89 ff             	mov    rdi,r15
    7ffff7fb1da6:	e8 8e f6 ff ff       	call   0x7ffff7fb1439
    7ffff7fb1dab:	c4 c1 7c 10 47 10    	vmovups ymm0,YMMWORD PTR [r15+0x10]
    7ffff7fb1db1:	c5 fc 11 04 24       	vmovups YMMWORD PTR [rsp],ymm0
    7ffff7fb1db6:	41 8a 2f             	mov    bpl,BYTE PTR [r15]
    7ffff7fb1db9:	4c 8d 7c 24 40       	lea    r15,[rsp+0x40]
    7ffff7fb1dbe:	4c 89 ff             	mov    rdi,r15
    7ffff7fb1dc1:	4c 89 f6             	mov    rsi,r14
    7ffff7fb1dc4:	c5 f8 77             	vzeroupper
    7ffff7fb1dc7:	e8 6d f6 ff ff       	call   0x7ffff7fb1439
    7ffff7fb1dcc:	41 8a 07             	mov    al,BYTE PTR [r15]
    7ffff7fb1dcf:	c4 c1 7c 10 47 10    	vmovups ymm0,YMMWORD PTR [r15+0x10]
    7ffff7fb1dd5:	c5 fc 11 44 24 20    	vmovups YMMWORD PTR [rsp+0x20],ymm0
    7ffff7fb1ddb:	40 84 ed             	test   bpl,bpl
    7ffff7fb1dde:	74 0e                	je     0x7ffff7fb1dee
    7ffff7fb1de0:	84 c0                	test   al,al
    7ffff7fb1de2:	74 30                	je     0x7ffff7fb1e14
    7ffff7fb1de4:	48 8d 74 24 20       	lea    rsi,[rsp+0x20]
    7ffff7fb1de9:	48 89 e2             	mov    rdx,rsp
    7ffff7fb1dec:	eb 19                	jmp    0x7ffff7fb1e07
    7ffff7fb1dee:	48 89 e6             	mov    rsi,rsp
    7ffff7fb1df1:	48 8d 54 24 20       	lea    rdx,[rsp+0x20]
    7ffff7fb1df6:	84 c0                	test   al,al
    7ffff7fb1df8:	74 0d                	je     0x7ffff7fb1e07
    7ffff7fb1dfa:	48 89 df             	mov    rdi,rbx
    7ffff7fb1dfd:	c5 f8 77             	vzeroupper
    7ffff7fb1e00:	e8 3e fd ff ff       	call   0x7ffff7fb1b43
    7ffff7fb1e05:	eb 33                	jmp    0x7ffff7fb1e3a
    7ffff7fb1e07:	48 89 df             	mov    rdi,rbx
    7ffff7fb1e0a:	c5 f8 77             	vzeroupper
    7ffff7fb1e0d:	e8 c3 f8 ff ff       	call   0x7ffff7fb16d5
    7ffff7fb1e12:	eb 26                	jmp    0x7ffff7fb1e3a
    7ffff7fb1e14:	4c 8d 74 24 40       	lea    r14,[rsp+0x40]
    7ffff7fb1e19:	48 89 e6             	mov    rsi,rsp
    7ffff7fb1e1c:	48 8d 54 24 20       	lea    rdx,[rsp+0x20]
    7ffff7fb1e21:	4c 89 f7             	mov    rdi,r14
    7ffff7fb1e24:	c5 f8 77             	vzeroupper
    7ffff7fb1e27:	e8 17 fd ff ff       	call   0x7ffff7fb1b43
    7ffff7fb1e2c:	6a 01                	push   0x1
    7ffff7fb1e2e:	5a                   	pop    rdx
    7ffff7fb1e2f:	48 89 df             	mov    rdi,rbx
    7ffff7fb1e32:	4c 89 f6             	mov    rsi,r14
    7ffff7fb1e35:	e8 a3 f6 ff ff       	call   0x7ffff7fb14dd
    7ffff7fb1e3a:	48 83 c4 78          	add    rsp,0x78
    7ffff7fb1e3e:	5b                   	pop    rbx
    7ffff7fb1e3f:	41 5e                	pop    r14
    7ffff7fb1e41:	41 5f                	pop    r15
    7ffff7fb1e43:	5d                   	pop    rbp
    7ffff7fb1e44:	c3                   	ret
    7ffff7fb1e45:	55                   	push   rbp
    7ffff7fb1e46:	41 57                	push   r15
    7ffff7fb1e48:	41 56                	push   r14
    7ffff7fb1e4a:	41 55                	push   r13
    7ffff7fb1e4c:	41 54                	push   r12
    7ffff7fb1e4e:	53                   	push   rbx
    7ffff7fb1e4f:	48 83 ec 78          	sub    rsp,0x78
    7ffff7fb1e53:	49 89 d5             	mov    r13,rdx
    7ffff7fb1e56:	48 89 7c 24 28       	mov    QWORD PTR [rsp+0x28],rdi
    7ffff7fb1e5b:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
    7ffff7fb1e60:	48 89 ef             	mov    rdi,rbp
    7ffff7fb1e63:	e8 12 f6 ff ff       	call   0x7ffff7fb147a
    7ffff7fb1e68:	8a 45 00             	mov    al,BYTE PTR [rbp+0x0]
    7ffff7fb1e6b:	88 44 24 0f          	mov    BYTE PTR [rsp+0xf],al
    7ffff7fb1e6f:	4c 8b 65 18          	mov    r12,QWORD PTR [rbp+0x18]
    7ffff7fb1e73:	4c 8b 75 28          	mov    r14,QWORD PTR [rbp+0x28]
    7ffff7fb1e77:	4c 8b 7d 20          	mov    r15,QWORD PTR [rbp+0x20]
    7ffff7fb1e7b:	8a 5d 10             	mov    bl,BYTE PTR [rbp+0x10]
    7ffff7fb1e7e:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
    7ffff7fb1e83:	48 89 ef             	mov    rdi,rbp
    7ffff7fb1e86:	4c 89 ee             	mov    rsi,r13
    7ffff7fb1e89:	e8 ab f5 ff ff       	call   0x7ffff7fb1439
    7ffff7fb1e8e:	8a 45 10             	mov    al,BYTE PTR [rbp+0x10]
    7ffff7fb1e91:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
    7ffff7fb1e95:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
    7ffff7fb1e99:	f6 c3 01             	test   bl,0x1
    7ffff7fb1e9c:	74 2c                	je     0x7ffff7fb1eca
    7ffff7fb1e9e:	a8 01                	test   al,0x1
    7ffff7fb1ea0:	74 4b                	je     0x7ffff7fb1eed
    7ffff7fb1ea2:	49 39 cf             	cmp    r15,rcx
    7ffff7fb1ea5:	0f 83 8d 00 00 00    	jae    0x7ffff7fb1f38
    7ffff7fb1eab:	48 8d 74 24 30       	lea    rsi,[rsp+0x30]
    7ffff7fb1eb0:	4c 89 26             	mov    QWORD PTR [rsi],r12
    7ffff7fb1eb3:	4c 89 7e 08          	mov    QWORD PTR [rsi+0x8],r15
    7ffff7fb1eb7:	4c 89 76 10          	mov    QWORD PTR [rsi+0x10],r14
    7ffff7fb1ebb:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    7ffff7fb1ec0:	e8 2f 43 00 00       	call   0x7ffff7fb61f4
    7ffff7fb1ec5:	e9 a3 00 00 00       	jmp    0x7ffff7fb1f6d
    7ffff7fb1eca:	a8 01                	test   al,0x1
    7ffff7fb1ecc:	74 3c                	je     0x7ffff7fb1f0a
    7ffff7fb1ece:	49 83 fe 01          	cmp    r14,0x1
    7ffff7fb1ed2:	6a 02                	push   0x2
    7ffff7fb1ed4:	58                   	pop    rax
    7ffff7fb1ed5:	48 83 d8 00          	sbb    rax,0x0
    7ffff7fb1ed9:	4c 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],r15
    7ffff7fb1ede:	4c 89 74 24 18       	mov    QWORD PTR [rsp+0x18],r14
    7ffff7fb1ee3:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
    7ffff7fb1ee8:	e9 80 00 00 00       	jmp    0x7ffff7fb1f6d
    7ffff7fb1eed:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    7ffff7fb1ef2:	4c 89 e6             	mov    rsi,r12
    7ffff7fb1ef5:	4c 89 fa             	mov    rdx,r15
    7ffff7fb1ef8:	e8 93 00 00 00       	call   0x7ffff7fb1f90
    7ffff7fb1efd:	4c 89 e7             	mov    rdi,r12
    7ffff7fb1f00:	4c 89 f6             	mov    rsi,r14
    7ffff7fb1f03:	e8 68 44 00 00       	call   0x7ffff7fb6370
    7ffff7fb1f08:	eb 63                	jmp    0x7ffff7fb1f6d
    7ffff7fb1f0a:	4c 89 ff             	mov    rdi,r15
    7ffff7fb1f0d:	4c 89 f6             	mov    rsi,r14
    7ffff7fb1f10:	48 89 ca             	mov    rdx,rcx
    7ffff7fb1f13:	4c 89 c1             	mov    rcx,r8
    7ffff7fb1f16:	ff 15 54 6c 00 00    	call   QWORD PTR [rip+0x6c54]        # 0x7ffff7fb8b70
    7ffff7fb1f1c:	48 83 fa 01          	cmp    rdx,0x1
    7ffff7fb1f20:	6a 02                	push   0x2
    7ffff7fb1f22:	59                   	pop    rcx
    7ffff7fb1f23:	48 83 d9 00          	sbb    rcx,0x0
    7ffff7fb1f27:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
    7ffff7fb1f2c:	48 89 54 24 18       	mov    QWORD PTR [rsp+0x18],rdx
    7ffff7fb1f31:	48 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],rcx
    7ffff7fb1f36:	eb 35                	jmp    0x7ffff7fb1f6d
    7ffff7fb1f38:	4c 8d 6c 24 30       	lea    r13,[rsp+0x30]
    7ffff7fb1f3d:	49 8b 75 18          	mov    rsi,QWORD PTR [r13+0x18]
    7ffff7fb1f41:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
    7ffff7fb1f46:	48 89 ef             	mov    rdi,rbp
    7ffff7fb1f49:	48 89 ca             	mov    rdx,rcx
    7ffff7fb1f4c:	e8 8a f3 ff ff       	call   0x7ffff7fb12db
    7ffff7fb1f51:	4d 89 65 00          	mov    QWORD PTR [r13+0x0],r12
    7ffff7fb1f55:	4d 89 7d 08          	mov    QWORD PTR [r13+0x8],r15
    7ffff7fb1f59:	4d 89 75 10          	mov    QWORD PTR [r13+0x10],r14
    7ffff7fb1f5d:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    7ffff7fb1f62:	4c 89 ee             	mov    rsi,r13
    7ffff7fb1f65:	48 89 ea             	mov    rdx,rbp
    7ffff7fb1f68:	e8 92 5d 00 00       	call   0x7ffff7fb7cff
    7ffff7fb1f6d:	0f b6 54 24 0f       	movzx  edx,BYTE PTR [rsp+0xf]
    7ffff7fb1f72:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
    7ffff7fb1f77:	48 8b 7c 24 28       	mov    rdi,QWORD PTR [rsp+0x28]
    7ffff7fb1f7c:	e8 5c f5 ff ff       	call   0x7ffff7fb14dd
    7ffff7fb1f81:	48 83 c4 78          	add    rsp,0x78
    7ffff7fb1f85:	5b                   	pop    rbx
    7ffff7fb1f86:	41 5c                	pop    r12
    7ffff7fb1f88:	41 5d                	pop    r13
    7ffff7fb1f8a:	41 5e                	pop    r14
    7ffff7fb1f8c:	41 5f                	pop    r15
    7ffff7fb1f8e:	5d                   	pop    rbp
    7ffff7fb1f8f:	c3                   	ret
    7ffff7fb1f90:	55                   	push   rbp
    7ffff7fb1f91:	41 57                	push   r15
    7ffff7fb1f93:	41 56                	push   r14
    7ffff7fb1f95:	41 55                	push   r13
    7ffff7fb1f97:	41 54                	push   r12
    7ffff7fb1f99:	53                   	push   rbx
    7ffff7fb1f9a:	48 83 ec 68          	sub    rsp,0x68
    7ffff7fb1f9e:	49 89 d7             	mov    r15,rdx
    7ffff7fb1fa1:	49 89 f6             	mov    r14,rsi
    7ffff7fb1fa4:	4d 85 c0             	test   r8,r8
    7ffff7fb1fa7:	75 1a                	jne    0x7ffff7fb1fc3
    7ffff7fb1fa9:	f3 48 0f b8 c1       	popcnt rax,rcx
    7ffff7fb1fae:	83 f8 01             	cmp    eax,0x1
    7ffff7fb1fb1:	75 49                	jne    0x7ffff7fb1ffc
    7ffff7fb1fb3:	48 ff c9             	dec    rcx
    7ffff7fb1fb6:	49 23 0e             	and    rcx,QWORD PTR [r14]
    7ffff7fb1fb9:	6a 01                	push   0x1
    7ffff7fb1fbb:	58                   	pop    rax
    7ffff7fb1fbc:	31 db                	xor    ebx,ebx
    7ffff7fb1fbe:	e9 61 02 00 00       	jmp    0x7ffff7fb2224
    7ffff7fb1fc3:	4c 89 c3             	mov    rbx,r8
    7ffff7fb1fc6:	48 89 c8             	mov    rax,rcx
    7ffff7fb1fc9:	48 83 c0 ff          	add    rax,0xffffffffffffffff
    7ffff7fb1fcd:	4c 89 c2             	mov    rdx,r8
    7ffff7fb1fd0:	48 83 d2 ff          	adc    rdx,0xffffffffffffffff
    7ffff7fb1fd4:	4c 89 c6             	mov    rsi,r8
    7ffff7fb1fd7:	48 31 d6             	xor    rsi,rdx
    7ffff7fb1fda:	49 89 c8             	mov    r8,rcx
    7ffff7fb1fdd:	49 31 c0             	xor    r8,rax
    7ffff7fb1fe0:	4c 39 c0             	cmp    rax,r8
    7ffff7fb1fe3:	48 19 f2             	sbb    rdx,rsi
    7ffff7fb1fe6:	73 69                	jae    0x7ffff7fb2051
    7ffff7fb1fe8:	48 83 c1 ff          	add    rcx,0xffffffffffffffff
    7ffff7fb1fec:	48 83 d3 ff          	adc    rbx,0xffffffffffffffff
    7ffff7fb1ff0:	49 23 0e             	and    rcx,QWORD PTR [r14]
    7ffff7fb1ff3:	49 23 5e 08          	and    rbx,QWORD PTR [r14+0x8]
    7ffff7fb1ff7:	e9 1d 02 00 00       	jmp    0x7ffff7fb2219
    7ffff7fb1ffc:	48 89 3c 24          	mov    QWORD PTR [rsp],rdi
    7ffff7fb2000:	f3 4c 0f bd e1       	lzcnt  r12,rcx
    7ffff7fb2005:	c4 62 99 f7 e9       	shlx   r13,rcx,r12
    7ffff7fb200a:	31 db                	xor    ebx,ebx
    7ffff7fb200c:	6a ff                	push   0xffffffffffffffff
    7ffff7fb200e:	5f                   	pop    rdi
    7ffff7fb200f:	48 89 fe             	mov    rsi,rdi
    7ffff7fb2012:	4c 89 ea             	mov    rdx,r13
    7ffff7fb2015:	31 c9                	xor    ecx,ecx
    7ffff7fb2017:	ff 15 5b 6b 00 00    	call   QWORD PTR [rip+0x6b5b]        # 0x7ffff7fb8b78
    7ffff7fb201d:	48 89 c5             	mov    rbp,rax
    7ffff7fb2020:	4b 8b 4c fe f8       	mov    rcx,QWORD PTR [r14+r15*8-0x8]
    7ffff7fb2025:	4c 39 e9             	cmp    rcx,r13
    7ffff7fb2028:	49 0f 43 dd          	cmovae rbx,r13
    7ffff7fb202c:	48 29 d9             	sub    rcx,rbx
    7ffff7fb202f:	49 83 ff 01          	cmp    r15,0x1
    7ffff7fb2033:	0f 84 0f 01 00 00    	je     0x7ffff7fb2148
    7ffff7fb2039:	4b 8b 54 fe f0       	mov    rdx,QWORD PTR [r14+r15*8-0x10]
    7ffff7fb203e:	4c 89 ef             	mov    rdi,r13
    7ffff7fb2041:	48 89 ee             	mov    rsi,rbp
    7ffff7fb2044:	e8 99 44 00 00       	call   0x7ffff7fb64e2
    7ffff7fb2049:	48 89 d1             	mov    rcx,rdx
    7ffff7fb204c:	49 ff cf             	dec    r15
    7ffff7fb204f:	eb de                	jmp    0x7ffff7fb202f
    7ffff7fb2051:	48 89 3c 24          	mov    QWORD PTR [rsp],rdi
    7ffff7fb2055:	f3 48 0f bd c3       	lzcnt  rax,rbx
    7ffff7fb205a:	f3 48 0f bd d1       	lzcnt  rdx,rcx
    7ffff7fb205f:	48 83 c2 40          	add    rdx,0x40
    7ffff7fb2063:	48 85 db             	test   rbx,rbx
    7ffff7fb2066:	48 0f 45 d0          	cmovne rdx,rax
    7ffff7fb206a:	45 31 ed             	xor    r13d,r13d
    7ffff7fb206d:	48 89 cf             	mov    rdi,rcx
    7ffff7fb2070:	48 89 de             	mov    rsi,rbx
    7ffff7fb2073:	48 89 54 24 18       	mov    QWORD PTR [rsp+0x18],rdx
    7ffff7fb2078:	ff 15 02 6b 00 00    	call   QWORD PTR [rip+0x6b02]        # 0x7ffff7fb8b80
    7ffff7fb207e:	48 8d 5c 24 40       	lea    rbx,[rsp+0x40]
    7ffff7fb2083:	48 89 df             	mov    rdi,rbx
    7ffff7fb2086:	48 89 c6             	mov    rsi,rax
    7ffff7fb2089:	e8 99 44 00 00       	call   0x7ffff7fb6527
    7ffff7fb208e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
    7ffff7fb2091:	48 8b 6b 08          	mov    rbp,QWORD PTR [rbx+0x8]
    7ffff7fb2095:	4b 8b 44 fe f0       	mov    rax,QWORD PTR [r14+r15*8-0x10]
    7ffff7fb209a:	4c 89 74 24 10       	mov    QWORD PTR [rsp+0x10],r14
    7ffff7fb209f:	4f 8b 4c fe f8       	mov    r9,QWORD PTR [r14+r15*8-0x8]
    7ffff7fb20a4:	48 39 d0             	cmp    rax,rdx
    7ffff7fb20a7:	4c 89 c9             	mov    rcx,r9
    7ffff7fb20aa:	48 19 e9             	sbb    rcx,rbp
    7ffff7fb20ad:	48 89 e9             	mov    rcx,rbp
    7ffff7fb20b0:	49 0f 42 cd          	cmovb  rcx,r13
    7ffff7fb20b4:	48 8b 5b 10          	mov    rbx,QWORD PTR [rbx+0x10]
    7ffff7fb20b8:	48 89 54 24 08       	mov    QWORD PTR [rsp+0x8],rdx
    7ffff7fb20bd:	4c 0f 43 ea          	cmovae r13,rdx
    7ffff7fb20c1:	4c 29 e8             	sub    rax,r13
    7ffff7fb20c4:	49 19 c9             	sbb    r9,rcx
    7ffff7fb20c7:	49 83 c7 fc          	add    r15,0xfffffffffffffffc
    7ffff7fb20cb:	49 8d 4f 03          	lea    rcx,[r15+0x3]
    7ffff7fb20cf:	48 83 f9 02          	cmp    rcx,0x2
    7ffff7fb20d3:	0f 86 a1 00 00 00    	jbe    0x7ffff7fb217a
    7ffff7fb20d9:	48 8b 4c 24 10       	mov    rcx,QWORD PTR [rsp+0x10]
    7ffff7fb20de:	4e 8b 2c f9          	mov    r13,QWORD PTR [rcx+r15*8]
    7ffff7fb20e2:	4e 8b 44 f9 08       	mov    r8,QWORD PTR [rcx+r15*8+0x8]
    7ffff7fb20e7:	4c 8d 64 24 20       	lea    r12,[rsp+0x20]
    7ffff7fb20ec:	4c 89 e7             	mov    rdi,r12
    7ffff7fb20ef:	49 89 de             	mov    r14,rbx
    7ffff7fb20f2:	48 89 eb             	mov    rbx,rbp
    7ffff7fb20f5:	48 8b 6c 24 08       	mov    rbp,QWORD PTR [rsp+0x8]
    7ffff7fb20fa:	48 89 ee             	mov    rsi,rbp
    7ffff7fb20fd:	48 89 da             	mov    rdx,rbx
    7ffff7fb2100:	4c 89 f1             	mov    rcx,r14
    7ffff7fb2103:	41 51                	push   r9
    7ffff7fb2105:	50                   	push   rax
    7ffff7fb2106:	e8 56 64 00 00       	call   0x7ffff7fb8561
    7ffff7fb210b:	58                   	pop    rax
    7ffff7fb210c:	59                   	pop    rcx
    7ffff7fb210d:	c5 f8 28 44 24 30    	vmovaps xmm0,XMMWORD PTR [rsp+0x30]
    7ffff7fb2113:	48 83 ec 10          	sub    rsp,0x10
    7ffff7fb2117:	c5 f8 11 04 24       	vmovups XMMWORD PTR [rsp],xmm0
    7ffff7fb211c:	4c 89 e7             	mov    rdi,r12
    7ffff7fb211f:	48 89 ee             	mov    rsi,rbp
    7ffff7fb2122:	48 89 dd             	mov    rbp,rbx
    7ffff7fb2125:	4c 89 f3             	mov    rbx,r14
    7ffff7fb2128:	48 89 ea             	mov    rdx,rbp
    7ffff7fb212b:	4c 89 f1             	mov    rcx,r14
    7ffff7fb212e:	4d 89 e8             	mov    r8,r13
    7ffff7fb2131:	e8 2b 64 00 00       	call   0x7ffff7fb8561
    7ffff7fb2136:	58                   	pop    rax
    7ffff7fb2137:	59                   	pop    rcx
    7ffff7fb2138:	48 8b 44 24 30       	mov    rax,QWORD PTR [rsp+0x30]
    7ffff7fb213d:	4c 8b 4c 24 38       	mov    r9,QWORD PTR [rsp+0x38]
    7ffff7fb2142:	49 83 c7 fe          	add    r15,0xfffffffffffffffe
    7ffff7fb2146:	eb 83                	jmp    0x7ffff7fb20cb
    7ffff7fb2148:	31 db                	xor    ebx,ebx
    7ffff7fb214a:	48 89 cf             	mov    rdi,rcx
    7ffff7fb214d:	31 f6                	xor    esi,esi
    7ffff7fb214f:	44 89 e2             	mov    edx,r12d
    7ffff7fb2152:	ff 15 28 6a 00 00    	call   QWORD PTR [rip+0x6a28]        # 0x7ffff7fb8b80
    7ffff7fb2158:	48 89 d1             	mov    rcx,rdx
    7ffff7fb215b:	4c 89 ef             	mov    rdi,r13
    7ffff7fb215e:	48 89 ee             	mov    rsi,rbp
    7ffff7fb2161:	48 89 c2             	mov    rdx,rax
    7ffff7fb2164:	e8 79 43 00 00       	call   0x7ffff7fb64e2
    7ffff7fb2169:	c4 e2 9b f7 ca       	shrx   rcx,rdx,r12
    7ffff7fb216e:	6a 01                	push   0x1
    7ffff7fb2170:	58                   	pop    rax
    7ffff7fb2171:	48 8b 3c 24          	mov    rdi,QWORD PTR [rsp]
    7ffff7fb2175:	e9 aa 00 00 00       	jmp    0x7ffff7fb2224
    7ffff7fb217a:	48 8b 4c 24 10       	mov    rcx,QWORD PTR [rsp+0x10]
    7ffff7fb217f:	75 2a                	jne    0x7ffff7fb21ab
    7ffff7fb2181:	4c 8b 01             	mov    r8,QWORD PTR [rcx]
    7ffff7fb2184:	4c 8d 74 24 20       	lea    r14,[rsp+0x20]
    7ffff7fb2189:	4c 89 f7             	mov    rdi,r14
    7ffff7fb218c:	48 8b 74 24 08       	mov    rsi,QWORD PTR [rsp+0x8]
    7ffff7fb2191:	48 89 ea             	mov    rdx,rbp
    7ffff7fb2194:	48 89 d9             	mov    rcx,rbx
    7ffff7fb2197:	41 51                	push   r9
    7ffff7fb2199:	50                   	push   rax
    7ffff7fb219a:	e8 c2 63 00 00       	call   0x7ffff7fb8561
    7ffff7fb219f:	58                   	pop    rax
    7ffff7fb21a0:	59                   	pop    rcx
    7ffff7fb21a1:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
    7ffff7fb21a5:	4d 8b 66 18          	mov    r12,QWORD PTR [r14+0x18]
    7ffff7fb21a9:	eb 03                	jmp    0x7ffff7fb21ae
    7ffff7fb21ab:	4d 89 cc             	mov    r12,r9
    7ffff7fb21ae:	4c 8b 35 cb 69 00 00 	mov    r14,QWORD PTR [rip+0x69cb]        # 0x7ffff7fb8b80
    7ffff7fb21b5:	48 89 c7             	mov    rdi,rax
    7ffff7fb21b8:	31 f6                	xor    esi,esi
    7ffff7fb21ba:	4c 8b 6c 24 18       	mov    r13,QWORD PTR [rsp+0x18]
    7ffff7fb21bf:	44 89 ea             	mov    edx,r13d
    7ffff7fb21c2:	41 ff d6             	call   r14
    7ffff7fb21c5:	4c 89 f1             	mov    rcx,r14
    7ffff7fb21c8:	49 89 c6             	mov    r14,rax
    7ffff7fb21cb:	49 89 d7             	mov    r15,rdx
    7ffff7fb21ce:	4c 89 e7             	mov    rdi,r12
    7ffff7fb21d1:	31 f6                	xor    esi,esi
    7ffff7fb21d3:	44 89 ea             	mov    edx,r13d
    7ffff7fb21d6:	ff d1                	call   rcx
    7ffff7fb21d8:	49 89 d1             	mov    r9,rdx
    7ffff7fb21db:	4c 09 f8             	or     rax,r15
    7ffff7fb21de:	4c 8d 7c 24 20       	lea    r15,[rsp+0x20]
    7ffff7fb21e3:	4c 89 ff             	mov    rdi,r15
    7ffff7fb21e6:	48 8b 74 24 08       	mov    rsi,QWORD PTR [rsp+0x8]
    7ffff7fb21eb:	48 89 ea             	mov    rdx,rbp
    7ffff7fb21ee:	48 89 d9             	mov    rcx,rbx
    7ffff7fb21f1:	4d 89 f0             	mov    r8,r14
    7ffff7fb21f4:	41 51                	push   r9
    7ffff7fb21f6:	50                   	push   rax
    7ffff7fb21f7:	e8 65 63 00 00       	call   0x7ffff7fb8561
    7ffff7fb21fc:	58                   	pop    rax
    7ffff7fb21fd:	59                   	pop    rcx
    7ffff7fb21fe:	49 8b 7f 10          	mov    rdi,QWORD PTR [r15+0x10]
    7ffff7fb2202:	49 8b 77 18          	mov    rsi,QWORD PTR [r15+0x18]
    7ffff7fb2206:	44 89 ea             	mov    edx,r13d
    7ffff7fb2209:	ff 15 79 69 00 00    	call   QWORD PTR [rip+0x6979]        # 0x7ffff7fb8b88
    7ffff7fb220f:	48 89 c1             	mov    rcx,rax
    7ffff7fb2212:	48 89 d3             	mov    rbx,rdx
    7ffff7fb2215:	48 8b 3c 24          	mov    rdi,QWORD PTR [rsp]
    7ffff7fb2219:	48 83 fb 01          	cmp    rbx,0x1
    7ffff7fb221d:	6a 02                	push   0x2
    7ffff7fb221f:	58                   	pop    rax
    7ffff7fb2220:	48 83 d8 00          	sbb    rax,0x0
    7ffff7fb2224:	48 89 0f             	mov    QWORD PTR [rdi],rcx
    7ffff7fb2227:	48 89 5f 08          	mov    QWORD PTR [rdi+0x8],rbx
    7ffff7fb222b:	48 89 47 10          	mov    QWORD PTR [rdi+0x10],rax
    7ffff7fb222f:	48 83 c4 68          	add    rsp,0x68
    7ffff7fb2233:	5b                   	pop    rbx
    7ffff7fb2234:	41 5c                	pop    r12
    7ffff7fb2236:	41 5d                	pop    r13
    7ffff7fb2238:	41 5e                	pop    r14
    7ffff7fb223a:	41 5f                	pop    r15
    7ffff7fb223c:	5d                   	pop    rbp
    7ffff7fb223d:	c3                   	ret
    7ffff7fb223e:	55                   	push   rbp
    7ffff7fb223f:	41 57                	push   r15
    7ffff7fb2241:	41 56                	push   r14
    7ffff7fb2243:	41 55                	push   r13
    7ffff7fb2245:	41 54                	push   r12
    7ffff7fb2247:	53                   	push   rbx
    7ffff7fb2248:	48 81 ec b8 00 00 00 	sub    rsp,0xb8
    7ffff7fb224f:	49 89 d7             	mov    r15,rdx
    7ffff7fb2252:	48 89 7c 24 38       	mov    QWORD PTR [rsp+0x38],rdi
    7ffff7fb2257:	4c 8d ac 24 80 00 00 	lea    r13,[rsp+0x80]
    7ffff7fb225e:	00 
    7ffff7fb225f:	4c 89 ef             	mov    rdi,r13
    7ffff7fb2262:	e8 d2 f1 ff ff       	call   0x7ffff7fb1439
    7ffff7fb2267:	41 8a 45 00          	mov    al,BYTE PTR [r13+0x0]
    7ffff7fb226b:	88 44 24 0f          	mov    BYTE PTR [rsp+0xf],al
    7ffff7fb226f:	49 8b 45 18          	mov    rax,QWORD PTR [r13+0x18]
    7ffff7fb2273:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
    7ffff7fb2278:	49 8b 5d 28          	mov    rbx,QWORD PTR [r13+0x28]
    7ffff7fb227c:	4d 8b 65 20          	mov    r12,QWORD PTR [r13+0x20]
    7ffff7fb2280:	45 8a 6d 10          	mov    r13b,BYTE PTR [r13+0x10]
    7ffff7fb2284:	4c 8d b4 24 80 00 00 	lea    r14,[rsp+0x80]
    7ffff7fb228b:	00 
    7ffff7fb228c:	4c 89 f7             	mov    rdi,r14
    7ffff7fb228f:	4c 89 fe             	mov    rsi,r15
    7ffff7fb2292:	e8 a2 f1 ff ff       	call   0x7ffff7fb1439
    7ffff7fb2297:	41 8a 36             	mov    sil,BYTE PTR [r14]
    7ffff7fb229a:	41 8a 46 10          	mov    al,BYTE PTR [r14+0x10]
    7ffff7fb229e:	4d 8b 7e 18          	mov    r15,QWORD PTR [r14+0x18]
    7ffff7fb22a2:	49 8b 6e 28          	mov    rbp,QWORD PTR [r14+0x28]
    7ffff7fb22a6:	4d 8b 76 20          	mov    r14,QWORD PTR [r14+0x20]
    7ffff7fb22aa:	41 f6 c5 01          	test   r13b,0x1
    7ffff7fb22ae:	0f 84 c0 00 00 00    	je     0x7ffff7fb2374
    7ffff7fb22b4:	40 88 74 24 0e       	mov    BYTE PTR [rsp+0xe],sil
    7ffff7fb22b9:	a8 01                	test   al,0x1
    7ffff7fb22bb:	0f 84 ea 00 00 00    	je     0x7ffff7fb23ab
    7ffff7fb22c1:	4d 39 f4             	cmp    r12,r14
    7ffff7fb22c4:	4c 8b 6c 24 40       	mov    r13,QWORD PTR [rsp+0x40]
    7ffff7fb22c9:	75 19                	jne    0x7ffff7fb22e4
    7ffff7fb22cb:	4c 89 ef             	mov    rdi,r13
    7ffff7fb22ce:	4c 89 f6             	mov    rsi,r14
    7ffff7fb22d1:	4c 89 fa             	mov    rdx,r15
    7ffff7fb22d4:	4c 89 f1             	mov    rcx,r14
    7ffff7fb22d7:	e8 af 41 00 00       	call   0x7ffff7fb648b
    7ffff7fb22dc:	84 c0                	test   al,al
    7ffff7fb22de:	0f 84 d7 01 00 00    	je     0x7ffff7fb24bb
    7ffff7fb22e4:	4d 89 f5             	mov    r13,r14
    7ffff7fb22e7:	4d 01 e6             	add    r14,r12
    7ffff7fb22ea:	48 8d 5c 24 68       	lea    rbx,[rsp+0x68]
    7ffff7fb22ef:	48 89 df             	mov    rdi,rbx
    7ffff7fb22f2:	4c 89 f6             	mov    rsi,r14
    7ffff7fb22f5:	e8 87 40 00 00       	call   0x7ffff7fb6381
    7ffff7fb22fa:	48 89 df             	mov    rdi,rbx
    7ffff7fb22fd:	4c 89 f6             	mov    rsi,r14
    7ffff7fb2300:	e8 d6 40 00 00       	call   0x7ffff7fb63db
    7ffff7fb2305:	4d 39 ec             	cmp    r12,r13
    7ffff7fb2308:	4c 89 ef             	mov    rdi,r13
    7ffff7fb230b:	49 0f 42 fc          	cmovb  rdi,r12
    7ffff7fb230f:	e8 88 42 00 00       	call   0x7ffff7fb659c
    7ffff7fb2314:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
    7ffff7fb231b:	00 
    7ffff7fb231c:	48 89 ef             	mov    rdi,rbp
    7ffff7fb231f:	48 89 c6             	mov    rsi,rax
    7ffff7fb2322:	e8 f1 58 00 00       	call   0x7ffff7fb7c18
    7ffff7fb2327:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
    7ffff7fb232a:	48 8b 73 08          	mov    rsi,QWORD PTR [rbx+0x8]
    7ffff7fb232e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
    7ffff7fb2332:	48 8b 4d 08          	mov    rcx,QWORD PTR [rbp+0x8]
    7ffff7fb2336:	48 01 c1             	add    rcx,rax
    7ffff7fb2339:	4c 8d 54 24 10       	lea    r10,[rsp+0x10]
    7ffff7fb233e:	49 89 02             	mov    QWORD PTR [r10],rax
    7ffff7fb2341:	49 89 4a 08          	mov    QWORD PTR [r10+0x8],rcx
    7ffff7fb2345:	31 d2                	xor    edx,edx
    7ffff7fb2347:	48 8b 4c 24 40       	mov    rcx,QWORD PTR [rsp+0x40]
    7ffff7fb234c:	4d 89 e0             	mov    r8,r12
    7ffff7fb234f:	4d 89 f9             	mov    r9,r15
    7ffff7fb2352:	41 52                	push   r10
    7ffff7fb2354:	41 55                	push   r13
    7ffff7fb2356:	e8 a3 45 00 00       	call   0x7ffff7fb68fe
    7ffff7fb235b:	59                   	pop    rcx
    7ffff7fb235c:	5a                   	pop    rdx
    7ffff7fb235d:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    7ffff7fb2362:	48 89 de             	mov    rsi,rbx
    7ffff7fb2365:	e8 8a 3e 00 00       	call   0x7ffff7fb61f4
    7ffff7fb236a:	48 89 ef             	mov    rdi,rbp
    7ffff7fb236d:	e8 da 58 00 00       	call   0x7ffff7fb7c4c
    7ffff7fb2372:	eb 62                	jmp    0x7ffff7fb23d6
    7ffff7fb2374:	a8 01                	test   al,0x1
    7ffff7fb2376:	0f 84 8a 00 00 00    	je     0x7ffff7fb2406
    7ffff7fb237c:	4c 89 f2             	mov    rdx,r14
    7ffff7fb237f:	4c 8d b4 24 80 00 00 	lea    r14,[rsp+0x80]
    7ffff7fb2386:	00 
    7ffff7fb2387:	4c 89 f7             	mov    rdi,r14
    7ffff7fb238a:	89 f5                	mov    ebp,esi
    7ffff7fb238c:	4c 89 fe             	mov    rsi,r15
    7ffff7fb238f:	e8 47 ef ff ff       	call   0x7ffff7fb12db
    7ffff7fb2394:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    7ffff7fb2399:	4c 89 f6             	mov    rsi,r14
    7ffff7fb239c:	4c 89 e2             	mov    rdx,r12
    7ffff7fb239f:	48 89 d9             	mov    rcx,rbx
    7ffff7fb23a2:	e8 58 5c 00 00       	call   0x7ffff7fb7fff
    7ffff7fb23a7:	89 ee                	mov    esi,ebp
    7ffff7fb23a9:	eb 30                	jmp    0x7ffff7fb23db
    7ffff7fb23ab:	48 8d 9c 24 80 00 00 	lea    rbx,[rsp+0x80]
    7ffff7fb23b2:	00 
    7ffff7fb23b3:	48 89 df             	mov    rdi,rbx
    7ffff7fb23b6:	48 8b 74 24 40       	mov    rsi,QWORD PTR [rsp+0x40]
    7ffff7fb23bb:	4c 89 e2             	mov    rdx,r12
    7ffff7fb23be:	e8 18 ef ff ff       	call   0x7ffff7fb12db
    7ffff7fb23c3:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    7ffff7fb23c8:	48 89 de             	mov    rsi,rbx
    7ffff7fb23cb:	4c 89 f2             	mov    rdx,r14
    7ffff7fb23ce:	48 89 e9             	mov    rcx,rbp
    7ffff7fb23d1:	e8 29 5c 00 00       	call   0x7ffff7fb7fff
    7ffff7fb23d6:	40 8a 74 24 0e       	mov    sil,BYTE PTR [rsp+0xe]
    7ffff7fb23db:	31 d2                	xor    edx,edx
    7ffff7fb23dd:	40 3a 74 24 0f       	cmp    sil,BYTE PTR [rsp+0xf]
    7ffff7fb23e2:	0f 95 c2             	setne  dl
    7ffff7fb23e5:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
    7ffff7fb23ea:	48 8b 7c 24 38       	mov    rdi,QWORD PTR [rsp+0x38]
    7ffff7fb23ef:	e8 e9 f0 ff ff       	call   0x7ffff7fb14dd
    7ffff7fb23f4:	48 81 c4 b8 00 00 00 	add    rsp,0xb8
    7ffff7fb23fb:	5b                   	pop    rbx
    7ffff7fb23fc:	41 5c                	pop    r12
    7ffff7fb23fe:	41 5d                	pop    r13
    7ffff7fb2400:	41 5e                	pop    r14
    7ffff7fb2402:	41 5f                	pop    r15
    7ffff7fb2404:	5d                   	pop    rbp
    7ffff7fb2405:	c3                   	ret
    7ffff7fb2406:	48 89 e8             	mov    rax,rbp
    7ffff7fb2409:	48 09 d8             	or     rax,rbx
    7ffff7fb240c:	75 2f                	jne    0x7ffff7fb243d
    7ffff7fb240e:	4c 89 f2             	mov    rdx,r14
    7ffff7fb2411:	c4 c2 f3 f6 c4       	mulx   rax,rcx,r12      #
    7ffff7fb2416:	49 0f af de          	imul   rbx,r14
    7ffff7fb241a:	48 01 c3             	add    rbx,rax
    7ffff7fb241d:	49 0f af ec          	imul   rbp,r12
    7ffff7fb2421:	31 c0                	xor    eax,eax
    7ffff7fb2423:	48 01 dd             	add    rbp,rbx
    7ffff7fb2426:	0f 95 c0             	setne  al
    7ffff7fb2429:	48 ff c0             	inc    rax
    7ffff7fb242c:	48 89 4c 24 10       	mov    QWORD PTR [rsp+0x10],rcx
    7ffff7fb2431:	48 89 6c 24 18       	mov    QWORD PTR [rsp+0x18],rbp
    7ffff7fb2436:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
    7ffff7fb243b:	eb 9e                	jmp    0x7ffff7fb23db
    7ffff7fb243d:	48 83 ec 10          	sub    rsp,0x10
    7ffff7fb2441:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb2445:	c5 f8 11 04 24       	vmovups XMMWORD PTR [rsp],xmm0
    7ffff7fb244a:	4c 89 f1             	mov    rcx,r14
    7ffff7fb244d:	4c 8d b4 24 90 00 00 	lea    r14,[rsp+0x90]
    7ffff7fb2454:	00 
    7ffff7fb2455:	4c 89 f7             	mov    rdi,r14
    7ffff7fb2458:	41 89 f7             	mov    r15d,esi
    7ffff7fb245b:	4c 89 e6             	mov    rsi,r12
    7ffff7fb245e:	48 89 da             	mov    rdx,rbx
    7ffff7fb2461:	49 89 e8             	mov    r8,rbp
    7ffff7fb2464:	e8 f9 57 00 00       	call   0x7ffff7fb7c62
    7ffff7fb2469:	58                   	pop    rax
    7ffff7fb246a:	59                   	pop    rcx
    7ffff7fb246b:	c4 c1 7c 10 06       	vmovups ymm0,YMMWORD PTR [r14]
    7ffff7fb2470:	c5 fc 11 44 24 40    	vmovups YMMWORD PTR [rsp+0x40],ymm0
    7ffff7fb2476:	6a 06                	push   0x6
    7ffff7fb2478:	5f                   	pop    rdi
    7ffff7fb2479:	c5 f8 77             	vzeroupper
    7ffff7fb247c:	e8 4a 3f 00 00       	call   0x7ffff7fb63cb
    7ffff7fb2481:	49 89 06             	mov    QWORD PTR [r14],rax
    7ffff7fb2484:	49 c7 46 10 06 00 00 	mov    QWORD PTR [r14+0x10],0x6
    7ffff7fb248b:	00 
    7ffff7fb248c:	c5 fc 10 44 24 40    	vmovups ymm0,YMMWORD PTR [rsp+0x40]
    7ffff7fb2492:	c5 fc 11 00          	vmovups YMMWORD PTR [rax],ymm0
    7ffff7fb2496:	49 c7 46 08 04 00 00 	mov    QWORD PTR [r14+0x8],0x4
    7ffff7fb249d:	00 
    7ffff7fb249e:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    7ffff7fb24a3:	48 8d b4 24 80 00 00 	lea    rsi,[rsp+0x80]
    7ffff7fb24aa:	00 
    7ffff7fb24ab:	c5 f8 77             	vzeroupper
    7ffff7fb24ae:	e8 41 3d 00 00       	call   0x7ffff7fb61f4
    7ffff7fb24b3:	44 89 fe             	mov    esi,r15d
    7ffff7fb24b6:	e9 20 ff ff ff       	jmp    0x7ffff7fb23db
    7ffff7fb24bb:	4b 8d 1c 36          	lea    rbx,[r14+r14*1]
    7ffff7fb24bf:	4c 89 74 24 28       	mov    QWORD PTR [rsp+0x28],r14
    7ffff7fb24c4:	4c 8d 74 24 68       	lea    r14,[rsp+0x68]
    7ffff7fb24c9:	4c 89 f7             	mov    rdi,r14
    7ffff7fb24cc:	48 89 de             	mov    rsi,rbx
    7ffff7fb24cf:	e8 ad 3e 00 00       	call   0x7ffff7fb6381
    7ffff7fb24d4:	4c 89 f7             	mov    rdi,r14
    7ffff7fb24d7:	4c 8b 7c 24 28       	mov    r15,QWORD PTR [rsp+0x28]
    7ffff7fb24dc:	48 89 de             	mov    rsi,rbx
    7ffff7fb24df:	e8 f7 3e 00 00       	call   0x7ffff7fb63db
    7ffff7fb24e4:	49 83 ff 1f          	cmp    r15,0x1f
    7ffff7fb24e8:	73 07                	jae    0x7ffff7fb24f1
    7ffff7fb24ea:	6a 01                	push   0x1
    7ffff7fb24ec:	5e                   	pop    rsi
    7ffff7fb24ed:	31 d2                	xor    edx,edx
    7ffff7fb24ef:	eb 0b                	jmp    0x7ffff7fb24fc
    7ffff7fb24f1:	4c 89 ff             	mov    rdi,r15
    7ffff7fb24f4:	e8 a3 40 00 00       	call   0x7ffff7fb659c
    7ffff7fb24f9:	48 89 c6             	mov    rsi,rax
    7ffff7fb24fc:	48 8d 9c 24 80 00 00 	lea    rbx,[rsp+0x80]
    7ffff7fb2503:	00 
    7ffff7fb2504:	48 89 df             	mov    rdi,rbx
    7ffff7fb2507:	e8 0c 57 00 00       	call   0x7ffff7fb7c18
    7ffff7fb250c:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    7ffff7fb2510:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
    7ffff7fb2514:	48 01 c1             	add    rcx,rax
    7ffff7fb2517:	4c 8b 64 24 68       	mov    r12,QWORD PTR [rsp+0x68]
    7ffff7fb251c:	48 8b 74 24 70       	mov    rsi,QWORD PTR [rsp+0x70]
    7ffff7fb2521:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
    7ffff7fb2526:	48 89 4c 24 18       	mov    QWORD PTR [rsp+0x18],rcx
    7ffff7fb252b:	49 83 ff 1f          	cmp    r15,0x1f
    7ffff7fb252f:	73 4f                	jae    0x7ffff7fb2580
    7ffff7fb2531:	48 89 74 24 30       	mov    QWORD PTR [rsp+0x30],rsi
    7ffff7fb2536:	49 8d 5f ff          	lea    rbx,[r15-0x1]
    7ffff7fb253a:	49 8d 6d 08          	lea    rbp,[r13+0x8]
    7ffff7fb253e:	6a 08                	push   0x8
    7ffff7fb2540:	41 5d                	pop    r13
    7ffff7fb2542:	31 c0                	xor    eax,eax


    # ----------------------BIG INT변환 반복문----------------------------


    7ffff7fb2544:	44 0f b6 f0          	movzx  r14d,al
    7ffff7fb2548:	48 83 fb ff          	cmp    rbx,0xffffffffffffffff
    7ffff7fb254c:	74 54                	je     0x7ffff7fb25a2
    7ffff7fb254e:	4b 8d 3c 2c          	lea    rdi,[r12+r13*1]
    7ffff7fb2552:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    7ffff7fb2556:	48 89 de             	mov    rsi,rbx
    7ffff7fb2559:	48 89 e9             	mov    rcx,rbp
    7ffff7fb255c:	49 89 d8             	mov    r8,rbx
    7ffff7fb255f:	e8 d6 55 00 00       	call   0x7ffff7fb7b3a
    7ffff7fb2564:	41 0f ba e6 00       	bt     r14d,0x0
    7ffff7fb2569:	4b 11 04 fc          	adc    QWORD PTR [r12+r15*8],rax
    7ffff7fb256d:	0f 92 c0             	setb   al
    7ffff7fb2570:	48 ff cb             	dec    rbx
    7ffff7fb2573:	49 ff c7             	inc    r15
    7ffff7fb2576:	48 83 c5 08          	add    rbp,0x8
    7ffff7fb257a:	49 83 c5 10          	add    r13,0x10
    7ffff7fb257e:	eb c4                	jmp    0x7ffff7fb2544


    # ----------------------BIG INT변환 반복문----------------------------


    7ffff7fb2580:	48 8d 44 24 10       	lea    rax,[rsp+0x10]
    7ffff7fb2585:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2588:	31 d2                	xor    edx,edx
    7ffff7fb258a:	4c 89 e9             	mov    rcx,r13
    7ffff7fb258d:	4d 89 f8             	mov    r8,r15
    7ffff7fb2590:	4d 89 e9             	mov    r9,r13
    7ffff7fb2593:	50                   	push   rax
    7ffff7fb2594:	41 57                	push   r15
    7ffff7fb2596:	e8 b6 53 00 00       	call   0x7ffff7fb7951
    7ffff7fb259b:	59                   	pop    rcx
    7ffff7fb259c:	5a                   	pop    rdx
    7ffff7fb259d:	e9 95 00 00 00       	jmp    0x7ffff7fb2637
    7ffff7fb25a2:	4c 8b 6c 24 30       	mov    r13,QWORD PTR [rsp+0x30]
    7ffff7fb25a7:	4c 89 e8             	mov    rax,r13
    7ffff7fb25aa:	48 d1 e8             	shr    rax,1
    7ffff7fb25ad:	48 8b 4c 24 28       	mov    rcx,QWORD PTR [rsp+0x28]
    7ffff7fb25b2:	48 39 c1             	cmp    rcx,rax
    7ffff7fb25b5:	48 0f 42 c1          	cmovb  rax,rcx
    7ffff7fb25b9:	49 8d 4c 24 08       	lea    rcx,[r12+0x8]
    7ffff7fb25be:	31 f6                	xor    esi,esi
    7ffff7fb25c0:	45 31 c9             	xor    r9d,r9d
    7ffff7fb25c3:	31 d2                	xor    edx,edx
    7ffff7fb25c5:	4c 8b 7c 24 40       	mov    r15,QWORD PTR [rsp+0x40]
    7ffff7fb25ca:	44 0f b6 c2          	movzx  r8d,dl
    7ffff7fb25ce:	41 0f b6 f9          	movzx  edi,r9b
    7ffff7fb25d2:	48 39 f0             	cmp    rax,rsi
    7ffff7fb25d5:	74 4a                	je     0x7ffff7fb2621
    7ffff7fb25d7:	49 8b 14 f7          	mov    rdx,QWORD PTR [r15+rsi*8]
    7ffff7fb25db:	48 ff c6             	inc    rsi
    7ffff7fb25de:	c4 e2 b3 f6 d2       	mulx   rdx,r9,rdx                   #
    7ffff7fb25e3:	4c 8b 51 f8          	mov    r10,QWORD PTR [rcx-0x8]
    7ffff7fb25e7:	4c 8b 19             	mov    r11,QWORD PTR [rcx]
    7ffff7fb25ea:	4c 89 d3             	mov    rbx,r10
    7ffff7fb25ed:	48 c1 eb 3f          	shr    rbx,0x3f
    7ffff7fb25f1:	4d 01 d2             	add    r10,r10
    7ffff7fb25f4:	4d 01 ca             	add    r10,r9
    7ffff7fb25f7:	48 11 d3             	adc    rbx,rdx
    7ffff7fb25fa:	41 83 e0 01          	and    r8d,0x1
    7ffff7fb25fe:	4d 01 d0             	add    r8,r10
    7ffff7fb2601:	4c 11 db             	adc    rbx,r11
    7ffff7fb2604:	0f 92 c2             	setb   dl
    7ffff7fb2607:	83 e7 01             	and    edi,0x1
    7ffff7fb260a:	4c 01 c7             	add    rdi,r8
    7ffff7fb260d:	4c 11 db             	adc    rbx,r11
    7ffff7fb2610:	41 0f 92 c1          	setb   r9b
    7ffff7fb2614:	48 89 79 f8          	mov    QWORD PTR [rcx-0x8],rdi
    7ffff7fb2618:	48 89 19             	mov    QWORD PTR [rcx],rbx
    7ffff7fb261b:	48 83 c1 10          	add    rcx,0x10
    7ffff7fb261f:	eb a9                	jmp    0x7ffff7fb25ca
    7ffff7fb2621:	41 83 e6 01          	and    r14d,0x1
    7ffff7fb2625:	41 83 e0 01          	and    r8d,0x1
    7ffff7fb2629:	83 e7 01             	and    edi,0x1
    7ffff7fb262c:	4c 01 f7             	add    rdi,r14
    7ffff7fb262f:	4c 01 c7             	add    rdi,r8
    7ffff7fb2632:	4b 01 7c ec f8       	add    QWORD PTR [r12+r13*8-0x8],rdi
    7ffff7fb2637:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    7ffff7fb263c:	48 8d 74 24 68       	lea    rsi,[rsp+0x68]
    7ffff7fb2641:	e8 ae 3b 00 00       	call   0x7ffff7fb61f4
    7ffff7fb2646:	48 8d bc 24 80 00 00 	lea    rdi,[rsp+0x80]
    7ffff7fb264d:	00 
    7ffff7fb264e:	e9 1a fd ff ff       	jmp    0x7ffff7fb236d
    7ffff7fb2653:	55                   	push   rbp
    7ffff7fb2654:	41 57                	push   r15
    7ffff7fb2656:	41 56                	push   r14
    7ffff7fb2658:	41 55                	push   r13
    7ffff7fb265a:	41 54                	push   r12
    7ffff7fb265c:	53                   	push   rbx
    7ffff7fb265d:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb2661:	48 89 fb             	mov    rbx,rdi
    7ffff7fb2664:	f6 06 01             	test   BYTE PTR [rsi],0x1
    7ffff7fb2667:	74 23                	je     0x7ffff7fb268c
    7ffff7fb2669:	4c 8b 7e 08          	mov    r15,QWORD PTR [rsi+0x8]
    7ffff7fb266d:	4c 8b 76 10          	mov    r14,QWORD PTR [rsi+0x10]
    7ffff7fb2671:	49 83 fe 02          	cmp    r14,0x2
    7ffff7fb2675:	74 58                	je     0x7ffff7fb26cf
    7ffff7fb2677:	49 83 fe 01          	cmp    r14,0x1
    7ffff7fb267b:	74 3a                	je     0x7ffff7fb26b7
    7ffff7fb267d:	4d 85 f6             	test   r14,r14
    7ffff7fb2680:	75 77                	jne    0x7ffff7fb26f9
    7ffff7fb2682:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb2686:	c5 f8 11 03          	vmovups XMMWORD PTR [rbx],xmm0
    7ffff7fb268a:	eb 39                	jmp    0x7ffff7fb26c5
    7ffff7fb268c:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
    7ffff7fb2690:	48 8b 4e 18          	mov    rcx,QWORD PTR [rsi+0x18]
    7ffff7fb2694:	48 0f ac c8 01       	shrd   rax,rcx,0x1
    7ffff7fb2699:	48 d1 e9             	shr    rcx,1
    7ffff7fb269c:	48 83 f9 01          	cmp    rcx,0x1
    7ffff7fb26a0:	6a 02                	push   0x2
    7ffff7fb26a2:	5a                   	pop    rdx
    7ffff7fb26a3:	48 83 da 00          	sbb    rdx,0x0
    7ffff7fb26a7:	48 89 03             	mov    QWORD PTR [rbx],rax
    7ffff7fb26aa:	48 89 4b 08          	mov    QWORD PTR [rbx+0x8],rcx
    7ffff7fb26ae:	48 89 53 10          	mov    QWORD PTR [rbx+0x10],rdx
    7ffff7fb26b2:	e9 96 00 00 00       	jmp    0x7ffff7fb274d
    7ffff7fb26b7:	49 8b 07             	mov    rax,QWORD PTR [r15]
    7ffff7fb26ba:	48 d1 e8             	shr    rax,1
    7ffff7fb26bd:	48 89 03             	mov    QWORD PTR [rbx],rax
    7ffff7fb26c0:	48 83 63 08 00       	and    QWORD PTR [rbx+0x8],0x0
    7ffff7fb26c5:	48 c7 43 10 01 00 00 	mov    QWORD PTR [rbx+0x10],0x1
    7ffff7fb26cc:	00 
    7ffff7fb26cd:	eb 7e                	jmp    0x7ffff7fb274d
    7ffff7fb26cf:	49 8b 07             	mov    rax,QWORD PTR [r15]
    7ffff7fb26d2:	49 8b 4f 08          	mov    rcx,QWORD PTR [r15+0x8]
    7ffff7fb26d6:	48 0f ac c8 01       	shrd   rax,rcx,0x1
    7ffff7fb26db:	48 89 ca             	mov    rdx,rcx
    7ffff7fb26de:	48 d1 ea             	shr    rdx,1
    7ffff7fb26e1:	48 83 f9 02          	cmp    rcx,0x2
    7ffff7fb26e5:	6a 02                	push   0x2
    7ffff7fb26e7:	59                   	pop    rcx
    7ffff7fb26e8:	48 83 d9 00          	sbb    rcx,0x0
    7ffff7fb26ec:	48 89 03             	mov    QWORD PTR [rbx],rax
    7ffff7fb26ef:	48 89 53 08          	mov    QWORD PTR [rbx+0x8],rdx
    7ffff7fb26f3:	48 89 4b 10          	mov    QWORD PTR [rbx+0x10],rcx
    7ffff7fb26f7:	eb 54                	jmp    0x7ffff7fb274d
    7ffff7fb26f9:	49 89 e4             	mov    r12,rsp
    7ffff7fb26fc:	4c 89 e7             	mov    rdi,r12
    7ffff7fb26ff:	4c 89 f6             	mov    rsi,r14
    7ffff7fb2702:	e8 7a 3c 00 00       	call   0x7ffff7fb6381
    7ffff7fb2707:	4d 8b 2c 24          	mov    r13,QWORD PTR [r12]
    7ffff7fb270b:	49 8b 6c 24 08       	mov    rbp,QWORD PTR [r12+0x8]
    7ffff7fb2710:	48 8d 3c ed 00 00 00 	lea    rdi,[rbp*8+0x0]
    7ffff7fb2717:	00 
    7ffff7fb2718:	4c 01 ef             	add    rdi,r13
    7ffff7fb271b:	4a 8d 14 f5 00 00 00 	lea    rdx,[r14*8+0x0]
    7ffff7fb2722:	00 
    7ffff7fb2723:	4c 89 fe             	mov    rsi,r15
    7ffff7fb2726:	ff 15 3c 64 00 00    	call   QWORD PTR [rip+0x643c]        # 0x7ffff7fb8b68
    7ffff7fb272c:	4c 01 f5             	add    rbp,r14
    7ffff7fb272f:	49 89 6c 24 08       	mov    QWORD PTR [r12+0x8],rbp
    7ffff7fb2734:	6a 01                	push   0x1
    7ffff7fb2736:	5a                   	pop    rdx
    7ffff7fb2737:	4c 89 ef             	mov    rdi,r13
    7ffff7fb273a:	48 89 ee             	mov    rsi,rbp
    7ffff7fb273d:	e8 c1 3c 00 00       	call   0x7ffff7fb6403
    7ffff7fb2742:	48 89 df             	mov    rdi,rbx
    7ffff7fb2745:	4c 89 e6             	mov    rsi,r12
    7ffff7fb2748:	e8 a7 3a 00 00       	call   0x7ffff7fb61f4
    7ffff7fb274d:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb2751:	5b                   	pop    rbx
    7ffff7fb2752:	41 5c                	pop    r12
    7ffff7fb2754:	41 5d                	pop    r13
    7ffff7fb2756:	41 5e                	pop    r14
    7ffff7fb2758:	41 5f                	pop    r15
    7ffff7fb275a:	5d                   	pop    rbp
    7ffff7fb275b:	c3                   	ret
    7ffff7fb275c:	55                   	push   rbp
    7ffff7fb275d:	41 57                	push   r15
    7ffff7fb275f:	41 56                	push   r14
    7ffff7fb2761:	41 55                	push   r13
    7ffff7fb2763:	41 54                	push   r12
    7ffff7fb2765:	53                   	push   rbx

    # -----------------------진입점-----------------------------





    7ffff7fb2766:	49 89 e3             	mov    r11,rsp
    7ffff7fb2769:	49 81 eb 00 00 02 00 	sub    r11,0x20000 # 메모리 할당
    7ffff7fb2770:	48 81 ec 00 10 00 00 	sub    rsp,0x1000 # 메모리 할당
    7ffff7fb2777:	48 c7 04 24 00 00 00 	mov    QWORD PTR [rsp],0x0
    7ffff7fb277e:	00 
    7ffff7fb277f:	4c 39 dc             	cmp    rsp,r11
    7ffff7fb2782:	75 ec                	jne    0x7ffff7fb2770
    7ffff7fb2784:	48 81 ec 68 02 00 00 	sub    rsp,0x268
    7ffff7fb278b:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb278f:	48 8d 9c 24 50 02 00 	lea    rbx,[rsp+0x250]
    7ffff7fb2796:	00 
    7ffff7fb2797:	48 83 a4 24 60 02 02 	and    QWORD PTR [rsp+0x20260],0x0
    7ffff7fb279e:	00 00 
    7ffff7fb27a0:	4c 8d b4 24 d8 01 00 	lea    r14,[rsp+0x1d8]
    7ffff7fb27a7:	00 
    7ffff7fb27a8:	49 83 26 00          	and    QWORD PTR [r14],0x0
    7ffff7fb27ac:	49 c7 46 08 01 00 00 	mov    QWORD PTR [r14+0x8],0x1
    7ffff7fb27b3:	00 
    7ffff7fb27b4:	49 83 66 10 00       	and    QWORD PTR [r14+0x10],0x0
    7ffff7fb27b9:	c5 f8 11 83 00 00 01 	vmovups XMMWORD PTR [rbx+0x10000],xmm0
    7ffff7fb27c0:	00 
    7ffff7fb27c1:	31 c0                	xor    eax,eax
    7ffff7fb27c3:	45 31 ff             	xor    r15d,r15d
    7ffff7fb27c6:	49 39 c7             	cmp    r15,rax
    7ffff7fb27c9:	75 33                	jne    0x7ffff7fb27fe
    7ffff7fb27cb:	48 8b 05 26 6b 00 00 	mov    rax,QWORD PTR [rip+0x6b26]        # 0x7ffff7fb92f8
    7ffff7fb27d2:	41 b8 f8 ff 00 00    	mov    r8d,0xfff8
    7ffff7fb27d8:	31 c9                	xor    ecx,ecx
    7ffff7fb27da:	48 89 da             	mov    rdx,rbx
    7ffff7fb27dd:	ff 50 48             	call   QWORD PTR [rax+0x48]
    7ffff7fb27e0:	49 89 c7             	mov    r15,rax
    7ffff7fb27e3:	c6 84 04 50 02 00 00 	mov    BYTE PTR [rsp+rax*1+0x250],0x0
    7ffff7fb27ea:	00 
    7ffff7fb27eb:	48 89 84 24 50 02 01 	mov    QWORD PTR [rsp+0x10250],rax
    7ffff7fb27f2:	00 
    7ffff7fb27f3:	48 83 a4 24 58 02 01 	and    QWORD PTR [rsp+0x10258],0x0
    7ffff7fb27fa:	00 00 
    7ffff7fb27fc:	31 c0                	xor    eax,eax
    7ffff7fb27fe:	49 29 c7             	sub    r15,rax
    7ffff7fb2801:	0f 86 8a 00 00 00    	jbe    0x7ffff7fb2891
    7ffff7fb2807:	4c 8d 24 04          	lea    r12,[rsp+rax*1]
    7ffff7fb280b:	49 81 c4 50 02 00 00 	add    r12,0x250
    7ffff7fb2812:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2815:	4c 89 fe             	mov    rsi,r15
    7ffff7fb2818:	e8 4f 37 00 00       	call   0x7ffff7fb5f6c
    7ffff7fb281d:	48 83 f8 01          	cmp    rax,0x1
    7ffff7fb2821:	74 2e                	je     0x7ffff7fb2851
    7ffff7fb2823:	4c 89 f7             	mov    rdi,r14
    7ffff7fb2826:	4c 89 e6             	mov    rsi,r12
    7ffff7fb2829:	4c 89 fa             	mov    rdx,r15
    7ffff7fb282c:	e8 0f eb ff ff       	call   0x7ffff7fb1340
    7ffff7fb2831:	4c 03 bc 24 58 02 01 	add    r15,QWORD PTR [rsp+0x10258]
    7ffff7fb2838:	00 
    7ffff7fb2839:	4c 89 bc 24 58 02 01 	mov    QWORD PTR [rsp+0x10258],r15
    7ffff7fb2840:	00 
    7ffff7fb2841:	4c 89 f8             	mov    rax,r15
    7ffff7fb2844:	4c 8b bc 24 50 02 01 	mov    r15,QWORD PTR [rsp+0x10250]
    7ffff7fb284b:	00 
    7ffff7fb284c:	e9 75 ff ff ff       	jmp    0x7ffff7fb27c6
    7ffff7fb2851:	49 89 d5             	mov    r13,rdx
    7ffff7fb2854:	48 85 d2             	test   rdx,rdx
    7ffff7fb2857:	74 10                	je     0x7ffff7fb2869
    7ffff7fb2859:	49 8d 55 ff          	lea    rdx,[r13-0x1]
    7ffff7fb285d:	43 80 7c 2c ff 0d    	cmp    BYTE PTR [r12+r13*1-0x1],0xd
    7ffff7fb2863:	49 0f 45 d5          	cmovne rdx,r13
    7ffff7fb2867:	eb 02                	jmp    0x7ffff7fb286b
    7ffff7fb2869:	31 d2                	xor    edx,edx
    7ffff7fb286b:	48 8d bc 24 d8 01 00 	lea    rdi,[rsp+0x1d8]
    7ffff7fb2872:	00 
    7ffff7fb2873:	4c 89 e6             	mov    rsi,r12
    7ffff7fb2876:	e8 c5 ea ff ff       	call   0x7ffff7fb1340
    7ffff7fb287b:	48 8b 84 24 58 02 01 	mov    rax,QWORD PTR [rsp+0x10258]
    7ffff7fb2882:	00 
    7ffff7fb2883:	4c 01 e8             	add    rax,r13
    7ffff7fb2886:	48 ff c0             	inc    rax
    7ffff7fb2889:	48 89 84 24 58 02 01 	mov    QWORD PTR [rsp+0x10258],rax
    7ffff7fb2890:	00 
    7ffff7fb2891:	4c 8b b4 24 e0 01 00 	mov    r14,QWORD PTR [rsp+0x1e0]
    7ffff7fb2898:	00 
    7ffff7fb2899:	48 83 bc 24 e8 01 00 	cmp    QWORD PTR [rsp+0x1e8],0x40 # 입력값 길이 확인
    7ffff7fb28a0:	00 40 
    7ffff7fb28a2:	0f 85 8a 08 00 00    	jne    0x7ffff7fb3132
    7ffff7fb28a8:	6a 04                	push   0x4
    7ffff7fb28aa:	58                   	pop    rax
    7ffff7fb28ab:	31 c9                	xor    ecx,ecx
    7ffff7fb28ad:	4c 8d 64 24 30       	lea    r12,[rsp+0x30]
    7ffff7fb28b2:	6a 01                	push   0x1
    7ffff7fb28b4:	5d                   	pop    rbp
    7ffff7fb28b5:	4c 89 b4 24 48 01 00 	mov    QWORD PTR [rsp+0x148],r14
    7ffff7fb28bc:	00 
    7ffff7fb28bd:	48 83 e8 01          	sub    rax,0x1
    7ffff7fb28c1:	0f 82 36 09 00 00    	jb     0x7ffff7fb31fd
    7ffff7fb28c7:	48 89 84 24 c8 01 00 	mov    QWORD PTR [rsp+0x1c8],rax
    7ffff7fb28ce:	00 
    7ffff7fb28cf:	48 8d 41 10          	lea    rax,[rcx+0x10]
    7ffff7fb28d3:	48 89 84 24 c0 01 00 	mov    QWORD PTR [rsp+0x1c0],rax
    7ffff7fb28da:	00 
    7ffff7fb28db:	49 8d 34 0e          	lea    rsi,[r14+rcx*1]
    7ffff7fb28df:	4c 89 e7             	mov    rdi,r12
    7ffff7fb28e2:	6a 08                	push   0x8
    7ffff7fb28e4:	5a                   	pop    rdx
    7ffff7fb28e5:	4d 89 f7             	mov    r15,r14
    7ffff7fb28e8:	49 89 ce             	mov    r14,rcx
    7ffff7fb28eb:	e8 55 09 00 00       	call   0x7ffff7fb3245
    7ffff7fb28f0:	48 8b 5c 24 38       	mov    rbx,QWORD PTR [rsp+0x38]
    7ffff7fb28f5:	48 8b 54 24 40       	mov    rdx,QWORD PTR [rsp+0x40]
    7ffff7fb28fa:	4c 8d 6c 24 60       	lea    r13,[rsp+0x60]
    7ffff7fb28ff:	4c 89 ef             	mov    rdi,r13
    7ffff7fb2902:	48 89 de             	mov    rsi,rbx
    7ffff7fb2905:	e8 67 59 00 00       	call   0x7ffff7fb8271
    7ffff7fb290a:	4c 89 b4 24 d0 01 00 	mov    QWORD PTR [rsp+0x1d0],r14
    7ffff7fb2911:	00 
    7ffff7fb2912:	4d 01 fe             	add    r14,r15
    7ffff7fb2915:	49 83 c6 08          	add    r14,0x8
    7ffff7fb2919:	48 8b 44 24 70       	mov    rax,QWORD PTR [rsp+0x70]
    7ffff7fb291e:	48 89 84 24 60 01 00 	mov    QWORD PTR [rsp+0x160],rax
    7ffff7fb2925:	00 
    7ffff7fb2926:	c5 f8 10 44 24 60    	vmovups xmm0,XMMWORD PTR [rsp+0x60]
    7ffff7fb292c:	c5 f8 29 84 24 50 01 	vmovaps XMMWORD PTR [rsp+0x150],xmm0
    7ffff7fb2933:	00 00 
    7ffff7fb2935:	48 8b 7c 24 30       	mov    rdi,QWORD PTR [rsp+0x30]
    7ffff7fb293a:	48 89 de             	mov    rsi,rbx
    7ffff7fb293d:	e8 82 e9 ff ff       	call   0x7ffff7fb12c4
    7ffff7fb2942:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2945:	4c 89 f6             	mov    rsi,r14
    7ffff7fb2948:	6a 08                	push   0x8
    7ffff7fb294a:	5a                   	pop    rdx
    7ffff7fb294b:	e8 f5 08 00 00       	call   0x7ffff7fb3245
    7ffff7fb2950:	48 8b 5c 24 38       	mov    rbx,QWORD PTR [rsp+0x38]
    7ffff7fb2955:	48 8b 54 24 40       	mov    rdx,QWORD PTR [rsp+0x40]
    7ffff7fb295a:	4c 89 ef             	mov    rdi,r13
    7ffff7fb295d:	48 89 de             	mov    rsi,rbx
    7ffff7fb2960:	e8 0c 59 00 00       	call   0x7ffff7fb8271
    7ffff7fb2965:	48 8b 44 24 70       	mov    rax,QWORD PTR [rsp+0x70]
    7ffff7fb296a:	48 89 84 24 80 01 00 	mov    QWORD PTR [rsp+0x180],rax
    7ffff7fb2971:	00 
    7ffff7fb2972:	c5 f8 10 44 24 60    	vmovups xmm0,XMMWORD PTR [rsp+0x60]
    7ffff7fb2978:	c5 f8 29 84 24 70 01 	vmovaps XMMWORD PTR [rsp+0x170],xmm0
    7ffff7fb297f:	00 00 
    7ffff7fb2981:	48 8b 7c 24 30       	mov    rdi,QWORD PTR [rsp+0x30]
    7ffff7fb2986:	48 89 de             	mov    rsi,rbx
    7ffff7fb2989:	e8 36 e9 ff ff       	call   0x7ffff7fb12c4
    7ffff7fb298e:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2991:	48 8d 35 c0 c9 ff ff 	lea    rsi,[rip+0xffffffffffffc9c0]        # 0x7ffff7faf358
    7ffff7fb2998:	6a 20                	push   0x20
    7ffff7fb299a:	5a                   	pop    rdx
    7ffff7fb299b:	e8 a5 08 00 00       	call   0x7ffff7fb3245
    7ffff7fb29a0:	48 8b 5c 24 38       	mov    rbx,QWORD PTR [rsp+0x38]
    7ffff7fb29a5:	48 8b 54 24 40       	mov    rdx,QWORD PTR [rsp+0x40]
    7ffff7fb29aa:	4c 89 ef             	mov    rdi,r13
    7ffff7fb29ad:	6a 02                	push   0x2
    7ffff7fb29af:	41 5d                	pop    r13
    7ffff7fb29b1:	48 89 de             	mov    rsi,rbx
    7ffff7fb29b4:	e8 b8 58 00 00       	call   0x7ffff7fb8271
    7ffff7fb29b9:	48 8b 44 24 70       	mov    rax,QWORD PTR [rsp+0x70]
    7ffff7fb29be:	48 89 84 24 e0 00 00 	mov    QWORD PTR [rsp+0xe0],rax
    7ffff7fb29c5:	00 
    7ffff7fb29c6:	c5 f8 10 44 24 60    	vmovups xmm0,XMMWORD PTR [rsp+0x60]
    7ffff7fb29cc:	c5 f8 29 84 24 d0 00 	vmovaps XMMWORD PTR [rsp+0xd0],xmm0
    7ffff7fb29d3:	00 00 
    7ffff7fb29d5:	48 8b 7c 24 30       	mov    rdi,QWORD PTR [rsp+0x30]
    7ffff7fb29da:	48 89 de             	mov    rsi,rbx
    7ffff7fb29dd:	e8 e2 e8 ff ff       	call   0x7ffff7fb12c4
    7ffff7fb29e2:	48 c7 84 24 f0 01 00 	mov    QWORD PTR [rsp+0x1f0],0x2
    7ffff7fb29e9:	00 02 00 00 00 
    7ffff7fb29ee:	48 83 a4 24 f8 01 00 	and    QWORD PTR [rsp+0x1f8],0x0
    7ffff7fb29f5:	00 00 
    7ffff7fb29f7:	48 89 ac 24 00 02 00 	mov    QWORD PTR [rsp+0x200],rbp
    7ffff7fb29fe:	00 
    7ffff7fb29ff:	48 8d 9c 24 38 02 00 	lea    rbx,[rsp+0x238]
    7ffff7fb2a06:	00 
    7ffff7fb2a07:	48 89 df             	mov    rdi,rbx
    7ffff7fb2a0a:	48 8d b4 24 d0 00 00 	lea    rsi,[rsp+0xd0]
    7ffff7fb2a11:	00 
    7ffff7fb2a12:	48 8d 94 24 f0 01 00 	lea    rdx,[rsp+0x1f0]
    7ffff7fb2a19:	00 
    7ffff7fb2a1a:	e8 6f f3 ff ff       	call   0x7ffff7fb1d8e
    7ffff7fb2a1f:	c5 f8 10 05 b9 c8 ff 	vmovups xmm0,XMMWORD PTR [rip+0xffffffffffffc8b9]        # 0x7ffff7faf2e0
    7ffff7fb2a26:	ff 
    7ffff7fb2a27:	c5 f8 29 84 24 10 01 	vmovaps XMMWORD PTR [rsp+0x110],xmm0
    7ffff7fb2a2e:	00 00 
    7ffff7fb2a30:	48 89 ac 24 20 01 00 	mov    QWORD PTR [rsp+0x120],rbp
    7ffff7fb2a37:	00 
    7ffff7fb2a38:	48 8d bc 24 30 01 00 	lea    rdi,[rsp+0x130]
    7ffff7fb2a3f:	00 
    7ffff7fb2a40:	48 8d b4 24 70 01 00 	lea    rsi,[rsp+0x170]
    7ffff7fb2a47:	00 
    7ffff7fb2a48:	e8 4d 5a 00 00       	call   0x7ffff7fb849a
    7ffff7fb2a4d:	48 8d bc 24 f0 00 00 	lea    rdi,[rsp+0xf0]
    7ffff7fb2a54:	00 
    7ffff7fb2a55:	48 89 de             	mov    rsi,rbx
    7ffff7fb2a58:	e8 3d 5a 00 00       	call   0x7ffff7fb849a
    7ffff7fb2a5d:	48 8b bc 24 f0 00 00 	mov    rdi,QWORD PTR [rsp+0xf0]
    7ffff7fb2a64:	00 
    7ffff7fb2a65:	48 8b b4 24 00 01 00 	mov    rsi,QWORD PTR [rsp+0x100]
    7ffff7fb2a6c:	00 


    # ---------------------------정답 확인 로직-------------------------------



    7ffff7fb2a6d:	48 89 f0             	mov    rax,rsi
    7ffff7fb2a70:	48 f7 d8             	neg    rax
    7ffff7fb2a73:	48 0f 48 c6          	cmovs  rax,rsi ; rax = abs(rsi)
    7ffff7fb2a77:	48 83 f0 01          	xor    rax,0x1 ; rax = abs(rsi) ^ 1
    7ffff7fb2a7b:	48 09 f8             	or     rax,rdi ; rax = (abs(rsi) ^ 1) | rdi
    7ffff7fb2a7e:	0f 84 cc 04 00 00    	je     0x7ffff7fb2f50


    7ffff7fb2a84:	48 89 bc 24 a0 00 00 	mov    QWORD PTR [rsp+0xa0],rdi
    7ffff7fb2a8b:	00 
    7ffff7fb2a8c:	48 89 b4 24 a8 00 00 	mov    QWORD PTR [rsp+0xa8],rsi
    7ffff7fb2a93:	00 
    7ffff7fb2a94:	48 c7 84 24 b0 00 00 	mov    QWORD PTR [rsp+0xb0],0x2
    7ffff7fb2a9b:	00 02 00 00 00 
    7ffff7fb2aa0:	48 83 a4 24 b8 00 00 	and    QWORD PTR [rsp+0xb8],0x0
    7ffff7fb2aa7:	00 00 
    7ffff7fb2aa9:	48 c7 84 24 c0 00 00 	mov    QWORD PTR [rsp+0xc0],0x1
    7ffff7fb2ab0:	00 01 00 00 00 
    7ffff7fb2ab5:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2ab8:	48 8d b4 24 f0 00 00 	lea    rsi,[rsp+0xf0]
    7ffff7fb2abf:	00 
    7ffff7fb2ac0:	e8 74 e9 ff ff       	call   0x7ffff7fb1439
    7ffff7fb2ac5:	8a 44 24 30          	mov    al,BYTE PTR [rsp+0x30]
    7ffff7fb2ac9:	88 44 24 2f          	mov    BYTE PTR [rsp+0x2f],al
    7ffff7fb2acd:	4c 8b 6c 24 48       	mov    r13,QWORD PTR [rsp+0x48]
    7ffff7fb2ad2:	4c 8b 74 24 58       	mov    r14,QWORD PTR [rsp+0x58]
    7ffff7fb2ad7:	4c 8b 7c 24 50       	mov    r15,QWORD PTR [rsp+0x50]
    7ffff7fb2adc:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2adf:	44 8a 64 24 40       	mov    r12b,BYTE PTR [rsp+0x40]
    7ffff7fb2ae4:	48 89 fd             	mov    rbp,rdi
    7ffff7fb2ae7:	48 8d b4 24 b0 00 00 	lea    rsi,[rsp+0xb0]
    7ffff7fb2aee:	00 
    7ffff7fb2aef:	e8 45 e9 ff ff       	call   0x7ffff7fb1439
    7ffff7fb2af4:	8a 44 24 40          	mov    al,BYTE PTR [rsp+0x40]
    7ffff7fb2af8:	4c 8b 44 24 58       	mov    r8,QWORD PTR [rsp+0x58]
    7ffff7fb2afd:	48 8b 5c 24 50       	mov    rbx,QWORD PTR [rsp+0x50]
    7ffff7fb2b02:	41 f6 c4 01          	test   r12b,0x1
    7ffff7fb2b06:	74 36                	je     0x7ffff7fb2b3e
    7ffff7fb2b08:	a8 01                	test   al,0x1
    7ffff7fb2b0a:	74 5f                	je     0x7ffff7fb2b6b
    7ffff7fb2b0c:	49 39 df             	cmp    r15,rbx
    7ffff7fb2b0f:	49 89 ec             	mov    r12,rbp
    7ffff7fb2b12:	0f 83 bd 00 00 00    	jae    0x7ffff7fb2bd5
    7ffff7fb2b18:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2b1b:	4c 89 ee             	mov    rsi,r13
    7ffff7fb2b1e:	4c 89 fa             	mov    rdx,r15
    7ffff7fb2b21:	e8 b5 e7 ff ff       	call   0x7ffff7fb12db
    7ffff7fb2b26:	4c 8d b4 24 80 00 00 	lea    r14,[rsp+0x80]
    7ffff7fb2b2d:	00 
    7ffff7fb2b2e:	4c 89 f7             	mov    rdi,r14
    7ffff7fb2b31:	4c 89 e6             	mov    rsi,r12
    7ffff7fb2b34:	e8 bb 36 00 00       	call   0x7ffff7fb61f4
    7ffff7fb2b39:	e9 d3 00 00 00       	jmp    0x7ffff7fb2c11
    7ffff7fb2b3e:	a8 01                	test   al,0x1
    7ffff7fb2b40:	74 4a                	je     0x7ffff7fb2b8c
    7ffff7fb2b42:	49 83 fe 01          	cmp    r14,0x1
    7ffff7fb2b46:	6a 02                	push   0x2
    7ffff7fb2b48:	41 5d                	pop    r13
    7ffff7fb2b4a:	4c 89 e8             	mov    rax,r13
    7ffff7fb2b4d:	48 83 d8 00          	sbb    rax,0x0
    7ffff7fb2b51:	4c 89 bc 24 80 00 00 	mov    QWORD PTR [rsp+0x80],r15
    7ffff7fb2b58:	00 
    7ffff7fb2b59:	4c 89 b4 24 88 00 00 	mov    QWORD PTR [rsp+0x88],r14
    7ffff7fb2b60:	00 
    7ffff7fb2b61:	48 89 84 24 90 00 00 	mov    QWORD PTR [rsp+0x90],rax
    7ffff7fb2b68:	00 
    7ffff7fb2b69:	eb 5a                	jmp    0x7ffff7fb2bc5
    7ffff7fb2b6b:	4c 8d b4 24 80 00 00 	lea    r14,[rsp+0x80]
    7ffff7fb2b72:	00 
    7ffff7fb2b73:	4c 89 f7             	mov    rdi,r14
    7ffff7fb2b76:	4c 89 ee             	mov    rsi,r13
    7ffff7fb2b79:	4c 89 fa             	mov    rdx,r15
    7ffff7fb2b7c:	48 89 d9             	mov    rcx,rbx
    7ffff7fb2b7f:	e8 0c f4 ff ff       	call   0x7ffff7fb1f90
    7ffff7fb2b84:	49 89 ec             	mov    r12,rbp
    7ffff7fb2b87:	e9 85 00 00 00       	jmp    0x7ffff7fb2c11
    7ffff7fb2b8c:	4c 89 ff             	mov    rdi,r15
    7ffff7fb2b8f:	4c 89 f6             	mov    rsi,r14
    7ffff7fb2b92:	48 89 da             	mov    rdx,rbx
    7ffff7fb2b95:	4c 89 c1             	mov    rcx,r8
    7ffff7fb2b98:	ff 15 d2 5f 00 00    	call   QWORD PTR [rip+0x5fd2]        # 0x7ffff7fb8b70
    7ffff7fb2b9e:	48 83 fa 01          	cmp    rdx,0x1
    7ffff7fb2ba2:	6a 02                	push   0x2
    7ffff7fb2ba4:	41 5d                	pop    r13
    7ffff7fb2ba6:	4c 89 e9             	mov    rcx,r13
    7ffff7fb2ba9:	48 83 d9 00          	sbb    rcx,0x0
    7ffff7fb2bad:	48 89 84 24 80 00 00 	mov    QWORD PTR [rsp+0x80],rax
    7ffff7fb2bb4:	00 
    7ffff7fb2bb5:	48 89 94 24 88 00 00 	mov    QWORD PTR [rsp+0x88],rdx
    7ffff7fb2bbc:	00 
    7ffff7fb2bbd:	48 89 8c 24 90 00 00 	mov    QWORD PTR [rsp+0x90],rcx
    7ffff7fb2bc4:	00 
    7ffff7fb2bc5:	49 89 ec             	mov    r12,rbp
    7ffff7fb2bc8:	6a 01                	push   0x1
    7ffff7fb2bca:	5d                   	pop    rbp
    7ffff7fb2bcb:	4c 8d b4 24 80 00 00 	lea    r14,[rsp+0x80]
    7ffff7fb2bd2:	00 
    7ffff7fb2bd3:	eb 43                	jmp    0x7ffff7fb2c18
    7ffff7fb2bd5:	4c 8b 74 24 48       	mov    r14,QWORD PTR [rsp+0x48]
    7ffff7fb2bda:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
    7ffff7fb2bdf:	48 89 ef             	mov    rdi,rbp
    7ffff7fb2be2:	4c 89 ee             	mov    rsi,r13
    7ffff7fb2be5:	4c 89 fa             	mov    rdx,r15
    7ffff7fb2be8:	e8 ee e6 ff ff       	call   0x7ffff7fb12db
    7ffff7fb2bed:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2bf0:	4c 89 f6             	mov    rsi,r14
    7ffff7fb2bf3:	48 89 da             	mov    rdx,rbx
    7ffff7fb2bf6:	e8 e0 e6 ff ff       	call   0x7ffff7fb12db
    7ffff7fb2bfb:	4c 8d b4 24 80 00 00 	lea    r14,[rsp+0x80]
    7ffff7fb2c02:	00 
    7ffff7fb2c03:	4c 89 f7             	mov    rdi,r14
    7ffff7fb2c06:	48 89 ee             	mov    rsi,rbp
    7ffff7fb2c09:	4c 89 e2             	mov    rdx,r12
    7ffff7fb2c0c:	e8 ee 50 00 00       	call   0x7ffff7fb7cff
    7ffff7fb2c11:	6a 01                	push   0x1
    7ffff7fb2c13:	5d                   	pop    rbp
    7ffff7fb2c14:	6a 02                	push   0x2
    7ffff7fb2c16:	41 5d                	pop    r13
    7ffff7fb2c18:	0f b6 54 24 2f       	movzx  edx,BYTE PTR [rsp+0x2f]
    7ffff7fb2c1d:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2c20:	4c 89 f6             	mov    rsi,r14
    7ffff7fb2c23:	e8 b5 e8 ff ff       	call   0x7ffff7fb14dd
    7ffff7fb2c28:	48 8b 5c 24 30       	mov    rbx,QWORD PTR [rsp+0x30]
    7ffff7fb2c2d:	48 8b 74 24 40       	mov    rsi,QWORD PTR [rsp+0x40]
    7ffff7fb2c32:	49 89 f6             	mov    r14,rsi
    7ffff7fb2c35:	49 f7 de             	neg    r14
    7ffff7fb2c38:	4c 0f 48 f6          	cmovs  r14,rsi
    7ffff7fb2c3c:	49 83 f6 01          	xor    r14,0x1
    7ffff7fb2c40:	48 89 df             	mov    rdi,rbx
    7ffff7fb2c43:	e8 bb 4f 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2c48:	4c 89 ef             	mov    rdi,r13
    7ffff7fb2c4b:	48 89 ee             	mov    rsi,rbp
    7ffff7fb2c4e:	e8 b0 4f 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2c53:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2c56:	49 09 de             	or     r14,rbx
    7ffff7fb2c59:	0f 85 b4 00 00 00    	jne    0x7ffff7fb2d13
    7ffff7fb2c5f:	48 8d 94 24 30 01 00 	lea    rdx,[rsp+0x130]
    7ffff7fb2c66:	00 
    7ffff7fb2c67:	48 89 d6             	mov    rsi,rdx
    7ffff7fb2c6a:	e8 cf f5 ff ff       	call   0x7ffff7fb223e
    7ffff7fb2c6f:	48 8d 7c 24 60       	lea    rdi,[rsp+0x60]
    7ffff7fb2c74:	4c 89 e6             	mov    rsi,r12
    7ffff7fb2c77:	48 8d 94 24 d0 00 00 	lea    rdx,[rsp+0xd0]
    7ffff7fb2c7e:	00 
    7ffff7fb2c7f:	e8 c1 f1 ff ff       	call   0x7ffff7fb1e45
    7ffff7fb2c84:	48 8b bc 24 30 01 00 	mov    rdi,QWORD PTR [rsp+0x130]
    7ffff7fb2c8b:	00 
    7ffff7fb2c8c:	48 8b b4 24 40 01 00 	mov    rsi,QWORD PTR [rsp+0x140]
    7ffff7fb2c93:	00 
    7ffff7fb2c94:	e8 6a 4f 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2c99:	48 8b 44 24 70       	mov    rax,QWORD PTR [rsp+0x70]
    7ffff7fb2c9e:	48 89 84 24 40 01 00 	mov    QWORD PTR [rsp+0x140],rax
    7ffff7fb2ca5:	00 
    7ffff7fb2ca6:	c5 f8 10 44 24 60    	vmovups xmm0,XMMWORD PTR [rsp+0x60]
    7ffff7fb2cac:	c5 f8 29 84 24 30 01 	vmovaps XMMWORD PTR [rsp+0x130],xmm0
    7ffff7fb2cb3:	00 00 
    7ffff7fb2cb5:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2cb8:	48 8d b4 24 f0 00 00 	lea    rsi,[rsp+0xf0]
    7ffff7fb2cbf:	00 
    7ffff7fb2cc0:	e8 74 e7 ff ff       	call   0x7ffff7fb1439
    7ffff7fb2cc5:	48 8d 44 24 40       	lea    rax,[rsp+0x40]
    7ffff7fb2cca:	c5 fc 10 00          	vmovups ymm0,YMMWORD PTR [rax]
    7ffff7fb2cce:	c5 fc 11 84 24 b0 00 	vmovups YMMWORD PTR [rsp+0xb0],ymm0
    7ffff7fb2cd5:	00 00 
    7ffff7fb2cd7:	80 7c 24 30 00       	cmp    BYTE PTR [rsp+0x30],0x0
    7ffff7fb2cdc:	0f 84 e4 00 00 00    	je     0x7ffff7fb2dc6
    7ffff7fb2ce2:	4c 8b bc 24 c0 00 00 	mov    r15,QWORD PTR [rsp+0xc0]
    7ffff7fb2ce9:	00 
    7ffff7fb2cea:	f6 84 24 b0 00 00 00 	test   BYTE PTR [rsp+0xb0],0x1
    7ffff7fb2cf1:	01 
    7ffff7fb2cf2:	0f 84 eb 00 00 00    	je     0x7ffff7fb2de3
    7ffff7fb2cf8:	48 8b bc 24 b8 00 00 	mov    rdi,QWORD PTR [rsp+0xb8]
    7ffff7fb2cff:	00 
    7ffff7fb2d00:	4c 89 fe             	mov    rsi,r15
    7ffff7fb2d03:	c5 f8 77             	vzeroupper
    7ffff7fb2d06:	e8 73 37 00 00       	call   0x7ffff7fb647e
    7ffff7fb2d0b:	41 89 c7             	mov    r15d,eax
    7ffff7fb2d0e:	e9 d4 00 00 00       	jmp    0x7ffff7fb2de7
    7ffff7fb2d13:	48 8d b4 24 10 01 00 	lea    rsi,[rsp+0x110]
    7ffff7fb2d1a:	00 
    7ffff7fb2d1b:	48 8d 94 24 30 01 00 	lea    rdx,[rsp+0x130]
    7ffff7fb2d22:	00 
    7ffff7fb2d23:	e8 16 f5 ff ff       	call   0x7ffff7fb223e
    7ffff7fb2d28:	48 8d 7c 24 60       	lea    rdi,[rsp+0x60]
    7ffff7fb2d2d:	4c 89 e6             	mov    rsi,r12
    7ffff7fb2d30:	48 8d 94 24 d0 00 00 	lea    rdx,[rsp+0xd0]
    7ffff7fb2d37:	00 
    7ffff7fb2d38:	e8 08 f1 ff ff       	call   0x7ffff7fb1e45
    7ffff7fb2d3d:	48 8b bc 24 10 01 00 	mov    rdi,QWORD PTR [rsp+0x110]
    7ffff7fb2d44:	00 
    7ffff7fb2d45:	48 8b b4 24 20 01 00 	mov    rsi,QWORD PTR [rsp+0x120]
    7ffff7fb2d4c:	00 
    7ffff7fb2d4d:	e8 b1 4e 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2d52:	48 8b 44 24 70       	mov    rax,QWORD PTR [rsp+0x70]
    7ffff7fb2d57:	48 89 84 24 20 01 00 	mov    QWORD PTR [rsp+0x120],rax
    7ffff7fb2d5e:	00 
    7ffff7fb2d5f:	c5 f8 10 44 24 60    	vmovups xmm0,XMMWORD PTR [rsp+0x60]
    7ffff7fb2d65:	c5 f8 29 84 24 10 01 	vmovaps XMMWORD PTR [rsp+0x110],xmm0
    7ffff7fb2d6c:	00 00 
    7ffff7fb2d6e:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2d71:	48 8d b4 24 f0 00 00 	lea    rsi,[rsp+0xf0]
    7ffff7fb2d78:	00 
    7ffff7fb2d79:	48 8d 15 60 c5 ff ff 	lea    rdx,[rip+0xffffffffffffc560]        # 0x7ffff7faf2e0
    7ffff7fb2d80:	e8 09 f0 ff ff       	call   0x7ffff7fb1d8e
    7ffff7fb2d85:	48 8b bc 24 a0 00 00 	mov    rdi,QWORD PTR [rsp+0xa0]
    7ffff7fb2d8c:	00 
    7ffff7fb2d8d:	48 8b b4 24 a8 00 00 	mov    rsi,QWORD PTR [rsp+0xa8]
    7ffff7fb2d94:	00 
    7ffff7fb2d95:	e8 69 4e 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2d9a:	48 8b 44 24 40       	mov    rax,QWORD PTR [rsp+0x40]
    7ffff7fb2d9f:	48 89 84 24 00 01 00 	mov    QWORD PTR [rsp+0x100],rax
    7ffff7fb2da6:	00 
    7ffff7fb2da7:	c5 f8 10 44 24 30    	vmovups xmm0,XMMWORD PTR [rsp+0x30]
    7ffff7fb2dad:	c5 f8 29 84 24 f0 00 	vmovaps XMMWORD PTR [rsp+0xf0],xmm0
    7ffff7fb2db4:	00 00 
    7ffff7fb2db6:	48 89 ef             	mov    rdi,rbp
    7ffff7fb2db9:	48 89 ee             	mov    rsi,rbp
    7ffff7fb2dbc:	e8 42 4e 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2dc1:	e9 97 fc ff ff       	jmp    0x7ffff7fb2a5d
    7ffff7fb2dc6:	48 8d bc 24 a8 01 00 	lea    rdi,[rsp+0x1a8]
    7ffff7fb2dcd:	00 
    7ffff7fb2dce:	48 8d b4 24 b0 00 00 	lea    rsi,[rsp+0xb0]
    7ffff7fb2dd5:	00 
    7ffff7fb2dd6:	c5 f8 77             	vzeroupper
    7ffff7fb2dd9:	e8 75 f8 ff ff       	call   0x7ffff7fb2653
    7ffff7fb2dde:	e9 31 01 00 00       	jmp    0x7ffff7fb2f14
    7ffff7fb2de3:	41 80 e7 01          	and    r15b,0x1
    7ffff7fb2de7:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2dea:	48 8d b4 24 b0 00 00 	lea    rsi,[rsp+0xb0]
    7ffff7fb2df1:	00 
    7ffff7fb2df2:	c5 f8 77             	vzeroupper
    7ffff7fb2df5:	e8 59 f8 ff ff       	call   0x7ffff7fb2653
    7ffff7fb2dfa:	48 8b 44 24 40       	mov    rax,QWORD PTR [rsp+0x40]
    7ffff7fb2dff:	48 8d 48 01          	lea    rcx,[rax+0x1]
    7ffff7fb2e03:	48 f7 c1 fd ff ff ff 	test   rcx,0xfffffffffffffffd
    7ffff7fb2e0a:	75 08                	jne    0x7ffff7fb2e14
    7ffff7fb2e0c:	48 83 7c 24 30 00    	cmp    QWORD PTR [rsp+0x30],0x0
    7ffff7fb2e12:	74 08                	je     0x7ffff7fb2e1c
    7ffff7fb2e14:	48 f7 d8             	neg    rax
    7ffff7fb2e17:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
    7ffff7fb2e1c:	48 8b 44 24 40       	mov    rax,QWORD PTR [rsp+0x40]
    7ffff7fb2e21:	48 89 84 24 30 02 00 	mov    QWORD PTR [rsp+0x230],rax
    7ffff7fb2e28:	00 
    7ffff7fb2e29:	c5 f8 10 44 24 30    	vmovups xmm0,XMMWORD PTR [rsp+0x30]
    7ffff7fb2e2f:	c5 f8 29 84 24 20 02 	vmovaps XMMWORD PTR [rsp+0x220],xmm0
    7ffff7fb2e36:	00 00 
    7ffff7fb2e38:	41 0f b6 c7          	movzx  eax,r15b
    7ffff7fb2e3c:	48 89 84 24 08 02 00 	mov    QWORD PTR [rsp+0x208],rax
    7ffff7fb2e43:	00 
    7ffff7fb2e44:	48 83 a4 24 10 02 00 	and    QWORD PTR [rsp+0x210],0x0
    7ffff7fb2e4b:	00 00 
    7ffff7fb2e4d:	48 c7 84 24 18 02 00 	mov    QWORD PTR [rsp+0x218],0x1
    7ffff7fb2e54:	00 01 00 00 00 
    7ffff7fb2e59:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2e5c:	48 8d b4 24 20 02 00 	lea    rsi,[rsp+0x220]
    7ffff7fb2e63:	00 
    7ffff7fb2e64:	e8 11 e6 ff ff       	call   0x7ffff7fb147a
    7ffff7fb2e69:	4c 8d 74 24 40       	lea    r14,[rsp+0x40]
    7ffff7fb2e6e:	c4 c1 7c 10 06       	vmovups ymm0,YMMWORD PTR [r14]
    7ffff7fb2e73:	c5 fc 11 84 24 80 00 	vmovups YMMWORD PTR [rsp+0x80],ymm0
    7ffff7fb2e7a:	00 00 
    7ffff7fb2e7c:	8a 5c 24 30          	mov    bl,BYTE PTR [rsp+0x30]
    7ffff7fb2e80:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2e83:	48 8d b4 24 08 02 00 	lea    rsi,[rsp+0x208]
    7ffff7fb2e8a:	00 
    7ffff7fb2e8b:	c5 f8 77             	vzeroupper
    7ffff7fb2e8e:	e8 e7 e5 ff ff       	call   0x7ffff7fb147a
    7ffff7fb2e93:	8a 44 24 30          	mov    al,BYTE PTR [rsp+0x30]
    7ffff7fb2e97:	c4 c1 7c 10 06       	vmovups ymm0,YMMWORD PTR [r14]
    7ffff7fb2e9c:	c5 fc 11 44 24 60    	vmovups YMMWORD PTR [rsp+0x60],ymm0
    7ffff7fb2ea2:	84 db                	test   bl,bl
    7ffff7fb2ea4:	74 1b                	je     0x7ffff7fb2ec1
    7ffff7fb2ea6:	84 c0                	test   al,al
    7ffff7fb2ea8:	48 8d 94 24 80 00 00 	lea    rdx,[rsp+0x80]
    7ffff7fb2eaf:	00 
    7ffff7fb2eb0:	74 3c                	je     0x7ffff7fb2eee
    7ffff7fb2eb2:	48 8d bc 24 a8 01 00 	lea    rdi,[rsp+0x1a8]
    7ffff7fb2eb9:	00 
    7ffff7fb2eba:	48 8d 74 24 60       	lea    rsi,[rsp+0x60]
    7ffff7fb2ebf:	eb 23                	jmp    0x7ffff7fb2ee4
    7ffff7fb2ec1:	84 c0                	test   al,al
    7ffff7fb2ec3:	48 8d b4 24 80 00 00 	lea    rsi,[rsp+0x80]
    7ffff7fb2eca:	00 
    7ffff7fb2ecb:	48 8d bc 24 a8 01 00 	lea    rdi,[rsp+0x1a8]
    7ffff7fb2ed2:	00 
    7ffff7fb2ed3:	48 8d 54 24 60       	lea    rdx,[rsp+0x60]
    7ffff7fb2ed8:	74 0a                	je     0x7ffff7fb2ee4
    7ffff7fb2eda:	c5 f8 77             	vzeroupper
    7ffff7fb2edd:	e8 66 eb ff ff       	call   0x7ffff7fb1a48
    7ffff7fb2ee2:	eb 30                	jmp    0x7ffff7fb2f14
    7ffff7fb2ee4:	c5 f8 77             	vzeroupper
    7ffff7fb2ee7:	e8 8a e6 ff ff       	call   0x7ffff7fb1576
    7ffff7fb2eec:	eb 26                	jmp    0x7ffff7fb2f14
    7ffff7fb2eee:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2ef1:	48 89 d6             	mov    rsi,rdx
    7ffff7fb2ef4:	48 8d 54 24 60       	lea    rdx,[rsp+0x60]
    7ffff7fb2ef9:	c5 f8 77             	vzeroupper
    7ffff7fb2efc:	e8 47 eb ff ff       	call   0x7ffff7fb1a48
    7ffff7fb2f01:	48 8d bc 24 a8 01 00 	lea    rdi,[rsp+0x1a8]
    7ffff7fb2f08:	00 
    7ffff7fb2f09:	4c 89 e6             	mov    rsi,r12
    7ffff7fb2f0c:	6a 01                	push   0x1
    7ffff7fb2f0e:	5a                   	pop    rdx
    7ffff7fb2f0f:	e8 c9 e5 ff ff       	call   0x7ffff7fb14dd
    7ffff7fb2f14:	48 8b b4 24 a8 00 00 	mov    rsi,QWORD PTR [rsp+0xa8]
    7ffff7fb2f1b:	00 
    7ffff7fb2f1c:	48 8b bc 24 a0 00 00 	mov    rdi,QWORD PTR [rsp+0xa0]
    7ffff7fb2f23:	00 
    7ffff7fb2f24:	e8 da 4c 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2f29:	48 8b 84 24 b8 01 00 	mov    rax,QWORD PTR [rsp+0x1b8]
    7ffff7fb2f30:	00 
    7ffff7fb2f31:	48 89 84 24 00 01 00 	mov    QWORD PTR [rsp+0x100],rax
    7ffff7fb2f38:	00 
    7ffff7fb2f39:	c5 f8 10 84 24 a8 01 	vmovups xmm0,XMMWORD PTR [rsp+0x1a8]
    7ffff7fb2f40:	00 00 
    7ffff7fb2f42:	c5 f8 29 84 24 f0 00 	vmovaps XMMWORD PTR [rsp+0xf0],xmm0
    7ffff7fb2f49:	00 00 
    7ffff7fb2f4b:	e9 0d fb ff ff       	jmp    0x7ffff7fb2a5d
    7ffff7fb2f50:	48 8b 84 24 20 01 00 	mov    rax,QWORD PTR [rsp+0x120]
    7ffff7fb2f57:	00 
    7ffff7fb2f58:	48 89 84 24 a0 01 00 	mov    QWORD PTR [rsp+0x1a0],rax
    7ffff7fb2f5f:	00 
    7ffff7fb2f60:	c5 f8 28 84 24 10 01 	vmovaps xmm0,XMMWORD PTR [rsp+0x110]
    7ffff7fb2f67:	00 00 
    7ffff7fb2f69:	c5 f8 29 84 24 90 01 	vmovaps XMMWORD PTR [rsp+0x190],xmm0
    7ffff7fb2f70:	00 00 
    7ffff7fb2f72:	e8 8c 4c 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2f77:	48 8b bc 24 30 01 00 	mov    rdi,QWORD PTR [rsp+0x130]
    7ffff7fb2f7e:	00 
    7ffff7fb2f7f:	48 8b b4 24 40 01 00 	mov    rsi,QWORD PTR [rsp+0x140]
    7ffff7fb2f86:	00 
    7ffff7fb2f87:	e8 77 4c 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2f8c:	48 8b bc 24 38 02 00 	mov    rdi,QWORD PTR [rsp+0x238]
    7ffff7fb2f93:	00 
    7ffff7fb2f94:	48 8b b4 24 48 02 00 	mov    rsi,QWORD PTR [rsp+0x248]
    7ffff7fb2f9b:	00 
    7ffff7fb2f9c:	e8 62 4c 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2fa1:	4c 89 ef             	mov    rdi,r13
    7ffff7fb2fa4:	48 89 ee             	mov    rsi,rbp
    7ffff7fb2fa7:	e8 57 4c 00 00       	call   0x7ffff7fb7c03
    7ffff7fb2fac:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2faf:	48 8d b4 24 50 01 00 	lea    rsi,[rsp+0x150]
    7ffff7fb2fb6:	00 
    7ffff7fb2fb7:	48 8d 94 24 90 01 00 	lea    rdx,[rsp+0x190]
    7ffff7fb2fbe:	00 
    7ffff7fb2fbf:	e8 7a f2 ff ff       	call   0x7ffff7fb223e
    7ffff7fb2fc4:	4c 8d bc 24 b0 00 00 	lea    r15,[rsp+0xb0]
    7ffff7fb2fcb:	00 
    7ffff7fb2fcc:	4c 89 ff             	mov    rdi,r15
    7ffff7fb2fcf:	4c 89 e6             	mov    rsi,r12
    7ffff7fb2fd2:	48 8d 94 24 d0 00 00 	lea    rdx,[rsp+0xd0]
    7ffff7fb2fd9:	00 
    7ffff7fb2fda:	e8 66 ee ff ff       	call   0x7ffff7fb1e45
    7ffff7fb2fdf:	48 8d 05 52 5a 00 00 	lea    rax,[rip+0x5a52]        # 0x7ffff7fb8a38
    7ffff7fb2fe6:	48 8b 8c 24 d0 01 00 	mov    rcx,QWORD PTR [rsp+0x1d0]
    7ffff7fb2fed:	00 
    7ffff7fb2fee:	48 8b 34 01          	mov    rsi,QWORD PTR [rcx+rax*1]
    7ffff7fb2ff2:	48 8b 54 01 08       	mov    rdx,QWORD PTR [rcx+rax*1+0x8]
    7ffff7fb2ff7:	4c 89 e7             	mov    rdi,r12
    7ffff7fb2ffa:	e8 46 02 00 00       	call   0x7ffff7fb3245
    7ffff7fb2fff:	48 8b 5c 24 38       	mov    rbx,QWORD PTR [rsp+0x38]
    7ffff7fb3004:	48 8b 54 24 40       	mov    rdx,QWORD PTR [rsp+0x40]
    7ffff7fb3009:	4c 8d 74 24 60       	lea    r14,[rsp+0x60]
    7ffff7fb300e:	4c 89 f7             	mov    rdi,r14
    7ffff7fb3011:	48 89 de             	mov    rsi,rbx
    7ffff7fb3014:	e8 58 52 00 00       	call   0x7ffff7fb8271
    7ffff7fb3019:	48 8b 44 24 70       	mov    rax,QWORD PTR [rsp+0x70]
    7ffff7fb301e:	48 89 84 24 90 00 00 	mov    QWORD PTR [rsp+0x90],rax
    7ffff7fb3025:	00 
    7ffff7fb3026:	c5 f8 10 44 24 60    	vmovups xmm0,XMMWORD PTR [rsp+0x60]
    7ffff7fb302c:	c5 f8 29 84 24 80 00 	vmovaps XMMWORD PTR [rsp+0x80],xmm0
    7ffff7fb3033:	00 00 
    7ffff7fb3035:	48 8b 7c 24 30       	mov    rdi,QWORD PTR [rsp+0x30]
    7ffff7fb303a:	48 89 de             	mov    rsi,rbx
    7ffff7fb303d:	e8 82 e2 ff ff       	call   0x7ffff7fb12c4
    7ffff7fb3042:	4c 89 f7             	mov    rdi,r14
    7ffff7fb3045:	4c 89 fe             	mov    rsi,r15
    7ffff7fb3048:	e8 70 4c 00 00       	call   0x7ffff7fb7cbd
    7ffff7fb304d:	4c 89 e7             	mov    rdi,r12
    7ffff7fb3050:	48 8d b4 24 80 00 00 	lea    rsi,[rsp+0x80]
    7ffff7fb3057:	00 
    7ffff7fb3058:	e8 60 4c 00 00       	call   0x7ffff7fb7cbd
    7ffff7fb305d:	8a 44 24 60          	mov    al,BYTE PTR [rsp+0x60]
    7ffff7fb3061:	3a 44 24 30          	cmp    al,BYTE PTR [rsp+0x30]
    7ffff7fb3065:	0f 85 f9 00 00 00    	jne    0x7ffff7fb3164
    7ffff7fb306b:	48 8b 54 24 70       	mov    rdx,QWORD PTR [rsp+0x70]
    7ffff7fb3070:	48 3b 54 24 40       	cmp    rdx,QWORD PTR [rsp+0x40]
    7ffff7fb3075:	0f 85 e9 00 00 00    	jne    0x7ffff7fb3164
    7ffff7fb307b:	48 8b 74 24 38       	mov    rsi,QWORD PTR [rsp+0x38]
    7ffff7fb3080:	48 8b 7c 24 68       	mov    rdi,QWORD PTR [rsp+0x68]
    7ffff7fb3085:	48 c1 e2 03          	shl    rdx,0x3
    7ffff7fb3089:	ff 15 01 5b 00 00    	call   QWORD PTR [rip+0x5b01]        # 0x7ffff7fb8b90
    7ffff7fb308f:	85 c0                	test   eax,eax
    7ffff7fb3091:	4c 8b b4 24 48 01 00 	mov    r14,QWORD PTR [rsp+0x148]
    7ffff7fb3098:	00 
    7ffff7fb3099:	0f 85 cd 00 00 00    	jne    0x7ffff7fb316c
    7ffff7fb309f:	48 8b bc 24 80 00 00 	mov    rdi,QWORD PTR [rsp+0x80]
    7ffff7fb30a6:	00 
    7ffff7fb30a7:	48 8b b4 24 90 00 00 	mov    rsi,QWORD PTR [rsp+0x90]
    7ffff7fb30ae:	00 
    7ffff7fb30af:	e8 4f 4b 00 00       	call   0x7ffff7fb7c03
    7ffff7fb30b4:	48 8b bc 24 b0 00 00 	mov    rdi,QWORD PTR [rsp+0xb0]
    7ffff7fb30bb:	00 
    7ffff7fb30bc:	48 8b b4 24 c0 00 00 	mov    rsi,QWORD PTR [rsp+0xc0]
    7ffff7fb30c3:	00 
    7ffff7fb30c4:	e8 3a 4b 00 00       	call   0x7ffff7fb7c03
    7ffff7fb30c9:	48 8b bc 24 90 01 00 	mov    rdi,QWORD PTR [rsp+0x190]
    7ffff7fb30d0:	00 
    7ffff7fb30d1:	48 8b b4 24 a0 01 00 	mov    rsi,QWORD PTR [rsp+0x1a0]
    7ffff7fb30d8:	00 
    7ffff7fb30d9:	e8 25 4b 00 00       	call   0x7ffff7fb7c03
    7ffff7fb30de:	48 8b bc 24 d0 00 00 	mov    rdi,QWORD PTR [rsp+0xd0]
    7ffff7fb30e5:	00 
    7ffff7fb30e6:	48 8b b4 24 e0 00 00 	mov    rsi,QWORD PTR [rsp+0xe0]
    7ffff7fb30ed:	00 
    7ffff7fb30ee:	e8 10 4b 00 00       	call   0x7ffff7fb7c03
    7ffff7fb30f3:	48 8b bc 24 70 01 00 	mov    rdi,QWORD PTR [rsp+0x170]
    7ffff7fb30fa:	00 
    7ffff7fb30fb:	48 8b b4 24 80 01 00 	mov    rsi,QWORD PTR [rsp+0x180]
    7ffff7fb3102:	00 
    7ffff7fb3103:	e8 fb 4a 00 00       	call   0x7ffff7fb7c03
    7ffff7fb3108:	48 8b bc 24 50 01 00 	mov    rdi,QWORD PTR [rsp+0x150]
    7ffff7fb310f:	00 
    7ffff7fb3110:	48 8b b4 24 60 01 00 	mov    rsi,QWORD PTR [rsp+0x160]
    7ffff7fb3117:	00 
    7ffff7fb3118:	e8 e6 4a 00 00       	call   0x7ffff7fb7c03
    7ffff7fb311d:	48 8b 8c 24 c0 01 00 	mov    rcx,QWORD PTR [rsp+0x1c0]
    7ffff7fb3124:	00 
    7ffff7fb3125:	48 8b 84 24 c8 01 00 	mov    rax,QWORD PTR [rsp+0x1c8]
    7ffff7fb312c:	00 
    7ffff7fb312d:	e9 8b f7 ff ff       	jmp    0x7ffff7fb28bd
    7ffff7fb3132:	48 8d 35 5f c2 ff ff 	lea    rsi,[rip+0xffffffffffffc25f]        # 0x7ffff7faf398
    7ffff7fb3139:	48 8d 9c 24 60 02 01 	lea    rbx,[rsp+0x10260]
    7ffff7fb3140:	00 
    7ffff7fb3141:	6a 05                	push   0x5
    7ffff7fb3143:	5a                   	pop    rdx
    7ffff7fb3144:	48 89 df             	mov    rdi,rbx
    7ffff7fb3147:	e8 ef e0 ff ff       	call   0x7ffff7fb123b
    7ffff7fb314c:	48 8b bc 24 d8 01 00 	mov    rdi,QWORD PTR [rsp+0x1d8]
    7ffff7fb3153:	00 
    7ffff7fb3154:	4c 89 f6             	mov    rsi,r14
    7ffff7fb3157:	e8 68 e1 ff ff       	call   0x7ffff7fb12c4
    7ffff7fb315c:	48 89 df             	mov    rdi,rbx
    7ffff7fb315f:	e9 c8 00 00 00       	jmp    0x7ffff7fb322c
    7ffff7fb3164:	4c 8b b4 24 48 01 00 	mov    r14,QWORD PTR [rsp+0x148]
    7ffff7fb316b:	00 
    7ffff7fb316c:	48 8b bc 24 80 00 00 	mov    rdi,QWORD PTR [rsp+0x80]
    7ffff7fb3173:	00 
    7ffff7fb3174:	48 8b b4 24 90 00 00 	mov    rsi,QWORD PTR [rsp+0x90]
    7ffff7fb317b:	00 
    7ffff7fb317c:	e8 82 4a 00 00       	call   0x7ffff7fb7c03
    7ffff7fb3181:	48 8b bc 24 b0 00 00 	mov    rdi,QWORD PTR [rsp+0xb0]
    7ffff7fb3188:	00 
    7ffff7fb3189:	48 8b b4 24 c0 00 00 	mov    rsi,QWORD PTR [rsp+0xc0]
    7ffff7fb3190:	00 
    7ffff7fb3191:	e8 6d 4a 00 00       	call   0x7ffff7fb7c03
    7ffff7fb3196:	48 8b bc 24 90 01 00 	mov    rdi,QWORD PTR [rsp+0x190]
    7ffff7fb319d:	00 
    7ffff7fb319e:	48 8b b4 24 a0 01 00 	mov    rsi,QWORD PTR [rsp+0x1a0]
    7ffff7fb31a5:	00 
    7ffff7fb31a6:	e8 58 4a 00 00       	call   0x7ffff7fb7c03
    7ffff7fb31ab:	48 8b bc 24 d0 00 00 	mov    rdi,QWORD PTR [rsp+0xd0]
    7ffff7fb31b2:	00 
    7ffff7fb31b3:	48 8b b4 24 e0 00 00 	mov    rsi,QWORD PTR [rsp+0xe0]
    7ffff7fb31ba:	00 
    7ffff7fb31bb:	e8 43 4a 00 00       	call   0x7ffff7fb7c03
    7ffff7fb31c0:	48 8b bc 24 70 01 00 	mov    rdi,QWORD PTR [rsp+0x170]
    7ffff7fb31c7:	00 
    7ffff7fb31c8:	48 8b b4 24 80 01 00 	mov    rsi,QWORD PTR [rsp+0x180]
    7ffff7fb31cf:	00 
    7ffff7fb31d0:	e8 2e 4a 00 00       	call   0x7ffff7fb7c03
    7ffff7fb31d5:	48 8b bc 24 50 01 00 	mov    rdi,QWORD PTR [rsp+0x150]
    7ffff7fb31dc:	00 
    7ffff7fb31dd:	48 8b b4 24 60 01 00 	mov    rsi,QWORD PTR [rsp+0x160]
    7ffff7fb31e4:	00 
    7ffff7fb31e5:	e8 19 4a 00 00       	call   0x7ffff7fb7c03
    7ffff7fb31ea:	48 8d 35 a7 c1 ff ff 	lea    rsi,[rip+0xffffffffffffc1a7]        # 0x7ffff7faf398
    7ffff7fb31f1:	48 8d bc 24 60 02 01 	lea    rdi,[rsp+0x10260]
    7ffff7fb31f8:	00 
    7ffff7fb31f9:	6a 05                	push   0x5
    7ffff7fb31fb:	eb 11                	jmp    0x7ffff7fb320e
    7ffff7fb31fd:	48 8d 35 99 c1 ff ff 	lea    rsi,[rip+0xffffffffffffc199]        # 0x7ffff7faf39d
    7ffff7fb3204:	48 8d bc 24 60 02 01 	lea    rdi,[rsp+0x10260]
    7ffff7fb320b:	00 
    7ffff7fb320c:	6a 07                	push   0x7
    7ffff7fb320e:	5a                   	pop    rdx
    7ffff7fb320f:	e8 27 e0 ff ff       	call   0x7ffff7fb123b
    7ffff7fb3214:	48 8b bc 24 d8 01 00 	mov    rdi,QWORD PTR [rsp+0x1d8]
    7ffff7fb321b:	00 
    7ffff7fb321c:	4c 89 f6             	mov    rsi,r14
    7ffff7fb321f:	e8 a0 e0 ff ff       	call   0x7ffff7fb12c4
    7ffff7fb3224:	48 8d bc 24 60 02 01 	lea    rdi,[rsp+0x10260]
    7ffff7fb322b:	00 
    7ffff7fb322c:	e8 e0 e1 ff ff       	call   0x7ffff7fb1411
    7ffff7fb3231:	48 81 c4 68 02 02 00 	add    rsp,0x20268
    7ffff7fb3238:	5b                   	pop    rbx
    7ffff7fb3239:	41 5c                	pop    r12
    7ffff7fb323b:	41 5d                	pop    r13
    7ffff7fb323d:	41 5e                	pop    r14
    7ffff7fb323f:	41 5f                	pop    r15
    7ffff7fb3241:	5d                   	pop    rbp
    7ffff7fb3242:	c3                   	ret
    7ffff7fb3243:	0f 0b                	ud2
    7ffff7fb3245:	55                   	push   rbp
    7ffff7fb3246:	41 57                	push   r15
    7ffff7fb3248:	41 56                	push   r14
    7ffff7fb324a:	41 55                	push   r13
    7ffff7fb324c:	41 54                	push   r12
    7ffff7fb324e:	53                   	push   rbx
    7ffff7fb324f:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb3253:	49 89 d6             	mov    r14,rdx
    7ffff7fb3256:	49 89 f7             	mov    r15,rsi
    7ffff7fb3259:	48 89 7c 24 08       	mov    QWORD PTR [rsp+0x8],rdi
    7ffff7fb325e:	49 89 d5             	mov    r13,rdx
    7ffff7fb3261:	49 01 d5             	add    r13,rdx
    7ffff7fb3264:	74 0a                	je     0x7ffff7fb3270
    7ffff7fb3266:	4c 89 ef             	mov    rdi,r13
    7ffff7fb3269:	e8 95 e1 ff ff       	call   0x7ffff7fb1403
    7ffff7fb326e:	eb 03                	jmp    0x7ffff7fb3273
    7ffff7fb3270:	6a 01                	push   0x1
    7ffff7fb3272:	58                   	pop    rax
    7ffff7fb3273:	4c 8d 64 24 10       	lea    r12,[rsp+0x10]
    7ffff7fb3278:	4d 89 2c 24          	mov    QWORD PTR [r12],r13
    7ffff7fb327c:	49 89 44 24 08       	mov    QWORD PTR [r12+0x8],rax
    7ffff7fb3281:	49 83 64 24 10 00    	and    QWORD PTR [r12+0x10],0x0
    7ffff7fb3287:	45 31 ed             	xor    r13d,r13d
    7ffff7fb328a:	bd ff 00 00 00       	mov    ebp,0xff
    7ffff7fb328f:	4d 39 ee             	cmp    r14,r13
    7ffff7fb3292:	74 4a                	je     0x7ffff7fb32de
    7ffff7fb3294:	43 8a 04 2f          	mov    al,BYTE PTR [r15+r13*1]
    7ffff7fb3298:	89 c1                	mov    ecx,eax
    7ffff7fb329a:	c0 e9 04             	shr    cl,0x4
    7ffff7fb329d:	89 c3                	mov    ebx,eax
    7ffff7fb329f:	80 e3 0f             	and    bl,0xf
    7ffff7fb32a2:	8d 51 30             	lea    edx,[rcx+0x30]
    7ffff7fb32a5:	80 c1 57             	add    cl,0x57
    7ffff7fb32a8:	3c a0                	cmp    al,0xa0
    7ffff7fb32aa:	0f b6 c2             	movzx  eax,dl
    7ffff7fb32ad:	0f b6 f1             	movzx  esi,cl
    7ffff7fb32b0:	0f 42 f0             	cmovb  esi,eax
    7ffff7fb32b3:	21 ee                	and    esi,ebp
    7ffff7fb32b5:	4c 89 e7             	mov    rdi,r12
    7ffff7fb32b8:	e8 18 e1 ff ff       	call   0x7ffff7fb13d5
    7ffff7fb32bd:	8d 43 30             	lea    eax,[rbx+0x30]
    7ffff7fb32c0:	8d 4b 57             	lea    ecx,[rbx+0x57]
    7ffff7fb32c3:	80 fb 0a             	cmp    bl,0xa
    7ffff7fb32c6:	0f b6 c0             	movzx  eax,al
    7ffff7fb32c9:	0f b6 f1             	movzx  esi,cl
    7ffff7fb32cc:	0f 42 f0             	cmovb  esi,eax
    7ffff7fb32cf:	21 ee                	and    esi,ebp
    7ffff7fb32d1:	4c 89 e7             	mov    rdi,r12
    7ffff7fb32d4:	e8 fc e0 ff ff       	call   0x7ffff7fb13d5
    7ffff7fb32d9:	49 ff c5             	inc    r13
    7ffff7fb32dc:	eb b1                	jmp    0x7ffff7fb328f
    7ffff7fb32de:	48 8b 44 24 20       	mov    rax,QWORD PTR [rsp+0x20]
    7ffff7fb32e3:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
    7ffff7fb32e8:	48 89 41 10          	mov    QWORD PTR [rcx+0x10],rax
    7ffff7fb32ec:	c5 f8 10 44 24 10    	vmovups xmm0,XMMWORD PTR [rsp+0x10]
    7ffff7fb32f2:	c5 f8 11 01          	vmovups XMMWORD PTR [rcx],xmm0
    7ffff7fb32f6:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb32fa:	5b                   	pop    rbx
    7ffff7fb32fb:	41 5c                	pop    r12
    7ffff7fb32fd:	41 5d                	pop    r13
    7ffff7fb32ff:	41 5e                	pop    r14
    7ffff7fb3301:	41 5f                	pop    r15
    7ffff7fb3303:	5d                   	pop    rbp
    7ffff7fb3304:	c3                   	ret
    7ffff7fb3305:	48 8b 05 6c 57 00 00 	mov    rax,QWORD PTR [rip+0x576c]        # 0x7ffff7fb8a78
    7ffff7fb330c:	ff e0                	jmp    rax
    7ffff7fb330e:	48 8b 05 6b 57 00 00 	mov    rax,QWORD PTR [rip+0x576b]        # 0x7ffff7fb8a80
    7ffff7fb3315:	ff e0                	jmp    rax
    7ffff7fb3317:	48 8b 05 6a 57 00 00 	mov    rax,QWORD PTR [rip+0x576a]        # 0x7ffff7fb8a88
    7ffff7fb331e:	ff e0                	jmp    rax
    7ffff7fb3320:	55                   	push   rbp
    7ffff7fb3321:	48 89 e5             	mov    rbp,rsp
    7ffff7fb3324:	41 56                	push   r14
    7ffff7fb3326:	53                   	push   rbx
    7ffff7fb3327:	48 83 ec 30          	sub    rsp,0x30
    7ffff7fb332b:	48 89 fb             	mov    rbx,rdi
    7ffff7fb332e:	48 8b 07             	mov    rax,QWORD PTR [rdi]
    7ffff7fb3331:	48 8d 48 01          	lea    rcx,[rax+0x1]
    7ffff7fb3335:	48 8d 14 00          	lea    rdx,[rax+rax*1]
    7ffff7fb3339:	48 39 ca             	cmp    rdx,rcx
    7ffff7fb333c:	48 0f 47 ca          	cmova  rcx,rdx
    7ffff7fb3340:	48 83 f9 09          	cmp    rcx,0x9
    7ffff7fb3344:	41 be 08 00 00 00    	mov    r14d,0x8
    7ffff7fb334a:	4c 0f 43 f1          	cmovae r14,rcx
    7ffff7fb334e:	48 85 c0             	test   rax,rax
    7ffff7fb3351:	75 04                	jne    0x7ffff7fb3357
    7ffff7fb3353:	31 c0                	xor    eax,eax
    7ffff7fb3355:	eb 11                	jmp    0x7ffff7fb3368
    7ffff7fb3357:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
    7ffff7fb335b:	48 89 4d d8          	mov    QWORD PTR [rbp-0x28],rcx
    7ffff7fb335f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    7ffff7fb3363:	b8 01 00 00 00       	mov    eax,0x1
    7ffff7fb3368:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    7ffff7fb336c:	48 8d 7d c0          	lea    rdi,[rbp-0x40]
    7ffff7fb3370:	48 8d 55 d8          	lea    rdx,[rbp-0x28]
    7ffff7fb3374:	4c 89 f6             	mov    rsi,r14
    7ffff7fb3377:	e8 14 00 00 00       	call   0x7ffff7fb3390
    7ffff7fb337c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    7ffff7fb3380:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb3384:	4c 89 33             	mov    QWORD PTR [rbx],r14
    7ffff7fb3387:	48 83 c4 30          	add    rsp,0x30
    7ffff7fb338b:	5b                   	pop    rbx
    7ffff7fb338c:	41 5e                	pop    r14
    7ffff7fb338e:	5d                   	pop    rbp
    7ffff7fb338f:	c3                   	ret
    7ffff7fb3390:	55                   	push   rbp
    7ffff7fb3391:	48 89 e5             	mov    rbp,rsp
    7ffff7fb3394:	41 56                	push   r14
    7ffff7fb3396:	53                   	push   rbx
    7ffff7fb3397:	49 89 f6             	mov    r14,rsi
    7ffff7fb339a:	48 89 fb             	mov    rbx,rdi
    7ffff7fb339d:	48 83 7a 08 00       	cmp    QWORD PTR [rdx+0x8],0x0
    7ffff7fb33a2:	74 1b                	je     0x7ffff7fb33bf
    7ffff7fb33a4:	48 8b 72 10          	mov    rsi,QWORD PTR [rdx+0x10]
    7ffff7fb33a8:	48 85 f6             	test   rsi,rsi
    7ffff7fb33ab:	74 12                	je     0x7ffff7fb33bf
    7ffff7fb33ad:	48 8b 3a             	mov    rdi,QWORD PTR [rdx]
    7ffff7fb33b0:	ba 01 00 00 00       	mov    edx,0x1
    7ffff7fb33b5:	4c 89 f1             	mov    rcx,r14
    7ffff7fb33b8:	e8 5a ff ff ff       	call   0x7ffff7fb3317
    7ffff7fb33bd:	eb 14                	jmp    0x7ffff7fb33d3
    7ffff7fb33bf:	0f b6 05 3a 5f 00 00 	movzx  eax,BYTE PTR [rip+0x5f3a]        # 0x7ffff7fb9300
    7ffff7fb33c6:	be 01 00 00 00       	mov    esi,0x1
    7ffff7fb33cb:	4c 89 f7             	mov    rdi,r14
    7ffff7fb33ce:	e8 32 ff ff ff       	call   0x7ffff7fb3305
    7ffff7fb33d3:	31 c9                	xor    ecx,ecx
    7ffff7fb33d5:	48 85 c0             	test   rax,rax
    7ffff7fb33d8:	ba 01 00 00 00       	mov    edx,0x1
    7ffff7fb33dd:	48 0f 45 d0          	cmovne rdx,rax
    7ffff7fb33e1:	0f 94 c1             	sete   cl
    7ffff7fb33e4:	48 89 53 08          	mov    QWORD PTR [rbx+0x8],rdx
    7ffff7fb33e8:	4c 89 73 10          	mov    QWORD PTR [rbx+0x10],r14
    7ffff7fb33ec:	48 89 0b             	mov    QWORD PTR [rbx],rcx
    7ffff7fb33ef:	5b                   	pop    rbx
    7ffff7fb33f0:	41 5e                	pop    r14
    7ffff7fb33f2:	5d                   	pop    rbp
    7ffff7fb33f3:	c3                   	ret
    7ffff7fb33f4:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb33f8:	48 89 f2             	mov    rdx,rsi
    7ffff7fb33fb:	48 89 f9             	mov    rcx,rdi
    7ffff7fb33fe:	48 8b 05 f3 5e 00 00 	mov    rax,QWORD PTR [rip+0x5ef3]        # 0x7ffff7fb92f8
    7ffff7fb3405:	ff 50 28             	call   QWORD PTR [rax+0x28]
    7ffff7fb3408:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb340c:	c3                   	ret
    7ffff7fb340d:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb3411:	49 89 d0             	mov    r8,rdx
    7ffff7fb3414:	48 89 f2             	mov    rdx,rsi
    7ffff7fb3417:	48 89 f9             	mov    rcx,rdi
    7ffff7fb341a:	48 8b 05 d7 5e 00 00 	mov    rax,QWORD PTR [rip+0x5ed7]        # 0x7ffff7fb92f8
    7ffff7fb3421:	ff 50 38             	call   QWORD PTR [rax+0x38]
    7ffff7fb3424:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb3428:	c3                   	ret
    7ffff7fb3429:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb342d:	49 89 c9             	mov    r9,rcx
    7ffff7fb3430:	49 89 d0             	mov    r8,rdx
    7ffff7fb3433:	48 89 f2             	mov    rdx,rsi
    7ffff7fb3436:	48 89 f9             	mov    rcx,rdi
    7ffff7fb3439:	48 8b 05 b8 5e 00 00 	mov    rax,QWORD PTR [rip+0x5eb8]        # 0x7ffff7fb92f8
    7ffff7fb3440:	ff 50 40             	call   QWORD PTR [rax+0x40]
    7ffff7fb3443:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb3447:	c3                   	ret
    7ffff7fb3448:	48 83 c6 08          	add    rsi,0x8
    7ffff7fb344c:	31 c0                	xor    eax,eax
    7ffff7fb344e:	4c 8d 05 63 be ff ff 	lea    r8,[rip+0xffffffffffffbe63]        # 0x7ffff7faf2b8
    7ffff7fb3455:	4c 8b 4e f8          	mov    r9,QWORD PTR [rsi-0x8]
    7ffff7fb3459:	49 83 f9 09          	cmp    r9,0x9
    7ffff7fb345d:	77 1a                	ja     0x7ffff7fb3479
    7ffff7fb345f:	4f 63 0c 88          	movsxd r9,DWORD PTR [r8+r9*4]
    7ffff7fb3463:	4d 01 c1             	add    r9,r8
    7ffff7fb3466:	41 ff e1             	jmp    r9
    7ffff7fb3469:	48 8b 06             	mov    rax,QWORD PTR [rsi]
    7ffff7fb346c:	48 01 f8             	add    rax,rdi
    7ffff7fb346f:	eb 08                	jmp    0x7ffff7fb3479
    7ffff7fb3471:	48 8b 16             	mov    rdx,QWORD PTR [rsi]
    7ffff7fb3474:	eb 03                	jmp    0x7ffff7fb3479
    7ffff7fb3476:	48 8b 0e             	mov    rcx,QWORD PTR [rsi]
    7ffff7fb3479:	48 83 c6 10          	add    rsi,0x10
    7ffff7fb347d:	eb d6                	jmp    0x7ffff7fb3455
    7ffff7fb347f:	48 85 c0             	test   rax,rax
    7ffff7fb3482:	74 21                	je     0x7ffff7fb34a5
    7ffff7fb3484:	48 01 c2             	add    rdx,rax
    7ffff7fb3487:	48 39 d0             	cmp    rax,rdx
    7ffff7fb348a:	73 19                	jae    0x7ffff7fb34a5
    7ffff7fb348c:	83 78 08 08          	cmp    DWORD PTR [rax+0x8],0x8
    7ffff7fb3490:	75 0e                	jne    0x7ffff7fb34a0
    7ffff7fb3492:	48 8b 30             	mov    rsi,QWORD PTR [rax]
    7ffff7fb3495:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
    7ffff7fb3499:	49 01 f8             	add    r8,rdi
    7ffff7fb349c:	4c 89 04 3e          	mov    QWORD PTR [rsi+rdi*1],r8
    7ffff7fb34a0:	48 01 c8             	add    rax,rcx
    7ffff7fb34a3:	eb e2                	jmp    0x7ffff7fb3487
    7ffff7fb34a5:	c3                   	ret
    7ffff7fb34a6:	48 83 ec 38          	sub    rsp,0x38
    7ffff7fb34aa:	48 89 3d 47 5e 00 00 	mov    QWORD PTR [rip+0x5e47],rdi        # 0x7ffff7fb92f8
    7ffff7fb34b1:	48 8b 07             	mov    rax,QWORD PTR [rdi]
    7ffff7fb34b4:	48 83 f8 02          	cmp    rax,0x2
    7ffff7fb34b8:	0f 84 01 01 00 00    	je     0x7ffff7fb35bf
    7ffff7fb34be:	48 83 f8 01          	cmp    rax,0x1
    7ffff7fb34c2:	0f 85 94 01 00 00    	jne    0x7ffff7fb365c
    7ffff7fb34c8:	48 8b 77 10          	mov    rsi,QWORD PTR [rdi+0x10]
    7ffff7fb34cc:	48 8b 7f 18          	mov    rdi,QWORD PTR [rdi+0x18]
    7ffff7fb34d0:	48 8d 15 cd be ff ff 	lea    rdx,[rip+0xffffffffffffbecd]        # 0x7ffff7faf3a4
    7ffff7fb34d7:	48 89 f1             	mov    rcx,rsi
    7ffff7fb34da:	ff d7                	call   rdi
    7ffff7fb34dc:	48 89 05 45 5a 00 00 	mov    QWORD PTR [rip+0x5a45],rax        # 0x7ffff7fb8f28
    7ffff7fb34e3:	48 8d 15 c7 be ff ff 	lea    rdx,[rip+0xffffffffffffbec7]        # 0x7ffff7faf3b1
    7ffff7fb34ea:	48 89 f1             	mov    rcx,rsi
    7ffff7fb34ed:	ff d7                	call   rdi
    7ffff7fb34ef:	48 89 05 3a 5a 00 00 	mov    QWORD PTR [rip+0x5a3a],rax        # 0x7ffff7fb8f30
    7ffff7fb34f6:	48 8d 15 c0 be ff ff 	lea    rdx,[rip+0xffffffffffffbec0]        # 0x7ffff7faf3bd
    7ffff7fb34fd:	48 89 f1             	mov    rcx,rsi
    7ffff7fb3500:	ff d7                	call   rdi
    7ffff7fb3502:	48 89 05 2f 5a 00 00 	mov    QWORD PTR [rip+0x5a2f],rax        # 0x7ffff7fb8f38
    7ffff7fb3509:	48 8d 15 ba be ff ff 	lea    rdx,[rip+0xffffffffffffbeba]        # 0x7ffff7faf3ca
    7ffff7fb3510:	48 89 f1             	mov    rcx,rsi
    7ffff7fb3513:	ff d7                	call   rdi
    7ffff7fb3515:	48 89 05 24 5a 00 00 	mov    QWORD PTR [rip+0x5a24],rax        # 0x7ffff7fb8f40
    7ffff7fb351c:	48 8d 15 b0 be ff ff 	lea    rdx,[rip+0xffffffffffffbeb0]        # 0x7ffff7faf3d3
    7ffff7fb3523:	48 89 f1             	mov    rcx,rsi
    7ffff7fb3526:	ff d7                	call   rdi
    7ffff7fb3528:	48 89 05 19 5a 00 00 	mov    QWORD PTR [rip+0x5a19],rax        # 0x7ffff7fb8f48
    7ffff7fb352f:	48 8d 15 a7 be ff ff 	lea    rdx,[rip+0xffffffffffffbea7]        # 0x7ffff7faf3dd
    7ffff7fb3536:	48 89 f1             	mov    rcx,rsi
    7ffff7fb3539:	ff d7                	call   rdi
    7ffff7fb353b:	48 89 05 0e 5a 00 00 	mov    QWORD PTR [rip+0x5a0e],rax        # 0x7ffff7fb8f50
    7ffff7fb3542:	48 8d 15 a8 be ff ff 	lea    rdx,[rip+0xffffffffffffbea8]        # 0x7ffff7faf3f1
    7ffff7fb3549:	48 89 f1             	mov    rcx,rsi
    7ffff7fb354c:	ff d7                	call   rdi
    7ffff7fb354e:	48 89 05 03 5a 00 00 	mov    QWORD PTR [rip+0x5a03],rax        # 0x7ffff7fb8f58
    7ffff7fb3555:	48 8d 15 a2 be ff ff 	lea    rdx,[rip+0xffffffffffffbea2]        # 0x7ffff7faf3fe
    7ffff7fb355c:	48 89 f1             	mov    rcx,rsi
    7ffff7fb355f:	ff d7                	call   rdi
    7ffff7fb3561:	b9 e9 fd 00 00       	mov    ecx,0xfde9
    7ffff7fb3566:	ff d0                	call   rax
    7ffff7fb3568:	48 8d 15 9c be ff ff 	lea    rdx,[rip+0xffffffffffffbe9c]        # 0x7ffff7faf40b
    7ffff7fb356f:	48 89 f1             	mov    rcx,rsi
    7ffff7fb3572:	ff d7                	call   rdi
    7ffff7fb3574:	b9 e9 fd 00 00       	mov    ecx,0xfde9
    7ffff7fb3579:	ff d0                	call   rax
    7ffff7fb357b:	48 8d 05 0d 16 00 00 	lea    rax,[rip+0x160d]        # 0x7ffff7fb4b8f
    7ffff7fb3582:	48 89 05 ef 54 00 00 	mov    QWORD PTR [rip+0x54ef],rax        # 0x7ffff7fb8a78
    7ffff7fb3589:	48 8d 05 0d 16 00 00 	lea    rax,[rip+0x160d]        # 0x7ffff7fb4b9d
    7ffff7fb3590:	48 89 05 e9 54 00 00 	mov    QWORD PTR [rip+0x54e9],rax        # 0x7ffff7fb8a80
    7ffff7fb3597:	48 8d 05 04 16 00 00 	lea    rax,[rip+0x1604]        # 0x7ffff7fb4ba2
    7ffff7fb359e:	48 89 05 e3 54 00 00 	mov    QWORD PTR [rip+0x54e3],rax        # 0x7ffff7fb8a88
    7ffff7fb35a5:	48 8d 05 44 19 00 00 	lea    rax,[rip+0x1944]        # 0x7ffff7fb4ef0
    7ffff7fb35ac:	48 8d 0d 9b 18 00 00 	lea    rcx,[rip+0x189b]        # 0x7ffff7fb4e4e
    7ffff7fb35b3:	48 8b 3d 3e 5d 00 00 	mov    rdi,QWORD PTR [rip+0x5d3e]        # 0x7ffff7fb92f8
    7ffff7fb35ba:	e9 8e 00 00 00       	jmp    0x7ffff7fb364d
    7ffff7fb35bf:	f6 47 08 02          	test   BYTE PTR [rdi+0x8],0x2
    7ffff7fb35c3:	74 50                	je     0x7ffff7fb3615
    7ffff7fb35c5:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb35c9:	48 8d 74 24 20       	lea    rsi,[rsp+0x20]
    7ffff7fb35ce:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb35d2:	6a 61                	push   0x61
    7ffff7fb35d4:	58                   	pop    rax
    7ffff7fb35d5:	6a 03                	push   0x3
    7ffff7fb35d7:	5f                   	pop    rdi
    7ffff7fb35d8:	31 d2                	xor    edx,edx
    7ffff7fb35da:	45 31 d2             	xor    r10d,r10d
    7ffff7fb35dd:	45 31 c0             	xor    r8d,r8d
    7ffff7fb35e0:	45 31 c9             	xor    r9d,r9d
    7ffff7fb35e3:	0f 05                	syscall
    7ffff7fb35e5:	48 85 c0             	test   rax,rax
    7ffff7fb35e8:	75 24                	jne    0x7ffff7fb360e
    7ffff7fb35ea:	48 81 7c 24 20 00 00 	cmp    QWORD PTR [rsp+0x20],0x10000000
    7ffff7fb35f1:	00 10 
    7ffff7fb35f3:	73 19                	jae    0x7ffff7fb360e
    7ffff7fb35f5:	48 c7 06 00 00 00 10 	mov    QWORD PTR [rsi],0x10000000
    7ffff7fb35fc:	b8 a0 00 00 00       	mov    eax,0xa0
    7ffff7fb3601:	31 d2                	xor    edx,edx
    7ffff7fb3603:	45 31 d2             	xor    r10d,r10d
    7ffff7fb3606:	45 31 c0             	xor    r8d,r8d
    7ffff7fb3609:	45 31 c9             	xor    r9d,r9d
    7ffff7fb360c:	0f 05                	syscall
    7ffff7fb360e:	48 8b 3d e3 5c 00 00 	mov    rdi,QWORD PTR [rip+0x5ce3]        # 0x7ffff7fb92f8
    7ffff7fb3615:	48 8d 05 6f 00 00 00 	lea    rax,[rip+0x6f]        # 0x7ffff7fb368b
    7ffff7fb361c:	48 89 05 55 54 00 00 	mov    QWORD PTR [rip+0x5455],rax        # 0x7ffff7fb8a78
    7ffff7fb3623:	48 8d 05 6f 00 00 00 	lea    rax,[rip+0x6f]        # 0x7ffff7fb3699
    7ffff7fb362a:	48 89 05 4f 54 00 00 	mov    QWORD PTR [rip+0x544f],rax        # 0x7ffff7fb8a80
    7ffff7fb3631:	48 8d 05 66 00 00 00 	lea    rax,[rip+0x66]        # 0x7ffff7fb369e
    7ffff7fb3638:	48 89 05 49 54 00 00 	mov    QWORD PTR [rip+0x5449],rax        # 0x7ffff7fb8a88
    7ffff7fb363f:	48 8d 05 b9 03 00 00 	lea    rax,[rip+0x3b9]        # 0x7ffff7fb39ff
    7ffff7fb3646:	48 8d 0d 9b 03 00 00 	lea    rcx,[rip+0x39b]        # 0x7ffff7fb39e8
    7ffff7fb364d:	48 89 4f 48          	mov    QWORD PTR [rdi+0x48],rcx
    7ffff7fb3651:	48 8b 0d a0 5c 00 00 	mov    rcx,QWORD PTR [rip+0x5ca0]        # 0x7ffff7fb92f8
    7ffff7fb3658:	48 89 41 50          	mov    QWORD PTR [rcx+0x50],rax
    7ffff7fb365c:	e8 25 00 00 00       	call   0x7ffff7fb3686
    7ffff7fb3661:	48 8b 05 90 5c 00 00 	mov    rax,QWORD PTR [rip+0x5c90]        # 0x7ffff7fb92f8
    7ffff7fb3668:	f6 40 08 04          	test   BYTE PTR [rax+0x8],0x4
    7ffff7fb366c:	75 06                	jne    0x7ffff7fb3674
    7ffff7fb366e:	48 83 38 02          	cmp    QWORD PTR [rax],0x2
    7ffff7fb3672:	74 07                	je     0x7ffff7fb367b
    7ffff7fb3674:	31 c0                	xor    eax,eax
    7ffff7fb3676:	48 83 c4 38          	add    rsp,0x38
    7ffff7fb367a:	c3                   	ret
    7ffff7fb367b:	b8 e7 00 00 00       	mov    eax,0xe7
    7ffff7fb3680:	31 ff                	xor    edi,edi
    7ffff7fb3682:	0f 05                	syscall
    7ffff7fb3684:	0f 0b                	ud2
    7ffff7fb3686:	e9 d1 f0 ff ff       	jmp    0x7ffff7fb275c
    7ffff7fb368b:	48 89 f8             	mov    rax,rdi
    7ffff7fb368e:	48 89 f7             	mov    rdi,rsi
    7ffff7fb3691:	48 89 c6             	mov    rsi,rax
    7ffff7fb3694:	e9 7e 03 00 00       	jmp    0x7ffff7fb3a17
    7ffff7fb3699:	e9 d8 0d 00 00       	jmp    0x7ffff7fb4476
    7ffff7fb369e:	55                   	push   rbp
    7ffff7fb369f:	41 57                	push   r15
    7ffff7fb36a1:	41 56                	push   r14
    7ffff7fb36a3:	41 55                	push   r13
    7ffff7fb36a5:	41 54                	push   r12
    7ffff7fb36a7:	53                   	push   rbx
    7ffff7fb36a8:	50                   	push   rax
    7ffff7fb36a9:	49 89 cc             	mov    r12,rcx
    7ffff7fb36ac:	49 89 fe             	mov    r14,rdi
    7ffff7fb36af:	48 83 fa 11          	cmp    rdx,0x11
    7ffff7fb36b3:	0f 83 b5 00 00 00    	jae    0x7ffff7fb376e
    7ffff7fb36b9:	49 81 fc 98 ff fe ff 	cmp    r12,0xfffffffffffeff98
    7ffff7fb36c0:	0f 87 81 02 00 00    	ja     0x7ffff7fb3947
    7ffff7fb36c6:	49 8d 44 24 17       	lea    rax,[r12+0x17]
    7ffff7fb36cb:	48 83 e0 f0          	and    rax,0xfffffffffffffff0
    7ffff7fb36cf:	49 83 fc 17          	cmp    r12,0x17
    7ffff7fb36d3:	6a 20                	push   0x20
    7ffff7fb36d5:	41 5f                	pop    r15
    7ffff7fb36d7:	4c 0f 43 f8          	cmovae r15,rax
    7ffff7fb36db:	49 8d 5e f0          	lea    rbx,[r14-0x10]
    7ffff7fb36df:	49 8b 4e f8          	mov    rcx,QWORD PTR [r14-0x8]
    7ffff7fb36e3:	48 89 cd             	mov    rbp,rcx
    7ffff7fb36e6:	48 83 e5 f8          	and    rbp,0xfffffffffffffff8
    7ffff7fb36ea:	f6 c1 03             	test   cl,0x3
    7ffff7fb36ed:	0f 84 b8 00 00 00    	je     0x7ffff7fb37ab
    7ffff7fb36f3:	49 8d 3c 2e          	lea    rdi,[r14+rbp*1]
    7ffff7fb36f7:	48 83 c7 f0          	add    rdi,0xfffffffffffffff0
    7ffff7fb36fb:	48 89 ee             	mov    rsi,rbp
    7ffff7fb36fe:	4c 29 fe             	sub    rsi,r15
    7ffff7fb3701:	0f 83 7d 01 00 00    	jae    0x7ffff7fb3884
    7ffff7fb3707:	48 3b 3d e2 57 00 00 	cmp    rdi,QWORD PTR [rip+0x57e2]        # 0x7ffff7fb8ef0
    7ffff7fb370e:	0f 84 a9 01 00 00    	je     0x7ffff7fb38bd
    7ffff7fb3714:	48 3b 3d cd 57 00 00 	cmp    rdi,QWORD PTR [rip+0x57cd]        # 0x7ffff7fb8ee8
    7ffff7fb371b:	0f 84 d9 01 00 00    	je     0x7ffff7fb38fa
    7ffff7fb3721:	48 8b 77 08          	mov    rsi,QWORD PTR [rdi+0x8]
    7ffff7fb3725:	40 f6 c6 02          	test   sil,0x2
    7ffff7fb3729:	0f 85 da 01 00 00    	jne    0x7ffff7fb3909
    7ffff7fb372f:	48 83 e6 f8          	and    rsi,0xfffffffffffffff8
    7ffff7fb3733:	48 01 f5             	add    rbp,rsi
    7ffff7fb3736:	49 89 ed             	mov    r13,rbp
    7ffff7fb3739:	4d 29 fd             	sub    r13,r15
    7ffff7fb373c:	0f 82 c7 01 00 00    	jb     0x7ffff7fb3909
    7ffff7fb3742:	e8 03 04 00 00       	call   0x7ffff7fb3b4a
    7ffff7fb3747:	49 83 fd 20          	cmp    r13,0x20
    7ffff7fb374b:	0f 83 67 02 00 00    	jae    0x7ffff7fb39b8
    7ffff7fb3751:	49 8b 46 f8          	mov    rax,QWORD PTR [r14-0x8]
    7ffff7fb3755:	83 e0 01             	and    eax,0x1
    7ffff7fb3758:	48 01 e8             	add    rax,rbp
    7ffff7fb375b:	48 83 c0 02          	add    rax,0x2
    7ffff7fb375f:	49 89 46 f8          	mov    QWORD PTR [r14-0x8],rax
    7ffff7fb3763:	41 80 4c 2e f8 01    	or     BYTE PTR [r14+rbp*1-0x8],0x1
    7ffff7fb3769:	e9 34 02 00 00       	jmp    0x7ffff7fb39a2
    7ffff7fb376e:	49 89 f7             	mov    r15,rsi
    7ffff7fb3771:	48 89 d7             	mov    rdi,rdx
    7ffff7fb3774:	4c 89 e6             	mov    rsi,r12
    7ffff7fb3777:	e8 9b 02 00 00       	call   0x7ffff7fb3a17
    7ffff7fb377c:	48 85 c0             	test   rax,rax
    7ffff7fb377f:	0f 84 c2 01 00 00    	je     0x7ffff7fb3947
    7ffff7fb3785:	48 89 c3             	mov    rbx,rax
    7ffff7fb3788:	4d 39 e7             	cmp    r15,r12
    7ffff7fb378b:	4d 0f 42 e7          	cmovb  r12,r15
    7ffff7fb378f:	48 89 c7             	mov    rdi,rax
    7ffff7fb3792:	4c 89 f6             	mov    rsi,r14
    7ffff7fb3795:	4c 89 e2             	mov    rdx,r12
    7ffff7fb3798:	ff 15 ca 53 00 00    	call   QWORD PTR [rip+0x53ca]        # 0x7ffff7fb8b68
    7ffff7fb379e:	4c 89 f7             	mov    rdi,r14
    7ffff7fb37a1:	e8 d0 0c 00 00       	call   0x7ffff7fb4476
    7ffff7fb37a6:	e9 fb 01 00 00       	jmp    0x7ffff7fb39a6
    7ffff7fb37ab:	49 81 ff 00 01 00 00 	cmp    r15,0x100
    7ffff7fb37b2:	0f 82 51 01 00 00    	jb     0x7ffff7fb3909
    7ffff7fb37b8:	4c 89 f8             	mov    rax,r15
    7ffff7fb37bb:	48 83 c8 08          	or     rax,0x8
    7ffff7fb37bf:	48 39 c5             	cmp    rbp,rax
    7ffff7fb37c2:	0f 93 c0             	setae  al
    7ffff7fb37c5:	48 89 e9             	mov    rcx,rbp
    7ffff7fb37c8:	4c 29 f9             	sub    rcx,r15
    7ffff7fb37cb:	48 81 f9 01 00 02 00 	cmp    rcx,0x20001
    7ffff7fb37d2:	0f 92 c1             	setb   cl
    7ffff7fb37d5:	84 c8                	test   al,cl
    7ffff7fb37d7:	0f 85 c5 01 00 00    	jne    0x7ffff7fb39a2
    7ffff7fb37dd:	4c 8b 2b             	mov    r13,QWORD PTR [rbx]
    7ffff7fb37e0:	4a 8d 34 2d 20 00 00 	lea    rsi,[r13*1+0x20]
    7ffff7fb37e7:	00 
    7ffff7fb37e8:	48 01 ee             	add    rsi,rbp
    7ffff7fb37eb:	49 81 c7 3e 10 00 00 	add    r15,0x103e
    7ffff7fb37f2:	49 81 e7 00 f0 ff ff 	and    r15,0xfffffffffffff000
    7ffff7fb37f9:	4c 29 eb             	sub    rbx,r13
    7ffff7fb37fc:	6a 19                	push   0x19
    7ffff7fb37fe:	58                   	pop    rax
    7ffff7fb37ff:	6a 01                	push   0x1
    7ffff7fb3801:	41 5a                	pop    r10
    7ffff7fb3803:	48 89 df             	mov    rdi,rbx
    7ffff7fb3806:	4c 89 fa             	mov    rdx,r15
    7ffff7fb3809:	45 31 c0             	xor    r8d,r8d
    7ffff7fb380c:	45 31 c9             	xor    r9d,r9d
    7ffff7fb380f:	0f 05                	syscall
    7ffff7fb3811:	48 8d 48 01          	lea    rcx,[rax+0x1]
    7ffff7fb3815:	48 f7 c1 fe ff ff ff 	test   rcx,0xfffffffffffffffe
    7ffff7fb381c:	0f 84 e7 00 00 00    	je     0x7ffff7fb3909
    7ffff7fb3822:	4a 8d 1c 28          	lea    rbx,[rax+r13*1]
    7ffff7fb3826:	4c 89 f9             	mov    rcx,r15
    7ffff7fb3829:	4c 29 e9             	sub    rcx,r13
    7ffff7fb382c:	48 8d 51 e0          	lea    rdx,[rcx-0x20]
    7ffff7fb3830:	4a 89 54 28 08       	mov    QWORD PTR [rax+r13*1+0x8],rdx
    7ffff7fb3835:	48 c7 44 19 e8 0b 00 	mov    QWORD PTR [rcx+rbx*1-0x18],0xb
    7ffff7fb383c:	00 00 
    7ffff7fb383e:	4a 83 64 38 f0 00    	and    QWORD PTR [rax+r15*1-0x10],0x0
    7ffff7fb3844:	48 8b 0d c5 56 00 00 	mov    rcx,QWORD PTR [rip+0x56c5]        # 0x7ffff7fb8f10
    7ffff7fb384b:	48 39 c1             	cmp    rcx,rax
    7ffff7fb384e:	48 0f 42 c1          	cmovb  rax,rcx
    7ffff7fb3852:	48 89 05 b7 56 00 00 	mov    QWORD PTR [rip+0x56b7],rax        # 0x7ffff7fb8f10
    7ffff7fb3859:	49 29 f7             	sub    r15,rsi
    7ffff7fb385c:	4c 03 3d 95 56 00 00 	add    r15,QWORD PTR [rip+0x5695]        # 0x7ffff7fb8ef8
    7ffff7fb3863:	4c 89 3d 8e 56 00 00 	mov    QWORD PTR [rip+0x568e],r15        # 0x7ffff7fb8ef8
    7ffff7fb386a:	48 8b 05 8f 56 00 00 	mov    rax,QWORD PTR [rip+0x568f]        # 0x7ffff7fb8f00
    7ffff7fb3871:	4c 39 f8             	cmp    rax,r15
    7ffff7fb3874:	4c 0f 47 f8          	cmova  r15,rax
    7ffff7fb3878:	4c 89 3d 81 56 00 00 	mov    QWORD PTR [rip+0x5681],r15        # 0x7ffff7fb8f00
    7ffff7fb387f:	e9 1e 01 00 00       	jmp    0x7ffff7fb39a2
    7ffff7fb3884:	48 83 fe 20          	cmp    rsi,0x20
    7ffff7fb3888:	0f 82 14 01 00 00    	jb     0x7ffff7fb39a2
    7ffff7fb388e:	4a 8d 04 3b          	lea    rax,[rbx+r15*1]
    7ffff7fb3892:	83 e1 01             	and    ecx,0x1
    7ffff7fb3895:	4c 01 f9             	add    rcx,r15
    7ffff7fb3898:	48 83 c1 02          	add    rcx,0x2
    7ffff7fb389c:	49 89 4e f8          	mov    QWORD PTR [r14-0x8],rcx
    7ffff7fb38a0:	48 89 f1             	mov    rcx,rsi
    7ffff7fb38a3:	48 83 c9 03          	or     rcx,0x3
    7ffff7fb38a7:	4b 89 4c 3e f8       	mov    QWORD PTR [r14+r15*1-0x8],rcx
    7ffff7fb38ac:	80 4f 08 01          	or     BYTE PTR [rdi+0x8],0x1
    7ffff7fb38b0:	48 89 c7             	mov    rdi,rax
    7ffff7fb38b3:	e8 c7 02 00 00       	call   0x7ffff7fb3b7f
    7ffff7fb38b8:	e9 e5 00 00 00       	jmp    0x7ffff7fb39a2
    7ffff7fb38bd:	48 03 2d 1c 56 00 00 	add    rbp,QWORD PTR [rip+0x561c]        # 0x7ffff7fb8ee0
    7ffff7fb38c4:	4c 29 fd             	sub    rbp,r15
    7ffff7fb38c7:	76 40                	jbe    0x7ffff7fb3909
    7ffff7fb38c9:	4a 8d 04 3b          	lea    rax,[rbx+r15*1]
    7ffff7fb38cd:	83 e1 01             	and    ecx,0x1
    7ffff7fb38d0:	4c 01 f9             	add    rcx,r15
    7ffff7fb38d3:	48 83 c1 02          	add    rcx,0x2
    7ffff7fb38d7:	49 89 4e f8          	mov    QWORD PTR [r14-0x8],rcx
    7ffff7fb38db:	48 89 e9             	mov    rcx,rbp
    7ffff7fb38de:	48 83 c9 01          	or     rcx,0x1
    7ffff7fb38e2:	4b 89 4c 3e f8       	mov    QWORD PTR [r14+r15*1-0x8],rcx
    7ffff7fb38e7:	48 89 05 02 56 00 00 	mov    QWORD PTR [rip+0x5602],rax        # 0x7ffff7fb8ef0
    7ffff7fb38ee:	48 89 2d eb 55 00 00 	mov    QWORD PTR [rip+0x55eb],rbp        # 0x7ffff7fb8ee0
    7ffff7fb38f5:	e9 a8 00 00 00       	jmp    0x7ffff7fb39a2
    7ffff7fb38fa:	48 03 2d d7 55 00 00 	add    rbp,QWORD PTR [rip+0x55d7]        # 0x7ffff7fb8ed8
    7ffff7fb3901:	48 89 e8             	mov    rax,rbp
    7ffff7fb3904:	4c 29 f8             	sub    rax,r15
    7ffff7fb3907:	73 42                	jae    0x7ffff7fb394b
    7ffff7fb3909:	4c 89 e7             	mov    rdi,r12
    7ffff7fb390c:	e8 fe 03 00 00       	call   0x7ffff7fb3d0f
    7ffff7fb3911:	48 85 c0             	test   rax,rax
    7ffff7fb3914:	74 31                	je     0x7ffff7fb3947
    7ffff7fb3916:	48 89 c3             	mov    rbx,rax
    7ffff7fb3919:	49 8b 46 f8          	mov    rax,QWORD PTR [r14-0x8]
    7ffff7fb391d:	48 89 c1             	mov    rcx,rax
    7ffff7fb3920:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb3924:	31 d2                	xor    edx,edx
    7ffff7fb3926:	a8 03                	test   al,0x3
    7ffff7fb3928:	0f 95 c2             	setne  dl
    7ffff7fb392b:	c1 e2 03             	shl    edx,0x3
    7ffff7fb392e:	48 83 ca f0          	or     rdx,0xfffffffffffffff0
    7ffff7fb3932:	48 01 ca             	add    rdx,rcx
    7ffff7fb3935:	4c 39 e2             	cmp    rdx,r12
    7ffff7fb3938:	49 0f 43 d4          	cmovae rdx,r12
    7ffff7fb393c:	48 89 df             	mov    rdi,rbx
    7ffff7fb393f:	4c 89 f6             	mov    rsi,r14
    7ffff7fb3942:	e9 51 fe ff ff       	jmp    0x7ffff7fb3798
    7ffff7fb3947:	31 db                	xor    ebx,ebx
    7ffff7fb3949:	eb 5b                	jmp    0x7ffff7fb39a6
    7ffff7fb394b:	48 83 f8 1f          	cmp    rax,0x1f
    7ffff7fb394f:	77 1a                	ja     0x7ffff7fb396b
    7ffff7fb3951:	83 e1 01             	and    ecx,0x1
    7ffff7fb3954:	48 09 e9             	or     rcx,rbp
    7ffff7fb3957:	48 83 c9 02          	or     rcx,0x2
    7ffff7fb395b:	49 89 4e f8          	mov    QWORD PTR [r14-0x8],rcx
    7ffff7fb395f:	41 80 4c 2e f8 01    	or     BYTE PTR [r14+rbp*1-0x8],0x1
    7ffff7fb3965:	31 c0                	xor    eax,eax
    7ffff7fb3967:	31 d2                	xor    edx,edx
    7ffff7fb3969:	eb 29                	jmp    0x7ffff7fb3994
    7ffff7fb396b:	4a 8d 14 3b          	lea    rdx,[rbx+r15*1]
    7ffff7fb396f:	83 e1 01             	and    ecx,0x1
    7ffff7fb3972:	4c 01 f9             	add    rcx,r15
    7ffff7fb3975:	48 83 c1 02          	add    rcx,0x2
    7ffff7fb3979:	49 89 4e f8          	mov    QWORD PTR [r14-0x8],rcx
    7ffff7fb397d:	48 89 c1             	mov    rcx,rax
    7ffff7fb3980:	48 83 c9 01          	or     rcx,0x1
    7ffff7fb3984:	4b 89 4c 3e f8       	mov    QWORD PTR [r14+r15*1-0x8],rcx
    7ffff7fb3989:	49 89 44 2e f0       	mov    QWORD PTR [r14+rbp*1-0x10],rax
    7ffff7fb398e:	41 80 64 2e f8 fe    	and    BYTE PTR [r14+rbp*1-0x8],0xfe
    7ffff7fb3994:	48 89 05 3d 55 00 00 	mov    QWORD PTR [rip+0x553d],rax        # 0x7ffff7fb8ed8
    7ffff7fb399b:	48 89 15 46 55 00 00 	mov    QWORD PTR [rip+0x5546],rdx        # 0x7ffff7fb8ee8
    7ffff7fb39a2:	48 83 c3 10          	add    rbx,0x10
    7ffff7fb39a6:	48 89 d8             	mov    rax,rbx
    7ffff7fb39a9:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb39ad:	5b                   	pop    rbx
    7ffff7fb39ae:	41 5c                	pop    r12
    7ffff7fb39b0:	41 5d                	pop    r13
    7ffff7fb39b2:	41 5e                	pop    r14
    7ffff7fb39b4:	41 5f                	pop    r15
    7ffff7fb39b6:	5d                   	pop    rbp
    7ffff7fb39b7:	c3                   	ret
    7ffff7fb39b8:	4a 8d 3c 3b          	lea    rdi,[rbx+r15*1]
    7ffff7fb39bc:	49 8b 46 f8          	mov    rax,QWORD PTR [r14-0x8]
    7ffff7fb39c0:	83 e0 01             	and    eax,0x1
    7ffff7fb39c3:	4c 01 f8             	add    rax,r15
    7ffff7fb39c6:	48 83 c0 02          	add    rax,0x2
    7ffff7fb39ca:	49 89 46 f8          	mov    QWORD PTR [r14-0x8],rax
    7ffff7fb39ce:	4c 89 e8             	mov    rax,r13
    7ffff7fb39d1:	48 83 c8 03          	or     rax,0x3
    7ffff7fb39d5:	4b 89 44 3e f8       	mov    QWORD PTR [r14+r15*1-0x8],rax
    7ffff7fb39da:	41 80 4c 2e f8 01    	or     BYTE PTR [r14+rbp*1-0x8],0x1
    7ffff7fb39e0:	4c 89 ee             	mov    rsi,r13
    7ffff7fb39e3:	e9 cb fe ff ff       	jmp    0x7ffff7fb38b3
    7ffff7fb39e8:	56                   	push   rsi
    7ffff7fb39e9:	57                   	push   rdi
    7ffff7fb39ea:	50                   	push   rax
    7ffff7fb39eb:	31 c0                	xor    eax,eax
    7ffff7fb39ed:	48 89 cf             	mov    rdi,rcx
    7ffff7fb39f0:	48 89 d6             	mov    rsi,rdx
    7ffff7fb39f3:	4c 89 c2             	mov    rdx,r8
    7ffff7fb39f6:	0f 05                	syscall
    7ffff7fb39f8:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb39fc:	5f                   	pop    rdi
    7ffff7fb39fd:	5e                   	pop    rsi
    7ffff7fb39fe:	c3                   	ret
    7ffff7fb39ff:	56                   	push   rsi
    7ffff7fb3a00:	57                   	push   rdi
    7ffff7fb3a01:	50                   	push   rax
    7ffff7fb3a02:	6a 01                	push   0x1
    7ffff7fb3a04:	58                   	pop    rax
    7ffff7fb3a05:	48 89 cf             	mov    rdi,rcx
    7ffff7fb3a08:	48 89 d6             	mov    rsi,rdx
    7ffff7fb3a0b:	4c 89 c2             	mov    rdx,r8
    7ffff7fb3a0e:	0f 05                	syscall
    7ffff7fb3a10:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb3a14:	5f                   	pop    rdi
    7ffff7fb3a15:	5e                   	pop    rsi
    7ffff7fb3a16:	c3                   	ret
    7ffff7fb3a17:	41 56                	push   r14
    7ffff7fb3a19:	53                   	push   rbx
    7ffff7fb3a1a:	50                   	push   rax
    7ffff7fb3a1b:	48 89 fb             	mov    rbx,rdi
    7ffff7fb3a1e:	48 83 ff 21          	cmp    rdi,0x21
    7ffff7fb3a22:	6a 20                	push   0x20
    7ffff7fb3a24:	58                   	pop    rax
    7ffff7fb3a25:	48 0f 42 d8          	cmovb  rbx,rax
    7ffff7fb3a29:	48 c7 c1 99 ff fe ff 	mov    rcx,0xfffffffffffeff99
    7ffff7fb3a30:	48 29 d9             	sub    rcx,rbx
    7ffff7fb3a33:	48 39 f1             	cmp    rcx,rsi
    7ffff7fb3a36:	0f 86 a6 00 00 00    	jbe    0x7ffff7fb3ae2
    7ffff7fb3a3c:	4c 8d 76 17          	lea    r14,[rsi+0x17]
    7ffff7fb3a40:	49 83 e6 f0          	and    r14,0xfffffffffffffff0
    7ffff7fb3a44:	48 83 fe 17          	cmp    rsi,0x17
    7ffff7fb3a48:	4c 0f 42 f0          	cmovb  r14,rax
    7ffff7fb3a4c:	4a 8d 3c 33          	lea    rdi,[rbx+r14*1]
    7ffff7fb3a50:	48 83 c7 18          	add    rdi,0x18
    7ffff7fb3a54:	e8 b6 02 00 00       	call   0x7ffff7fb3d0f
    7ffff7fb3a59:	48 85 c0             	test   rax,rax
    7ffff7fb3a5c:	0f 84 80 00 00 00    	je     0x7ffff7fb3ae2
    7ffff7fb3a62:	48 8d 78 f0          	lea    rdi,[rax-0x10]
    7ffff7fb3a66:	48 8d 4b ff          	lea    rcx,[rbx-0x1]
    7ffff7fb3a6a:	48 85 c1             	test   rcx,rax
    7ffff7fb3a6d:	74 77                	je     0x7ffff7fb3ae6
    7ffff7fb3a6f:	48 01 c1             	add    rcx,rax
    7ffff7fb3a72:	48 89 da             	mov    rdx,rbx
    7ffff7fb3a75:	48 f7 da             	neg    rdx
    7ffff7fb3a78:	48 21 ca             	and    rdx,rcx
    7ffff7fb3a7b:	48 8d 4a f0          	lea    rcx,[rdx-0x10]
    7ffff7fb3a7f:	48 29 f9             	sub    rcx,rdi
    7ffff7fb3a82:	31 f6                	xor    esi,esi
    7ffff7fb3a84:	48 83 f9 21          	cmp    rcx,0x21
    7ffff7fb3a88:	48 0f 42 f3          	cmovb  rsi,rbx
    7ffff7fb3a8c:	48 8d 1c 32          	lea    rbx,[rdx+rsi*1]
    7ffff7fb3a90:	48 83 c3 f0          	add    rbx,0xfffffffffffffff0
    7ffff7fb3a94:	48 89 de             	mov    rsi,rbx
    7ffff7fb3a97:	48 29 fe             	sub    rsi,rdi
    7ffff7fb3a9a:	48 8b 50 f8          	mov    rdx,QWORD PTR [rax-0x8]
    7ffff7fb3a9e:	48 89 d1             	mov    rcx,rdx
    7ffff7fb3aa1:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb3aa5:	48 29 f1             	sub    rcx,rsi
    7ffff7fb3aa8:	f6 c2 03             	test   dl,0x3
    7ffff7fb3aab:	74 3e                	je     0x7ffff7fb3aeb
    7ffff7fb3aad:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
    7ffff7fb3ab1:	83 e2 01             	and    edx,0x1
    7ffff7fb3ab4:	48 09 ca             	or     rdx,rcx
    7ffff7fb3ab7:	48 83 ca 02          	or     rdx,0x2
    7ffff7fb3abb:	48 89 53 08          	mov    QWORD PTR [rbx+0x8],rdx
    7ffff7fb3abf:	80 4c 0b 08 01       	or     BYTE PTR [rbx+rcx*1+0x8],0x1
    7ffff7fb3ac4:	48 8b 48 f8          	mov    rcx,QWORD PTR [rax-0x8]
    7ffff7fb3ac8:	83 e1 01             	and    ecx,0x1
    7ffff7fb3acb:	48 09 f1             	or     rcx,rsi
    7ffff7fb3ace:	48 83 c9 02          	or     rcx,0x2
    7ffff7fb3ad2:	48 89 48 f8          	mov    QWORD PTR [rax-0x8],rcx
    7ffff7fb3ad6:	80 4c 30 f8 01       	or     BYTE PTR [rax+rsi*1-0x8],0x1
    7ffff7fb3adb:	e8 9f 00 00 00       	call   0x7ffff7fb3b7f
    7ffff7fb3ae0:	eb 13                	jmp    0x7ffff7fb3af5
    7ffff7fb3ae2:	31 db                	xor    ebx,ebx
    7ffff7fb3ae4:	eb 59                	jmp    0x7ffff7fb3b3f
    7ffff7fb3ae6:	48 89 fb             	mov    rbx,rdi
    7ffff7fb3ae9:	eb 0a                	jmp    0x7ffff7fb3af5
    7ffff7fb3aeb:	48 03 37             	add    rsi,QWORD PTR [rdi]
    7ffff7fb3aee:	48 89 33             	mov    QWORD PTR [rbx],rsi
    7ffff7fb3af1:	48 89 4b 08          	mov    QWORD PTR [rbx+0x8],rcx
    7ffff7fb3af5:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
    7ffff7fb3af9:	a8 03                	test   al,0x3
    7ffff7fb3afb:	74 3e                	je     0x7ffff7fb3b3b
    7ffff7fb3afd:	48 89 c1             	mov    rcx,rax
    7ffff7fb3b00:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb3b04:	49 8d 56 20          	lea    rdx,[r14+0x20]
    7ffff7fb3b08:	48 39 d1             	cmp    rcx,rdx
    7ffff7fb3b0b:	76 2e                	jbe    0x7ffff7fb3b3b
    7ffff7fb3b0d:	48 89 ce             	mov    rsi,rcx
    7ffff7fb3b10:	4c 29 f6             	sub    rsi,r14
    7ffff7fb3b13:	4a 8d 3c 33          	lea    rdi,[rbx+r14*1]
    7ffff7fb3b17:	83 e0 01             	and    eax,0x1
    7ffff7fb3b1a:	4c 01 f0             	add    rax,r14
    7ffff7fb3b1d:	48 83 c0 02          	add    rax,0x2
    7ffff7fb3b21:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb3b25:	48 89 f0             	mov    rax,rsi
    7ffff7fb3b28:	48 83 c8 03          	or     rax,0x3
    7ffff7fb3b2c:	4a 89 44 33 08       	mov    QWORD PTR [rbx+r14*1+0x8],rax
    7ffff7fb3b31:	80 4c 0b 08 01       	or     BYTE PTR [rbx+rcx*1+0x8],0x1
    7ffff7fb3b36:	e8 44 00 00 00       	call   0x7ffff7fb3b7f
    7ffff7fb3b3b:	48 83 c3 10          	add    rbx,0x10
    7ffff7fb3b3f:	48 89 d8             	mov    rax,rbx
    7ffff7fb3b42:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb3b46:	5b                   	pop    rbx
    7ffff7fb3b47:	41 5e                	pop    r14
    7ffff7fb3b49:	c3                   	ret
    7ffff7fb3b4a:	48 81 fe 00 01 00 00 	cmp    rsi,0x100
    7ffff7fb3b51:	0f 83 04 0f 00 00    	jae    0x7ffff7fb4a5b
    7ffff7fb3b57:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
    7ffff7fb3b5b:	48 8b 4f 18          	mov    rcx,QWORD PTR [rdi+0x18]
    7ffff7fb3b5f:	48 39 c1             	cmp    rcx,rax
    7ffff7fb3b62:	74 09                	je     0x7ffff7fb3b6d
    7ffff7fb3b64:	48 89 48 18          	mov    QWORD PTR [rax+0x18],rcx
    7ffff7fb3b68:	48 89 41 10          	mov    QWORD PTR [rcx+0x10],rax
    7ffff7fb3b6c:	c3                   	ret
    7ffff7fb3b6d:	40 c0 ee 03          	shr    sil,0x3
    7ffff7fb3b71:	6a fe                	push   0xfffffffffffffffe
    7ffff7fb3b73:	58                   	pop    rax
    7ffff7fb3b74:	89 f1                	mov    ecx,esi
    7ffff7fb3b76:	d3 c0                	rol    eax,cl
    7ffff7fb3b78:	21 05 a2 53 00 00    	and    DWORD PTR [rip+0x53a2],eax        # 0x7ffff7fb8f20
    7ffff7fb3b7e:	c3                   	ret
    7ffff7fb3b7f:	41 57                	push   r15
    7ffff7fb3b81:	41 56                	push   r14
    7ffff7fb3b83:	41 55                	push   r13
    7ffff7fb3b85:	41 54                	push   r12
    7ffff7fb3b87:	53                   	push   rbx
    7ffff7fb3b88:	49 89 f5             	mov    r13,rsi
    7ffff7fb3b8b:	49 89 fc             	mov    r12,rdi
    7ffff7fb3b8e:	4c 8d 3c 37          	lea    r15,[rdi+rsi*1]
    7ffff7fb3b92:	48 8b 4f 08          	mov    rcx,QWORD PTR [rdi+0x8]
    7ffff7fb3b96:	48 89 f3             	mov    rbx,rsi
    7ffff7fb3b99:	49 89 fe             	mov    r14,rdi
    7ffff7fb3b9c:	f6 c1 01             	test   cl,0x1
    7ffff7fb3b9f:	0f 85 85 00 00 00    	jne    0x7ffff7fb3c2a
    7ffff7fb3ba5:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
    7ffff7fb3ba9:	f6 c1 02             	test   cl,0x2
    7ffff7fb3bac:	75 33                	jne    0x7ffff7fb3be1
    7ffff7fb3bae:	4a 8d 34 28          	lea    rsi,[rax+r13*1]
    7ffff7fb3bb2:	48 83 c6 20          	add    rsi,0x20
    7ffff7fb3bb6:	49 29 c4             	sub    r12,rax
    7ffff7fb3bb9:	6a 0b                	push   0xb
    7ffff7fb3bbb:	58                   	pop    rax
    7ffff7fb3bbc:	4c 89 e7             	mov    rdi,r12
    7ffff7fb3bbf:	31 d2                	xor    edx,edx
    7ffff7fb3bc1:	45 31 d2             	xor    r10d,r10d
    7ffff7fb3bc4:	45 31 c0             	xor    r8d,r8d
    7ffff7fb3bc7:	45 31 c9             	xor    r9d,r9d
    7ffff7fb3bca:	0f 05                	syscall
    7ffff7fb3bcc:	48 85 c0             	test   rax,rax
    7ffff7fb3bcf:	0f 85 30 01 00 00    	jne    0x7ffff7fb3d05
    7ffff7fb3bd5:	48 29 35 1c 53 00 00 	sub    QWORD PTR [rip+0x531c],rsi        # 0x7ffff7fb8ef8
    7ffff7fb3bdc:	e9 24 01 00 00       	jmp    0x7ffff7fb3d05
    7ffff7fb3be1:	4d 89 e6             	mov    r14,r12
    7ffff7fb3be4:	49 29 c6             	sub    r14,rax
    7ffff7fb3be7:	4a 8d 1c 28          	lea    rbx,[rax+r13*1]
    7ffff7fb3beb:	4c 3b 35 f6 52 00 00 	cmp    r14,QWORD PTR [rip+0x52f6]        # 0x7ffff7fb8ee8
    7ffff7fb3bf2:	74 0d                	je     0x7ffff7fb3c01
    7ffff7fb3bf4:	4c 89 f7             	mov    rdi,r14
    7ffff7fb3bf7:	48 89 c6             	mov    rsi,rax
    7ffff7fb3bfa:	e8 4b ff ff ff       	call   0x7ffff7fb3b4a
    7ffff7fb3bff:	eb 29                	jmp    0x7ffff7fb3c2a
    7ffff7fb3c01:	41 8b 47 08          	mov    eax,DWORD PTR [r15+0x8]
    7ffff7fb3c05:	f7 d0                	not    eax
    7ffff7fb3c07:	a8 03                	test   al,0x3
    7ffff7fb3c09:	75 1f                	jne    0x7ffff7fb3c2a
    7ffff7fb3c0b:	48 89 1d c6 52 00 00 	mov    QWORD PTR [rip+0x52c6],rbx        # 0x7ffff7fb8ed8
    7ffff7fb3c12:	41 80 67 08 fe       	and    BYTE PTR [r15+0x8],0xfe
    7ffff7fb3c17:	48 89 d8             	mov    rax,rbx
    7ffff7fb3c1a:	48 83 c8 01          	or     rax,0x1
    7ffff7fb3c1e:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb3c22:	49 89 1f             	mov    QWORD PTR [r15],rbx
    7ffff7fb3c25:	e9 db 00 00 00       	jmp    0x7ffff7fb3d05
    7ffff7fb3c2a:	4b 8b 74 2c 08       	mov    rsi,QWORD PTR [r12+r13*1+0x8]
    7ffff7fb3c2f:	40 f6 c6 02          	test   sil,0x2
    7ffff7fb3c33:	75 49                	jne    0x7ffff7fb3c7e
    7ffff7fb3c35:	4c 3b 3d b4 52 00 00 	cmp    r15,QWORD PTR [rip+0x52b4]        # 0x7ffff7fb8ef0
    7ffff7fb3c3c:	74 6b                	je     0x7ffff7fb3ca9
    7ffff7fb3c3e:	4c 3b 3d a3 52 00 00 	cmp    r15,QWORD PTR [rip+0x52a3]        # 0x7ffff7fb8ee8
    7ffff7fb3c45:	0f 84 96 00 00 00    	je     0x7ffff7fb3ce1
    7ffff7fb3c4b:	48 83 e6 f8          	and    rsi,0xfffffffffffffff8
    7ffff7fb3c4f:	48 01 f3             	add    rbx,rsi
    7ffff7fb3c52:	4c 89 ff             	mov    rdi,r15
    7ffff7fb3c55:	e8 f0 fe ff ff       	call   0x7ffff7fb3b4a
    7ffff7fb3c5a:	48 89 d8             	mov    rax,rbx
    7ffff7fb3c5d:	48 83 c8 01          	or     rax,0x1
    7ffff7fb3c61:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb3c65:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb3c69:	4c 3b 35 78 52 00 00 	cmp    r14,QWORD PTR [rip+0x5278]        # 0x7ffff7fb8ee8
    7ffff7fb3c70:	75 23                	jne    0x7ffff7fb3c95
    7ffff7fb3c72:	48 89 1d 5f 52 00 00 	mov    QWORD PTR [rip+0x525f],rbx        # 0x7ffff7fb8ed8
    7ffff7fb3c79:	e9 87 00 00 00       	jmp    0x7ffff7fb3d05
    7ffff7fb3c7e:	48 83 e6 fe          	and    rsi,0xfffffffffffffffe
    7ffff7fb3c82:	49 89 77 08          	mov    QWORD PTR [r15+0x8],rsi
    7ffff7fb3c86:	48 89 d8             	mov    rax,rbx
    7ffff7fb3c89:	48 83 c8 01          	or     rax,0x1
    7ffff7fb3c8d:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb3c91:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb3c95:	4c 89 f7             	mov    rdi,r14
    7ffff7fb3c98:	48 89 de             	mov    rsi,rbx
    7ffff7fb3c9b:	5b                   	pop    rbx
    7ffff7fb3c9c:	41 5c                	pop    r12
    7ffff7fb3c9e:	41 5d                	pop    r13
    7ffff7fb3ca0:	41 5e                	pop    r14
    7ffff7fb3ca2:	41 5f                	pop    r15
    7ffff7fb3ca4:	e9 80 0e 00 00       	jmp    0x7ffff7fb4b29
    7ffff7fb3ca9:	48 03 1d 30 52 00 00 	add    rbx,QWORD PTR [rip+0x5230]        # 0x7ffff7fb8ee0
    7ffff7fb3cb0:	48 89 1d 29 52 00 00 	mov    QWORD PTR [rip+0x5229],rbx        # 0x7ffff7fb8ee0
    7ffff7fb3cb7:	4c 89 35 32 52 00 00 	mov    QWORD PTR [rip+0x5232],r14        # 0x7ffff7fb8ef0
    7ffff7fb3cbe:	48 83 cb 01          	or     rbx,0x1
    7ffff7fb3cc2:	49 89 5e 08          	mov    QWORD PTR [r14+0x8],rbx
    7ffff7fb3cc6:	4c 3b 35 1b 52 00 00 	cmp    r14,QWORD PTR [rip+0x521b]        # 0x7ffff7fb8ee8
    7ffff7fb3ccd:	75 36                	jne    0x7ffff7fb3d05
    7ffff7fb3ccf:	48 83 25 11 52 00 00 	and    QWORD PTR [rip+0x5211],0x0        # 0x7ffff7fb8ee8
    7ffff7fb3cd6:	00 
    7ffff7fb3cd7:	48 83 25 f9 51 00 00 	and    QWORD PTR [rip+0x51f9],0x0        # 0x7ffff7fb8ed8
    7ffff7fb3cde:	00 
    7ffff7fb3cdf:	eb 24                	jmp    0x7ffff7fb3d05
    7ffff7fb3ce1:	48 03 1d f0 51 00 00 	add    rbx,QWORD PTR [rip+0x51f0]        # 0x7ffff7fb8ed8
    7ffff7fb3ce8:	48 89 1d e9 51 00 00 	mov    QWORD PTR [rip+0x51e9],rbx        # 0x7ffff7fb8ed8
    7ffff7fb3cef:	4c 89 35 f2 51 00 00 	mov    QWORD PTR [rip+0x51f2],r14        # 0x7ffff7fb8ee8
    7ffff7fb3cf6:	48 89 d8             	mov    rax,rbx
    7ffff7fb3cf9:	48 83 c8 01          	or     rax,0x1
    7ffff7fb3cfd:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb3d01:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb3d05:	5b                   	pop    rbx
    7ffff7fb3d06:	41 5c                	pop    r12
    7ffff7fb3d08:	41 5d                	pop    r13
    7ffff7fb3d0a:	41 5e                	pop    r14
    7ffff7fb3d0c:	41 5f                	pop    r15
    7ffff7fb3d0e:	c3                   	ret
    7ffff7fb3d0f:	55                   	push   rbp
    7ffff7fb3d10:	41 57                	push   r15
    7ffff7fb3d12:	41 56                	push   r14
    7ffff7fb3d14:	41 55                	push   r13
    7ffff7fb3d16:	41 54                	push   r12
    7ffff7fb3d18:	53                   	push   rbx
    7ffff7fb3d19:	50                   	push   rax
    7ffff7fb3d1a:	48 89 fb             	mov    rbx,rdi
    7ffff7fb3d1d:	6a 02                	push   0x2
    7ffff7fb3d1f:	5d                   	pop    rbp
    7ffff7fb3d20:	48 81 ff e9 00 00 00 	cmp    rdi,0xe9
    7ffff7fb3d27:	73 79                	jae    0x7ffff7fb3da2
    7ffff7fb3d29:	8d 43 17             	lea    eax,[rbx+0x17]
    7ffff7fb3d2c:	25 f0 01 00 00       	and    eax,0x1f0
    7ffff7fb3d31:	48 83 fb 17          	cmp    rbx,0x17
    7ffff7fb3d35:	6a 20                	push   0x20
    7ffff7fb3d37:	5b                   	pop    rbx
    7ffff7fb3d38:	48 0f 43 d8          	cmovae rbx,rax
    7ffff7fb3d3c:	89 d9                	mov    ecx,ebx
    7ffff7fb3d3e:	c1 e9 03             	shr    ecx,0x3
    7ffff7fb3d41:	c4 62 73 f7 3d d6 51 	shrx   r15d,DWORD PTR [rip+0x51d6],ecx        # 0x7ffff7fb8f20
    7ffff7fb3d48:	00 00 
    7ffff7fb3d4a:	41 f6 c7 03          	test   r15b,0x3
    7ffff7fb3d4e:	0f 84 1b 01 00 00    	je     0x7ffff7fb3e6f
    7ffff7fb3d54:	41 83 e7 01          	and    r15d,0x1
    7ffff7fb3d58:	41 09 cf             	or     r15d,ecx
    7ffff7fb3d5b:	41 83 f7 01          	xor    r15d,0x1
    7ffff7fb3d5f:	44 89 f8             	mov    eax,r15d
    7ffff7fb3d62:	c1 e0 04             	shl    eax,0x4
    7ffff7fb3d65:	48 8d 0d 3c 4e 00 00 	lea    rcx,[rip+0x4e3c]        # 0x7ffff7fb8ba8
    7ffff7fb3d6c:	48 8d 3c 08          	lea    rdi,[rax+rcx*1]
    7ffff7fb3d70:	48 81 c7 20 01 00 00 	add    rdi,0x120
    7ffff7fb3d77:	48 8b 5f 10          	mov    rbx,QWORD PTR [rdi+0x10]
    7ffff7fb3d7b:	4c 8d 73 10          	lea    r14,[rbx+0x10]
    7ffff7fb3d7f:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
    7ffff7fb3d83:	44 89 fa             	mov    edx,r15d
    7ffff7fb3d86:	e8 b0 0d 00 00       	call   0x7ffff7fb4b3b
    7ffff7fb3d8b:	41 c1 e7 03          	shl    r15d,0x3
    7ffff7fb3d8f:	49 8d 47 03          	lea    rax,[r15+0x3]
    7ffff7fb3d93:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb3d97:	42 80 4c 3b 08 01    	or     BYTE PTR [rbx+r15*1+0x8],0x1
    7ffff7fb3d9d:	e9 dd 05 00 00       	jmp    0x7ffff7fb437f
    7ffff7fb3da2:	48 81 fb 99 ff fe ff 	cmp    rbx,0xfffffffffffeff99
    7ffff7fb3da9:	0f 83 cd 05 00 00    	jae    0x7ffff7fb437c
    7ffff7fb3daf:	48 83 c3 17          	add    rbx,0x17
    7ffff7fb3db3:	48 83 e3 f0          	and    rbx,0xfffffffffffffff0
    7ffff7fb3db7:	44 8b 25 66 51 00 00 	mov    r12d,DWORD PTR [rip+0x5166]        # 0x7ffff7fb8f24
    7ffff7fb3dbe:	45 85 e4             	test   r12d,r12d
    7ffff7fb3dc1:	0f 84 29 01 00 00    	je     0x7ffff7fb3ef0
    7ffff7fb3dc7:	49 89 df             	mov    r15,rbx
    7ffff7fb3dca:	49 f7 df             	neg    r15
    7ffff7fb3dcd:	48 89 df             	mov    rdi,rbx
    7ffff7fb3dd0:	e8 e8 1f 00 00       	call   0x7ffff7fb5dbd
    7ffff7fb3dd5:	89 c1                	mov    ecx,eax
    7ffff7fb3dd7:	48 8d 15 ca 4d 00 00 	lea    rdx,[rip+0x4dca]        # 0x7ffff7fb8ba8
    7ffff7fb3dde:	48 8b 0c ca          	mov    rcx,QWORD PTR [rdx+rcx*8]
    7ffff7fb3de2:	48 85 c9             	test   rcx,rcx
    7ffff7fb3de5:	0f 84 9c 01 00 00    	je     0x7ffff7fb3f87
    7ffff7fb3deb:	89 c6                	mov    esi,eax
    7ffff7fb3ded:	40 d0 ee             	shr    sil,1
    7ffff7fb3df0:	40 b7 39             	mov    dil,0x39
    7ffff7fb3df3:	40 28 f7             	sub    dil,sil
    7ffff7fb3df6:	40 80 e7 3f          	and    dil,0x3f
    7ffff7fb3dfa:	31 f6                	xor    esi,esi
    7ffff7fb3dfc:	83 f8 1f             	cmp    eax,0x1f
    7ffff7fb3dff:	40 0f b6 ff          	movzx  edi,dil
    7ffff7fb3e03:	0f 44 fe             	cmove  edi,esi
    7ffff7fb3e06:	c4 e2 c1 f7 f3       	shlx   rsi,rbx,rdi
    7ffff7fb3e0b:	45 31 c0             	xor    r8d,r8d
    7ffff7fb3e0e:	45 31 f6             	xor    r14d,r14d
    7ffff7fb3e11:	4c 89 c7             	mov    rdi,r8
    7ffff7fb3e14:	4c 8b 41 08          	mov    r8,QWORD PTR [rcx+0x8]
    7ffff7fb3e18:	49 83 e0 f8          	and    r8,0xfffffffffffffff8
    7ffff7fb3e1c:	49 29 d8             	sub    r8,rbx
    7ffff7fb3e1f:	72 14                	jb     0x7ffff7fb3e35
    7ffff7fb3e21:	4d 39 f8             	cmp    r8,r15
    7ffff7fb3e24:	73 0f                	jae    0x7ffff7fb3e35
    7ffff7fb3e26:	4d 89 c7             	mov    r15,r8
    7ffff7fb3e29:	49 89 ce             	mov    r14,rcx
    7ffff7fb3e2c:	4d 85 c0             	test   r8,r8
    7ffff7fb3e2f:	0f 84 b7 01 00 00    	je     0x7ffff7fb3fec
    7ffff7fb3e35:	4c 8b 49 28          	mov    r9,QWORD PTR [rcx+0x28]
    7ffff7fb3e39:	49 89 f0             	mov    r8,rsi
    7ffff7fb3e3c:	49 c1 e8 3f          	shr    r8,0x3f
    7ffff7fb3e40:	4a 8b 4c c1 20       	mov    rcx,QWORD PTR [rcx+r8*8+0x20]
    7ffff7fb3e45:	49 39 c9             	cmp    r9,rcx
    7ffff7fb3e48:	4d 89 c8             	mov    r8,r9
    7ffff7fb3e4b:	4c 0f 44 c7          	cmove  r8,rdi
    7ffff7fb3e4f:	4d 85 c9             	test   r9,r9
    7ffff7fb3e52:	4c 0f 44 c7          	cmove  r8,rdi
    7ffff7fb3e56:	48 01 f6             	add    rsi,rsi
    7ffff7fb3e59:	48 85 c9             	test   rcx,rcx
    7ffff7fb3e5c:	75 b3                	jne    0x7ffff7fb3e11
    7ffff7fb3e5e:	4d 85 c0             	test   r8,r8
    7ffff7fb3e61:	0f 84 17 01 00 00    	je     0x7ffff7fb3f7e
    7ffff7fb3e67:	4c 89 c1             	mov    rcx,r8
    7ffff7fb3e6a:	e9 83 01 00 00       	jmp    0x7ffff7fb3ff2
    7ffff7fb3e6f:	48 8b 05 62 50 00 00 	mov    rax,QWORD PTR [rip+0x5062]        # 0x7ffff7fb8ed8
    7ffff7fb3e76:	48 39 c3             	cmp    rbx,rax
    7ffff7fb3e79:	0f 86 d5 01 00 00    	jbe    0x7ffff7fb4054
    7ffff7fb3e7f:	45 85 ff             	test   r15d,r15d
    7ffff7fb3e82:	74 78                	je     0x7ffff7fb3efc
    7ffff7fb3e84:	c4 c2 71 f7 c7       	shlx   eax,r15d,ecx
    7ffff7fb3e89:	c4 e2 71 f7 cd       	shlx   ecx,ebp,ecx
    7ffff7fb3e8e:	89 ca                	mov    edx,ecx
    7ffff7fb3e90:	f7 da                	neg    edx
    7ffff7fb3e92:	09 ca                	or     edx,ecx
    7ffff7fb3e94:	21 c2                	and    edx,eax
    7ffff7fb3e96:	f3 44 0f bc fa       	tzcnt  r15d,edx
    7ffff7fb3e9b:	44 89 f8             	mov    eax,r15d
    7ffff7fb3e9e:	c1 e0 04             	shl    eax,0x4
    7ffff7fb3ea1:	48 8d 0d 00 4d 00 00 	lea    rcx,[rip+0x4d00]        # 0x7ffff7fb8ba8
    7ffff7fb3ea8:	48 8d 3c 08          	lea    rdi,[rax+rcx*1]
    7ffff7fb3eac:	48 81 c7 20 01 00 00 	add    rdi,0x120
    7ffff7fb3eb3:	4c 8b 67 10          	mov    r12,QWORD PTR [rdi+0x10]
    7ffff7fb3eb7:	4d 8d 74 24 10       	lea    r14,[r12+0x10]
    7ffff7fb3ebc:	49 8b 74 24 10       	mov    rsi,QWORD PTR [r12+0x10]
    7ffff7fb3ec1:	44 89 fa             	mov    edx,r15d
    7ffff7fb3ec4:	e8 72 0c 00 00       	call   0x7ffff7fb4b3b
    7ffff7fb3ec9:	41 c1 e7 03          	shl    r15d,0x3
    7ffff7fb3ecd:	4c 89 fe             	mov    rsi,r15
    7ffff7fb3ed0:	48 29 de             	sub    rsi,rbx
    7ffff7fb3ed3:	48 83 fe 20          	cmp    rsi,0x20
    7ffff7fb3ed7:	73 7b                	jae    0x7ffff7fb3f54
    7ffff7fb3ed9:	4c 89 f8             	mov    rax,r15
    7ffff7fb3edc:	48 83 c8 03          	or     rax,0x3
    7ffff7fb3ee0:	49 89 44 24 08       	mov    QWORD PTR [r12+0x8],rax
    7ffff7fb3ee5:	43 80 4c 3c 08 01    	or     BYTE PTR [r12+r15*1+0x8],0x1
    7ffff7fb3eeb:	e9 8f 04 00 00       	jmp    0x7ffff7fb437f
    7ffff7fb3ef0:	48 8b 05 e1 4f 00 00 	mov    rax,QWORD PTR [rip+0x4fe1]        # 0x7ffff7fb8ed8
    7ffff7fb3ef7:	e9 58 01 00 00       	jmp    0x7ffff7fb4054
    7ffff7fb3efc:	8b 0d 22 50 00 00    	mov    ecx,DWORD PTR [rip+0x5022]        # 0x7ffff7fb8f24
    7ffff7fb3f02:	85 c9                	test   ecx,ecx
    7ffff7fb3f04:	0f 84 4a 01 00 00    	je     0x7ffff7fb4054
    7ffff7fb3f0a:	f3 0f bc c1          	tzcnt  eax,ecx
    7ffff7fb3f0e:	48 8d 0d 93 4c 00 00 	lea    rcx,[rip+0x4c93]        # 0x7ffff7fb8ba8
    7ffff7fb3f15:	48 8b 0c c1          	mov    rcx,QWORD PTR [rcx+rax*8]
    7ffff7fb3f19:	4c 8b 79 08          	mov    r15,QWORD PTR [rcx+0x8]
    7ffff7fb3f1d:	49 83 e7 f8          	and    r15,0xfffffffffffffff8
    7ffff7fb3f21:	49 29 df             	sub    r15,rbx
    7ffff7fb3f24:	49 89 ce             	mov    r14,rcx
    7ffff7fb3f27:	48 8b 41 20          	mov    rax,QWORD PTR [rcx+0x20]
    7ffff7fb3f2b:	48 85 c0             	test   rax,rax
    7ffff7fb3f2e:	75 09                	jne    0x7ffff7fb3f39
    7ffff7fb3f30:	48 8b 41 28          	mov    rax,QWORD PTR [rcx+0x28]
    7ffff7fb3f34:	48 85 c0             	test   rax,rax
    7ffff7fb3f37:	74 75                	je     0x7ffff7fb3fae
    7ffff7fb3f39:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
    7ffff7fb3f3d:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb3f41:	48 29 d9             	sub    rcx,rbx
    7ffff7fb3f44:	4c 39 f9             	cmp    rcx,r15
    7ffff7fb3f47:	4c 0f 42 f9          	cmovb  r15,rcx
    7ffff7fb3f4b:	4c 0f 42 f0          	cmovb  r14,rax
    7ffff7fb3f4f:	48 89 c1             	mov    rcx,rax
    7ffff7fb3f52:	eb d3                	jmp    0x7ffff7fb3f27
    7ffff7fb3f54:	48 89 d8             	mov    rax,rbx
    7ffff7fb3f57:	48 83 c8 03          	or     rax,0x3
    7ffff7fb3f5b:	49 89 44 24 08       	mov    QWORD PTR [r12+0x8],rax
    7ffff7fb3f60:	49 8d 3c 1c          	lea    rdi,[r12+rbx*1]
    7ffff7fb3f64:	48 89 f0             	mov    rax,rsi
    7ffff7fb3f67:	48 83 c8 01          	or     rax,0x1
    7ffff7fb3f6b:	49 89 44 1c 08       	mov    QWORD PTR [r12+rbx*1+0x8],rax
    7ffff7fb3f70:	4b 89 34 3c          	mov    QWORD PTR [r12+r15*1],rsi
    7ffff7fb3f74:	e8 de 0b 00 00       	call   0x7ffff7fb4b57
    7ffff7fb3f79:	e9 01 04 00 00       	jmp    0x7ffff7fb437f
    7ffff7fb3f7e:	4d 85 f6             	test   r14,r14
    7ffff7fb3f81:	74 04                	je     0x7ffff7fb3f87
    7ffff7fb3f83:	31 c9                	xor    ecx,ecx
    7ffff7fb3f85:	eb 6b                	jmp    0x7ffff7fb3ff2
    7ffff7fb3f87:	c4 e2 79 f7 cd       	shlx   ecx,ebp,eax
    7ffff7fb3f8c:	89 c8                	mov    eax,ecx
    7ffff7fb3f8e:	f7 d8                	neg    eax
    7ffff7fb3f90:	09 c8                	or     eax,ecx
    7ffff7fb3f92:	44 21 e0             	and    eax,r12d
    7ffff7fb3f95:	74 10                	je     0x7ffff7fb3fa7
    7ffff7fb3f97:	f3 0f bc c0          	tzcnt  eax,eax
    7ffff7fb3f9b:	48 8d 04 c2          	lea    rax,[rdx+rax*8]
    7ffff7fb3f9f:	45 31 f6             	xor    r14d,r14d
    7ffff7fb3fa2:	e9 87 00 00 00       	jmp    0x7ffff7fb402e
    7ffff7fb3fa7:	31 c9                	xor    ecx,ecx
    7ffff7fb3fa9:	45 31 f6             	xor    r14d,r14d
    7ffff7fb3fac:	eb 44                	jmp    0x7ffff7fb3ff2
    7ffff7fb3fae:	4c 89 f7             	mov    rdi,r14
    7ffff7fb3fb1:	e8 a5 0a 00 00       	call   0x7ffff7fb4a5b
    7ffff7fb3fb6:	49 83 ff 20          	cmp    r15,0x20
    7ffff7fb3fba:	0f 82 ec 01 00 00    	jb     0x7ffff7fb41ac
    7ffff7fb3fc0:	49 8d 3c 1e          	lea    rdi,[r14+rbx*1]
    7ffff7fb3fc4:	48 89 d8             	mov    rax,rbx
    7ffff7fb3fc7:	48 83 c8 03          	or     rax,0x3
    7ffff7fb3fcb:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb3fcf:	4c 89 f8             	mov    rax,r15
    7ffff7fb3fd2:	48 83 c8 01          	or     rax,0x1
    7ffff7fb3fd6:	49 89 44 1e 08       	mov    QWORD PTR [r14+rbx*1+0x8],rax
    7ffff7fb3fdb:	4d 89 3c 3f          	mov    QWORD PTR [r15+rdi*1],r15
    7ffff7fb3fdf:	4c 89 fe             	mov    rsi,r15
    7ffff7fb3fe2:	e8 70 0b 00 00       	call   0x7ffff7fb4b57
    7ffff7fb3fe7:	e9 a9 01 00 00       	jmp    0x7ffff7fb4195
    7ffff7fb3fec:	45 31 ff             	xor    r15d,r15d
    7ffff7fb3fef:	49 89 ce             	mov    r14,rcx
    7ffff7fb3ff2:	48 85 c9             	test   rcx,rcx
    7ffff7fb3ff5:	74 3c                	je     0x7ffff7fb4033
    7ffff7fb3ff7:	48 89 c8             	mov    rax,rcx
    7ffff7fb3ffa:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
    7ffff7fb3ffe:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb4002:	48 89 ca             	mov    rdx,rcx
    7ffff7fb4005:	48 29 da             	sub    rdx,rbx
    7ffff7fb4008:	4c 39 fa             	cmp    rdx,r15
    7ffff7fb400b:	49 0f 43 d7          	cmovae rdx,r15
    7ffff7fb400f:	4c 89 f6             	mov    rsi,r14
    7ffff7fb4012:	48 0f 42 f0          	cmovb  rsi,rax
    7ffff7fb4016:	48 39 d9             	cmp    rcx,rbx
    7ffff7fb4019:	4c 0f 43 fa          	cmovae r15,rdx
    7ffff7fb401d:	48 8b 48 20          	mov    rcx,QWORD PTR [rax+0x20]
    7ffff7fb4021:	4c 0f 43 f6          	cmovae r14,rsi
    7ffff7fb4025:	48 85 c9             	test   rcx,rcx
    7ffff7fb4028:	75 c8                	jne    0x7ffff7fb3ff2
    7ffff7fb402a:	48 83 c0 28          	add    rax,0x28
    7ffff7fb402e:	48 8b 08             	mov    rcx,QWORD PTR [rax]
    7ffff7fb4031:	eb bf                	jmp    0x7ffff7fb3ff2
    7ffff7fb4033:	48 8b 05 9e 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e9e]        # 0x7ffff7fb8ed8
    7ffff7fb403a:	4d 85 f6             	test   r14,r14
    7ffff7fb403d:	74 15                	je     0x7ffff7fb4054
    7ffff7fb403f:	48 89 c1             	mov    rcx,rax
    7ffff7fb4042:	48 29 d9             	sub    rcx,rbx
    7ffff7fb4045:	0f 82 53 01 00 00    	jb     0x7ffff7fb419e
    7ffff7fb404b:	49 39 cf             	cmp    r15,rcx
    7ffff7fb404e:	0f 82 4a 01 00 00    	jb     0x7ffff7fb419e
    7ffff7fb4054:	48 89 c1             	mov    rcx,rax
    7ffff7fb4057:	48 29 d9             	sub    rcx,rbx
    7ffff7fb405a:	73 33                	jae    0x7ffff7fb408f
    7ffff7fb405c:	48 8b 05 7d 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e7d]        # 0x7ffff7fb8ee0
    7ffff7fb4063:	48 29 d8             	sub    rax,rbx
    7ffff7fb4066:	76 5e                	jbe    0x7ffff7fb40c6
    7ffff7fb4068:	48 89 05 71 4e 00 00 	mov    QWORD PTR [rip+0x4e71],rax        # 0x7ffff7fb8ee0
    7ffff7fb406f:	4c 8b 35 7a 4e 00 00 	mov    r14,QWORD PTR [rip+0x4e7a]        # 0x7ffff7fb8ef0
    7ffff7fb4076:	49 8d 0c 1e          	lea    rcx,[r14+rbx*1]
    7ffff7fb407a:	48 89 0d 6f 4e 00 00 	mov    QWORD PTR [rip+0x4e6f],rcx        # 0x7ffff7fb8ef0
    7ffff7fb4081:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4085:	49 89 44 1e 08       	mov    QWORD PTR [r14+rbx*1+0x8],rax
    7ffff7fb408a:	e9 fe 00 00 00       	jmp    0x7ffff7fb418d
    7ffff7fb408f:	4c 8b 35 52 4e 00 00 	mov    r14,QWORD PTR [rip+0x4e52]        # 0x7ffff7fb8ee8
    7ffff7fb4096:	48 83 f9 20          	cmp    rcx,0x20
    7ffff7fb409a:	0f 83 cb 00 00 00    	jae    0x7ffff7fb416b
    7ffff7fb40a0:	48 83 25 30 4e 00 00 	and    QWORD PTR [rip+0x4e30],0x0        # 0x7ffff7fb8ed8
    7ffff7fb40a7:	00 
    7ffff7fb40a8:	48 83 25 38 4e 00 00 	and    QWORD PTR [rip+0x4e38],0x0        # 0x7ffff7fb8ee8
    7ffff7fb40af:	00 
    7ffff7fb40b0:	48 89 c1             	mov    rcx,rax
    7ffff7fb40b3:	48 83 c9 03          	or     rcx,0x3
    7ffff7fb40b7:	49 89 4e 08          	mov    QWORD PTR [r14+0x8],rcx
    7ffff7fb40bb:	41 80 4c 06 08 01    	or     BYTE PTR [r14+rax*1+0x8],0x1
    7ffff7fb40c1:	e9 cf 00 00 00       	jmp    0x7ffff7fb4195
    7ffff7fb40c6:	4c 8d bb 5f 00 01 00 	lea    r15,[rbx+0x1005f]
    7ffff7fb40cd:	49 81 e7 00 00 ff ff 	and    r15,0xffffffffffff0000
    7ffff7fb40d4:	45 31 f6             	xor    r14d,r14d
    7ffff7fb40d7:	6a 09                	push   0x9
    7ffff7fb40d9:	58                   	pop    rax
    7ffff7fb40da:	6a 03                	push   0x3
    7ffff7fb40dc:	5a                   	pop    rdx
    7ffff7fb40dd:	6a 22                	push   0x22
    7ffff7fb40df:	41 5a                	pop    r10
    7ffff7fb40e1:	6a ff                	push   0xffffffffffffffff
    7ffff7fb40e3:	41 58                	pop    r8
    7ffff7fb40e5:	31 ff                	xor    edi,edi
    7ffff7fb40e7:	4c 89 fe             	mov    rsi,r15
    7ffff7fb40ea:	45 31 c9             	xor    r9d,r9d
    7ffff7fb40ed:	0f 05                	syscall
    7ffff7fb40ef:	49 89 c4             	mov    r12,rax
    7ffff7fb40f2:	48 83 f8 ff          	cmp    rax,0xffffffffffffffff
    7ffff7fb40f6:	4d 0f 44 fe          	cmove  r15,r14
    7ffff7fb40fa:	0f 94 c0             	sete   al
    7ffff7fb40fd:	4d 85 e4             	test   r12,r12
    7ffff7fb4100:	0f 94 c1             	sete   cl
    7ffff7fb4103:	08 c1                	or     cl,al
    7ffff7fb4105:	0f 85 74 02 00 00    	jne    0x7ffff7fb437f
    7ffff7fb410b:	48 8b 05 e6 4d 00 00 	mov    rax,QWORD PTR [rip+0x4de6]        # 0x7ffff7fb8ef8
    7ffff7fb4112:	4c 01 f8             	add    rax,r15
    7ffff7fb4115:	48 89 05 dc 4d 00 00 	mov    QWORD PTR [rip+0x4ddc],rax        # 0x7ffff7fb8ef8
    7ffff7fb411c:	48 8b 0d dd 4d 00 00 	mov    rcx,QWORD PTR [rip+0x4ddd]        # 0x7ffff7fb8f00
    7ffff7fb4123:	48 39 c1             	cmp    rcx,rax
    7ffff7fb4126:	48 0f 47 c1          	cmova  rax,rcx
    7ffff7fb412a:	48 89 05 cf 4d 00 00 	mov    QWORD PTR [rip+0x4dcf],rax        # 0x7ffff7fb8f00
    7ffff7fb4131:	4c 8b 35 b8 4d 00 00 	mov    r14,QWORD PTR [rip+0x4db8]        # 0x7ffff7fb8ef0
    7ffff7fb4138:	4d 85 f6             	test   r14,r14
    7ffff7fb413b:	0f 84 aa 00 00 00    	je     0x7ffff7fb41eb
    7ffff7fb4141:	48 8d 05 60 4b 00 00 	lea    rax,[rip+0x4b60]        # 0x7ffff7fb8ca8
    7ffff7fb4148:	48 85 c0             	test   rax,rax
    7ffff7fb414b:	0f 84 2b 01 00 00    	je     0x7ffff7fb427c
    7ffff7fb4151:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    7ffff7fb4154:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
    7ffff7fb4158:	48 8d 34 0a          	lea    rsi,[rdx+rcx*1]
    7ffff7fb415c:	4c 39 e6             	cmp    rsi,r12
    7ffff7fb415f:	0f 84 e5 00 00 00    	je     0x7ffff7fb424a
    7ffff7fb4165:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    7ffff7fb4169:	eb dd                	jmp    0x7ffff7fb4148
    7ffff7fb416b:	49 8d 14 1e          	lea    rdx,[r14+rbx*1]
    7ffff7fb416f:	48 89 15 72 4d 00 00 	mov    QWORD PTR [rip+0x4d72],rdx        # 0x7ffff7fb8ee8
    7ffff7fb4176:	48 89 0d 5b 4d 00 00 	mov    QWORD PTR [rip+0x4d5b],rcx        # 0x7ffff7fb8ed8
    7ffff7fb417d:	48 89 ca             	mov    rdx,rcx
    7ffff7fb4180:	48 83 ca 01          	or     rdx,0x1
    7ffff7fb4184:	49 89 54 1e 08       	mov    QWORD PTR [r14+rbx*1+0x8],rdx
    7ffff7fb4189:	49 89 0c 06          	mov    QWORD PTR [r14+rax*1],rcx
    7ffff7fb418d:	48 83 cb 03          	or     rbx,0x3
    7ffff7fb4191:	49 89 5e 08          	mov    QWORD PTR [r14+0x8],rbx
    7ffff7fb4195:	49 83 c6 10          	add    r14,0x10
    7ffff7fb4199:	e9 e1 01 00 00       	jmp    0x7ffff7fb437f
    7ffff7fb419e:	4c 89 f7             	mov    rdi,r14
    7ffff7fb41a1:	e8 b5 08 00 00       	call   0x7ffff7fb4a5b
    7ffff7fb41a6:	49 83 ff 20          	cmp    r15,0x20
    7ffff7fb41aa:	73 16                	jae    0x7ffff7fb41c2
    7ffff7fb41ac:	49 01 df             	add    r15,rbx
    7ffff7fb41af:	4c 89 f8             	mov    rax,r15
    7ffff7fb41b2:	48 83 c8 03          	or     rax,0x3
    7ffff7fb41b6:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb41ba:	43 80 4c 3e 08 01    	or     BYTE PTR [r14+r15*1+0x8],0x1
    7ffff7fb41c0:	eb d3                	jmp    0x7ffff7fb4195
    7ffff7fb41c2:	49 8d 3c 1e          	lea    rdi,[r14+rbx*1]
    7ffff7fb41c6:	48 89 d8             	mov    rax,rbx
    7ffff7fb41c9:	48 83 c8 03          	or     rax,0x3
    7ffff7fb41cd:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb41d1:	4c 89 f8             	mov    rax,r15
    7ffff7fb41d4:	48 83 c8 01          	or     rax,0x1
    7ffff7fb41d8:	49 89 44 1e 08       	mov    QWORD PTR [r14+rbx*1+0x8],rax
    7ffff7fb41dd:	4d 89 3c 3f          	mov    QWORD PTR [r15+rdi*1],r15
    7ffff7fb41e1:	4c 89 fe             	mov    rsi,r15
    7ffff7fb41e4:	e8 40 09 00 00       	call   0x7ffff7fb4b29
    7ffff7fb41e9:	eb aa                	jmp    0x7ffff7fb4195
    7ffff7fb41eb:	48 8b 05 1e 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d1e]        # 0x7ffff7fb8f10
    7ffff7fb41f2:	48 85 c0             	test   rax,rax
    7ffff7fb41f5:	74 05                	je     0x7ffff7fb41fc
    7ffff7fb41f7:	4c 39 e0             	cmp    rax,r12
    7ffff7fb41fa:	76 07                	jbe    0x7ffff7fb4203
    7ffff7fb41fc:	4c 89 25 0d 4d 00 00 	mov    QWORD PTR [rip+0x4d0d],r12        # 0x7ffff7fb8f10
    7ffff7fb4203:	4c 89 25 9e 4a 00 00 	mov    QWORD PTR [rip+0x4a9e],r12        # 0x7ffff7fb8ca8
    7ffff7fb420a:	4c 89 3d 9f 4a 00 00 	mov    QWORD PTR [rip+0x4a9f],r15        # 0x7ffff7fb8cb0
    7ffff7fb4211:	83 25 a8 4a 00 00 00 	and    DWORD PTR [rip+0x4aa8],0x0        # 0x7ffff7fb8cc0
    7ffff7fb4218:	6a 20                	push   0x20
    7ffff7fb421a:	58                   	pop    rax
    7ffff7fb421b:	48 c7 05 f2 4c 00 00 	mov    QWORD PTR [rip+0x4cf2],0xfff        # 0x7ffff7fb8f18
    7ffff7fb4222:	ff 0f 00 00 
    7ffff7fb4226:	48 8d 0d 9b 4a 00 00 	lea    rcx,[rip+0x4a9b]        # 0x7ffff7fb8cc8
    7ffff7fb422d:	48 83 e8 01          	sub    rax,0x1
    7ffff7fb4231:	72 0e                	jb     0x7ffff7fb4241
    7ffff7fb4233:	48 89 49 18          	mov    QWORD PTR [rcx+0x18],rcx
    7ffff7fb4237:	48 89 49 10          	mov    QWORD PTR [rcx+0x10],rcx
    7ffff7fb423b:	48 83 c1 10          	add    rcx,0x10
    7ffff7fb423f:	eb ec                	jmp    0x7ffff7fb422d
    7ffff7fb4241:	49 83 c7 b0          	add    r15,0xffffffffffffffb0
    7ffff7fb4245:	4c 89 e7             	mov    rdi,r12
    7ffff7fb4248:	eb 25                	jmp    0x7ffff7fb426f
    7ffff7fb424a:	4d 39 e6             	cmp    r14,r12
    7ffff7fb424d:	73 2d                	jae    0x7ffff7fb427c
    7ffff7fb424f:	4c 39 f2             	cmp    rdx,r14
    7ffff7fb4252:	77 28                	ja     0x7ffff7fb427c
    7ffff7fb4254:	83 78 18 00          	cmp    DWORD PTR [rax+0x18],0x0
    7ffff7fb4258:	75 22                	jne    0x7ffff7fb427c
    7ffff7fb425a:	4c 01 f9             	add    rcx,r15
    7ffff7fb425d:	48 89 48 08          	mov    QWORD PTR [rax+0x8],rcx
    7ffff7fb4261:	48 8b 3d 88 4c 00 00 	mov    rdi,QWORD PTR [rip+0x4c88]        # 0x7ffff7fb8ef0
    7ffff7fb4268:	4c 03 3d 71 4c 00 00 	add    r15,QWORD PTR [rip+0x4c71]        # 0x7ffff7fb8ee0
    7ffff7fb426f:	4c 89 fe             	mov    rsi,r15
    7ffff7fb4272:	e8 69 06 00 00       	call   0x7ffff7fb48e0
    7ffff7fb4277:	e9 f0 00 00 00       	jmp    0x7ffff7fb436c
    7ffff7fb427c:	48 8b 05 8d 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c8d]        # 0x7ffff7fb8f10
    7ffff7fb4283:	4c 39 e0             	cmp    rax,r12
    7ffff7fb4286:	49 0f 43 c4          	cmovae rax,r12
    7ffff7fb428a:	48 89 05 7f 4c 00 00 	mov    QWORD PTR [rip+0x4c7f],rax        # 0x7ffff7fb8f10
    7ffff7fb4291:	4b 8d 0c 3c          	lea    rcx,[r12+r15*1]
    7ffff7fb4295:	48 8d 05 0c 4a 00 00 	lea    rax,[rip+0x4a0c]        # 0x7ffff7fb8ca8
    7ffff7fb429c:	48 85 c0             	test   rax,rax
    7ffff7fb429f:	74 18                	je     0x7ffff7fb42b9
    7ffff7fb42a1:	48 8b 28             	mov    rbp,QWORD PTR [rax]
    7ffff7fb42a4:	48 39 cd             	cmp    rbp,rcx
    7ffff7fb42a7:	74 06                	je     0x7ffff7fb42af
    7ffff7fb42a9:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    7ffff7fb42ad:	eb ed                	jmp    0x7ffff7fb429c
    7ffff7fb42af:	83 78 18 00          	cmp    DWORD PTR [rax+0x18],0x0
    7ffff7fb42b3:	0f 84 db 00 00 00    	je     0x7ffff7fb4394
    7ffff7fb42b9:	4c 89 f7             	mov    rdi,r14
    7ffff7fb42bc:	e8 bf 04 00 00       	call   0x7ffff7fb4780
    7ffff7fb42c1:	48 8b 08             	mov    rcx,QWORD PTR [rax]
    7ffff7fb42c4:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
    7ffff7fb42c8:	48 8d 2c 01          	lea    rbp,[rcx+rax*1]
    7ffff7fb42cc:	4c 8d 2c 01          	lea    r13,[rcx+rax*1]
    7ffff7fb42d0:	49 83 c5 c0          	add    r13,0xffffffffffffffc0
    7ffff7fb42d4:	49 83 e5 f0          	and    r13,0xfffffffffffffff0
    7ffff7fb42d8:	49 83 c5 f0          	add    r13,0xfffffffffffffff0
    7ffff7fb42dc:	49 8d 46 20          	lea    rax,[r14+0x20]
    7ffff7fb42e0:	49 39 c5             	cmp    r13,rax
    7ffff7fb42e3:	4d 0f 42 ee          	cmovb  r13,r14
    7ffff7fb42e7:	49 8d 45 10          	lea    rax,[r13+0x10]
    7ffff7fb42eb:	48 89 04 24          	mov    QWORD PTR [rsp],rax
    7ffff7fb42ef:	49 8d 77 b0          	lea    rsi,[r15-0x50]
    7ffff7fb42f3:	4c 89 e7             	mov    rdi,r12
    7ffff7fb42f6:	e8 e5 05 00 00       	call   0x7ffff7fb48e0
    7ffff7fb42fb:	49 c7 45 08 33 00 00 	mov    QWORD PTR [r13+0x8],0x33
    7ffff7fb4302:	00 
    7ffff7fb4303:	c5 fc 10 05 9d 49 00 	vmovups ymm0,YMMWORD PTR [rip+0x499d]        # 0x7ffff7fb8ca8
    7ffff7fb430a:	00 
    7ffff7fb430b:	c4 c1 7c 11 45 10    	vmovups YMMWORD PTR [r13+0x10],ymm0
    7ffff7fb4311:	4c 89 25 90 49 00 00 	mov    QWORD PTR [rip+0x4990],r12        # 0x7ffff7fb8ca8
    7ffff7fb4318:	4c 89 3d 91 49 00 00 	mov    QWORD PTR [rip+0x4991],r15        # 0x7ffff7fb8cb0
    7ffff7fb431f:	83 25 9a 49 00 00 00 	and    DWORD PTR [rip+0x499a],0x0        # 0x7ffff7fb8cc0
    7ffff7fb4326:	48 8b 04 24          	mov    rax,QWORD PTR [rsp]
    7ffff7fb432a:	48 89 05 87 49 00 00 	mov    QWORD PTR [rip+0x4987],rax        # 0x7ffff7fb8cb8
    7ffff7fb4331:	49 8d 45 38          	lea    rax,[r13+0x38]
    7ffff7fb4335:	48 c7 00 0b 00 00 00 	mov    QWORD PTR [rax],0xb
    7ffff7fb433c:	48 83 c0 08          	add    rax,0x8
    7ffff7fb4340:	48 39 e8             	cmp    rax,rbp
    7ffff7fb4343:	72 f0                	jb     0x7ffff7fb4335
    7ffff7fb4345:	4c 89 ee             	mov    rsi,r13
    7ffff7fb4348:	4c 29 f6             	sub    rsi,r14
    7ffff7fb434b:	74 1f                	je     0x7ffff7fb436c
    7ffff7fb434d:	41 80 65 08 fe       	and    BYTE PTR [r13+0x8],0xfe
    7ffff7fb4352:	48 89 f0             	mov    rax,rsi
    7ffff7fb4355:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4359:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb435d:	49 89 75 00          	mov    QWORD PTR [r13+0x0],rsi
    7ffff7fb4361:	4c 89 f7             	mov    rdi,r14
    7ffff7fb4364:	c5 f8 77             	vzeroupper
    7ffff7fb4367:	e8 bd 07 00 00       	call   0x7ffff7fb4b29
    7ffff7fb436c:	48 8b 05 6d 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b6d]        # 0x7ffff7fb8ee0
    7ffff7fb4373:	48 29 d8             	sub    rax,rbx
    7ffff7fb4376:	0f 87 ec fc ff ff    	ja     0x7ffff7fb4068
    7ffff7fb437c:	45 31 f6             	xor    r14d,r14d
    7ffff7fb437f:	4c 89 f0             	mov    rax,r14
    7ffff7fb4382:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb4386:	5b                   	pop    rbx
    7ffff7fb4387:	41 5c                	pop    r12
    7ffff7fb4389:	41 5d                	pop    r13
    7ffff7fb438b:	41 5e                	pop    r14
    7ffff7fb438d:	41 5f                	pop    r15
    7ffff7fb438f:	5d                   	pop    rbp
    7ffff7fb4390:	c5 f8 77             	vzeroupper
    7ffff7fb4393:	c3                   	ret
    7ffff7fb4394:	4c 89 20             	mov    QWORD PTR [rax],r12
    7ffff7fb4397:	4c 01 78 08          	add    QWORD PTR [rax+0x8],r15
    7ffff7fb439b:	49 83 c4 1f          	add    r12,0x1f
    7ffff7fb439f:	49 83 e4 f0          	and    r12,0xfffffffffffffff0
    7ffff7fb43a3:	4d 8d 74 24 f0       	lea    r14,[r12-0x10]
    7ffff7fb43a8:	48 83 c5 1f          	add    rbp,0x1f
    7ffff7fb43ac:	48 83 e5 f0          	and    rbp,0xfffffffffffffff0
    7ffff7fb43b0:	48 83 c5 f0          	add    rbp,0xfffffffffffffff0
    7ffff7fb43b4:	4d 8d 3c 1c          	lea    r15,[r12+rbx*1]
    7ffff7fb43b8:	49 83 c7 f0          	add    r15,0xfffffffffffffff0
    7ffff7fb43bc:	49 89 ed             	mov    r13,rbp
    7ffff7fb43bf:	4d 29 fd             	sub    r13,r15
    7ffff7fb43c2:	48 83 cb 03          	or     rbx,0x3
    7ffff7fb43c6:	49 89 5c 24 f8       	mov    QWORD PTR [r12-0x8],rbx
    7ffff7fb43cb:	48 3b 2d 1e 4b 00 00 	cmp    rbp,QWORD PTR [rip+0x4b1e]        # 0x7ffff7fb8ef0
    7ffff7fb43d2:	74 57                	je     0x7ffff7fb442b
    7ffff7fb43d4:	48 3b 2d 0d 4b 00 00 	cmp    rbp,QWORD PTR [rip+0x4b0d]        # 0x7ffff7fb8ee8
    7ffff7fb43db:	74 70                	je     0x7ffff7fb444d
    7ffff7fb43dd:	48 8b 5d 08          	mov    rbx,QWORD PTR [rbp+0x8]
    7ffff7fb43e1:	89 d8                	mov    eax,ebx
    7ffff7fb43e3:	83 e0 03             	and    eax,0x3
    7ffff7fb43e6:	83 f8 01             	cmp    eax,0x1
    7ffff7fb43e9:	75 1e                	jne    0x7ffff7fb4409
    7ffff7fb43eb:	48 83 e3 f8          	and    rbx,0xfffffffffffffff8
    7ffff7fb43ef:	48 89 ef             	mov    rdi,rbp
    7ffff7fb43f2:	48 89 de             	mov    rsi,rbx
    7ffff7fb43f5:	e8 50 f7 ff ff       	call   0x7ffff7fb3b4a
    7ffff7fb43fa:	48 8d 04 2b          	lea    rax,[rbx+rbp*1]
    7ffff7fb43fe:	49 01 dd             	add    r13,rbx
    7ffff7fb4401:	48 8b 5c 1d 08       	mov    rbx,QWORD PTR [rbp+rbx*1+0x8]
    7ffff7fb4406:	48 89 c5             	mov    rbp,rax
    7ffff7fb4409:	48 83 e3 fe          	and    rbx,0xfffffffffffffffe
    7ffff7fb440d:	48 89 5d 08          	mov    QWORD PTR [rbp+0x8],rbx
    7ffff7fb4411:	4c 89 e8             	mov    rax,r13
    7ffff7fb4414:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4418:	49 89 47 08          	mov    QWORD PTR [r15+0x8],rax
    7ffff7fb441c:	4f 89 2c 2f          	mov    QWORD PTR [r15+r13*1],r13
    7ffff7fb4420:	4c 89 ff             	mov    rdi,r15
    7ffff7fb4423:	4c 89 ee             	mov    rsi,r13
    7ffff7fb4426:	e9 b9 fd ff ff       	jmp    0x7ffff7fb41e4
    7ffff7fb442b:	4c 03 2d ae 4a 00 00 	add    r13,QWORD PTR [rip+0x4aae]        # 0x7ffff7fb8ee0
    7ffff7fb4432:	4c 89 2d a7 4a 00 00 	mov    QWORD PTR [rip+0x4aa7],r13        # 0x7ffff7fb8ee0
    7ffff7fb4439:	4c 89 3d b0 4a 00 00 	mov    QWORD PTR [rip+0x4ab0],r15        # 0x7ffff7fb8ef0
    7ffff7fb4440:	49 83 cd 01          	or     r13,0x1
    7ffff7fb4444:	4d 89 6f 08          	mov    QWORD PTR [r15+0x8],r13
    7ffff7fb4448:	e9 48 fd ff ff       	jmp    0x7ffff7fb4195
    7ffff7fb444d:	4c 03 2d 84 4a 00 00 	add    r13,QWORD PTR [rip+0x4a84]        # 0x7ffff7fb8ed8
    7ffff7fb4454:	4c 89 2d 7d 4a 00 00 	mov    QWORD PTR [rip+0x4a7d],r13        # 0x7ffff7fb8ed8
    7ffff7fb445b:	4c 89 3d 86 4a 00 00 	mov    QWORD PTR [rip+0x4a86],r15        # 0x7ffff7fb8ee8
    7ffff7fb4462:	4c 89 e8             	mov    rax,r13
    7ffff7fb4465:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4469:	49 89 47 08          	mov    QWORD PTR [r15+0x8],rax
    7ffff7fb446d:	4f 89 2c 2f          	mov    QWORD PTR [r15+r13*1],r13
    7ffff7fb4471:	e9 1f fd ff ff       	jmp    0x7ffff7fb4195
    7ffff7fb4476:	55                   	push   rbp
    7ffff7fb4477:	41 57                	push   r15
    7ffff7fb4479:	41 56                	push   r14
    7ffff7fb447b:	41 55                	push   r13
    7ffff7fb447d:	41 54                	push   r12
    7ffff7fb447f:	53                   	push   rbx
    7ffff7fb4480:	50                   	push   rax
    7ffff7fb4481:	4c 8d 67 f0          	lea    r12,[rdi-0x10]
    7ffff7fb4485:	48 8b 4f f8          	mov    rcx,QWORD PTR [rdi-0x8]
    7ffff7fb4489:	49 89 cd             	mov    r13,rcx
    7ffff7fb448c:	49 83 e5 f8          	and    r13,0xfffffffffffffff8
    7ffff7fb4490:	4e 8d 3c 2f          	lea    r15,[rdi+r13*1]
    7ffff7fb4494:	49 83 c7 f0          	add    r15,0xfffffffffffffff0
    7ffff7fb4498:	4c 89 eb             	mov    rbx,r13
    7ffff7fb449b:	4d 89 e6             	mov    r14,r12
    7ffff7fb449e:	f6 c1 01             	test   cl,0x1
    7ffff7fb44a1:	0f 85 85 00 00 00    	jne    0x7ffff7fb452c
    7ffff7fb44a7:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
    7ffff7fb44ab:	f6 c1 02             	test   cl,0x2
    7ffff7fb44ae:	75 33                	jne    0x7ffff7fb44e3
    7ffff7fb44b0:	4a 8d 34 28          	lea    rsi,[rax+r13*1]
    7ffff7fb44b4:	48 83 c6 20          	add    rsi,0x20
    7ffff7fb44b8:	49 29 c4             	sub    r12,rax
    7ffff7fb44bb:	6a 0b                	push   0xb
    7ffff7fb44bd:	58                   	pop    rax
    7ffff7fb44be:	4c 89 e7             	mov    rdi,r12
    7ffff7fb44c1:	31 d2                	xor    edx,edx
    7ffff7fb44c3:	45 31 d2             	xor    r10d,r10d
    7ffff7fb44c6:	45 31 c0             	xor    r8d,r8d
    7ffff7fb44c9:	45 31 c9             	xor    r9d,r9d
    7ffff7fb44cc:	0f 05                	syscall
    7ffff7fb44ce:	48 85 c0             	test   rax,rax
    7ffff7fb44d1:	0f 85 fc 01 00 00    	jne    0x7ffff7fb46d3
    7ffff7fb44d7:	48 29 35 1a 4a 00 00 	sub    QWORD PTR [rip+0x4a1a],rsi        # 0x7ffff7fb8ef8
    7ffff7fb44de:	e9 f0 01 00 00       	jmp    0x7ffff7fb46d3
    7ffff7fb44e3:	4d 89 e6             	mov    r14,r12
    7ffff7fb44e6:	49 29 c6             	sub    r14,rax
    7ffff7fb44e9:	4a 8d 1c 28          	lea    rbx,[rax+r13*1]
    7ffff7fb44ed:	4c 3b 35 f4 49 00 00 	cmp    r14,QWORD PTR [rip+0x49f4]        # 0x7ffff7fb8ee8
    7ffff7fb44f4:	74 0d                	je     0x7ffff7fb4503
    7ffff7fb44f6:	4c 89 f7             	mov    rdi,r14
    7ffff7fb44f9:	48 89 c6             	mov    rsi,rax
    7ffff7fb44fc:	e8 49 f6 ff ff       	call   0x7ffff7fb3b4a
    7ffff7fb4501:	eb 29                	jmp    0x7ffff7fb452c
    7ffff7fb4503:	41 8b 47 08          	mov    eax,DWORD PTR [r15+0x8]
    7ffff7fb4507:	f7 d0                	not    eax
    7ffff7fb4509:	a8 03                	test   al,0x3
    7ffff7fb450b:	75 1f                	jne    0x7ffff7fb452c
    7ffff7fb450d:	48 89 1d c4 49 00 00 	mov    QWORD PTR [rip+0x49c4],rbx        # 0x7ffff7fb8ed8
    7ffff7fb4514:	41 80 67 08 fe       	and    BYTE PTR [r15+0x8],0xfe
    7ffff7fb4519:	48 89 d8             	mov    rax,rbx
    7ffff7fb451c:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4520:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb4524:	49 89 1f             	mov    QWORD PTR [r15],rbx
    7ffff7fb4527:	e9 a7 01 00 00       	jmp    0x7ffff7fb46d3
    7ffff7fb452c:	4b 8b 74 2c 08       	mov    rsi,QWORD PTR [r12+r13*1+0x8]
    7ffff7fb4531:	40 f6 c6 02          	test   sil,0x2
    7ffff7fb4535:	75 4d                	jne    0x7ffff7fb4584
    7ffff7fb4537:	4c 3b 3d b2 49 00 00 	cmp    r15,QWORD PTR [rip+0x49b2]        # 0x7ffff7fb8ef0
    7ffff7fb453e:	0f 84 9e 00 00 00    	je     0x7ffff7fb45e2
    7ffff7fb4544:	4c 3b 3d 9d 49 00 00 	cmp    r15,QWORD PTR [rip+0x499d]        # 0x7ffff7fb8ee8
    7ffff7fb454b:	0f 84 5e 01 00 00    	je     0x7ffff7fb46af
    7ffff7fb4551:	48 83 e6 f8          	and    rsi,0xfffffffffffffff8
    7ffff7fb4555:	48 01 f3             	add    rbx,rsi
    7ffff7fb4558:	4c 89 ff             	mov    rdi,r15
    7ffff7fb455b:	e8 ea f5 ff ff       	call   0x7ffff7fb3b4a
    7ffff7fb4560:	48 89 d8             	mov    rax,rbx
    7ffff7fb4563:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4567:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb456b:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb456f:	4c 3b 35 72 49 00 00 	cmp    r14,QWORD PTR [rip+0x4972]        # 0x7ffff7fb8ee8
    7ffff7fb4576:	75 23                	jne    0x7ffff7fb459b
    7ffff7fb4578:	48 89 1d 59 49 00 00 	mov    QWORD PTR [rip+0x4959],rbx        # 0x7ffff7fb8ed8
    7ffff7fb457f:	e9 4f 01 00 00       	jmp    0x7ffff7fb46d3
    7ffff7fb4584:	48 83 e6 fe          	and    rsi,0xfffffffffffffffe
    7ffff7fb4588:	49 89 77 08          	mov    QWORD PTR [r15+0x8],rsi
    7ffff7fb458c:	48 89 d8             	mov    rax,rbx
    7ffff7fb458f:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4593:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb4597:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb459b:	4c 89 f7             	mov    rdi,r14
    7ffff7fb459e:	48 89 de             	mov    rsi,rbx
    7ffff7fb45a1:	48 81 fb 00 01 00 00 	cmp    rbx,0x100
    7ffff7fb45a8:	73 13                	jae    0x7ffff7fb45bd
    7ffff7fb45aa:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb45ae:	5b                   	pop    rbx
    7ffff7fb45af:	41 5c                	pop    r12
    7ffff7fb45b1:	41 5d                	pop    r13
    7ffff7fb45b3:	41 5e                	pop    r14
    7ffff7fb45b5:	41 5f                	pop    r15
    7ffff7fb45b7:	5d                   	pop    rbp
    7ffff7fb45b8:	e9 43 04 00 00       	jmp    0x7ffff7fb4a00
    7ffff7fb45bd:	e8 62 03 00 00       	call   0x7ffff7fb4924
    7ffff7fb45c2:	48 ff 0d 4f 49 00 00 	dec    QWORD PTR [rip+0x494f]        # 0x7ffff7fb8f18
    7ffff7fb45c9:	0f 85 04 01 00 00    	jne    0x7ffff7fb46d3
    7ffff7fb45cf:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb45d3:	5b                   	pop    rbx
    7ffff7fb45d4:	41 5c                	pop    r12
    7ffff7fb45d6:	41 5d                	pop    r13
    7ffff7fb45d8:	41 5e                	pop    r14
    7ffff7fb45da:	41 5f                	pop    r15
    7ffff7fb45dc:	5d                   	pop    rbp
    7ffff7fb45dd:	e9 c4 01 00 00       	jmp    0x7ffff7fb47a6
    7ffff7fb45e2:	48 03 1d f7 48 00 00 	add    rbx,QWORD PTR [rip+0x48f7]        # 0x7ffff7fb8ee0
    7ffff7fb45e9:	48 89 1d f0 48 00 00 	mov    QWORD PTR [rip+0x48f0],rbx        # 0x7ffff7fb8ee0
    7ffff7fb45f0:	4c 89 35 f9 48 00 00 	mov    QWORD PTR [rip+0x48f9],r14        # 0x7ffff7fb8ef0
    7ffff7fb45f7:	48 89 d8             	mov    rax,rbx
    7ffff7fb45fa:	48 83 c8 01          	or     rax,0x1
    7ffff7fb45fe:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb4602:	4c 3b 35 df 48 00 00 	cmp    r14,QWORD PTR [rip+0x48df]        # 0x7ffff7fb8ee8
    7ffff7fb4609:	75 10                	jne    0x7ffff7fb461b
    7ffff7fb460b:	48 83 25 d5 48 00 00 	and    QWORD PTR [rip+0x48d5],0x0        # 0x7ffff7fb8ee8
    7ffff7fb4612:	00 
    7ffff7fb4613:	48 83 25 bd 48 00 00 	and    QWORD PTR [rip+0x48bd],0x0        # 0x7ffff7fb8ed8
    7ffff7fb461a:	00 
    7ffff7fb461b:	48 39 1d e6 48 00 00 	cmp    QWORD PTR [rip+0x48e6],rbx        # 0x7ffff7fb8f08
    7ffff7fb4622:	0f 83 ab 00 00 00    	jae    0x7ffff7fb46d3
    7ffff7fb4628:	48 8b 3d c1 48 00 00 	mov    rdi,QWORD PTR [rip+0x48c1]        # 0x7ffff7fb8ef0
    7ffff7fb462f:	48 85 ff             	test   rdi,rdi
    7ffff7fb4632:	0f 84 9b 00 00 00    	je     0x7ffff7fb46d3
    7ffff7fb4638:	48 8b 1d a1 48 00 00 	mov    rbx,QWORD PTR [rip+0x48a1]        # 0x7ffff7fb8ee0
    7ffff7fb463f:	48 83 fb 51          	cmp    rbx,0x51
    7ffff7fb4643:	72 43                	jb     0x7ffff7fb4688
    7ffff7fb4645:	48 8d 43 b0          	lea    rax,[rbx-0x50]
    7ffff7fb4649:	45 31 ff             	xor    r15d,r15d
    7ffff7fb464c:	66 85 c0             	test   ax,ax
    7ffff7fb464f:	40 0f 95 c5          	setne  bpl
    7ffff7fb4653:	e8 28 01 00 00       	call   0x7ffff7fb4780
    7ffff7fb4658:	f6 40 18 01          	test   BYTE PTR [rax+0x18],0x1
    7ffff7fb465c:	75 2a                	jne    0x7ffff7fb4688
    7ffff7fb465e:	49 89 c6             	mov    r14,rax
    7ffff7fb4661:	41 88 ef             	mov    r15b,bpl
    7ffff7fb4664:	41 c1 e7 10          	shl    r15d,0x10
    7ffff7fb4668:	4c 01 fb             	add    rbx,r15
    7ffff7fb466b:	48 83 c3 b0          	add    rbx,0xffffffffffffffb0
    7ffff7fb466f:	48 c7 c0 00 00 ff ff 	mov    rax,0xffffffffffff0000
    7ffff7fb4676:	48 21 c3             	and    rbx,rax
    7ffff7fb4679:	48 01 c3             	add    rbx,rax
    7ffff7fb467c:	49 8b 76 08          	mov    rsi,QWORD PTR [r14+0x8]
    7ffff7fb4680:	48 89 f2             	mov    rdx,rsi
    7ffff7fb4683:	48 29 da             	sub    rdx,rbx
    7ffff7fb4686:	73 5a                	jae    0x7ffff7fb46e2
    7ffff7fb4688:	45 31 ff             	xor    r15d,r15d
    7ffff7fb468b:	e8 16 01 00 00       	call   0x7ffff7fb47a6
    7ffff7fb4690:	4c 01 f8             	add    rax,r15
    7ffff7fb4693:	75 3e                	jne    0x7ffff7fb46d3
    7ffff7fb4695:	48 8b 05 44 48 00 00 	mov    rax,QWORD PTR [rip+0x4844]        # 0x7ffff7fb8ee0
    7ffff7fb469c:	48 3b 05 65 48 00 00 	cmp    rax,QWORD PTR [rip+0x4865]        # 0x7ffff7fb8f08
    7ffff7fb46a3:	76 2e                	jbe    0x7ffff7fb46d3
    7ffff7fb46a5:	48 83 0d 5b 48 00 00 	or     QWORD PTR [rip+0x485b],0xffffffffffffffff        # 0x7ffff7fb8f08
    7ffff7fb46ac:	ff 
    7ffff7fb46ad:	eb 24                	jmp    0x7ffff7fb46d3
    7ffff7fb46af:	48 03 1d 22 48 00 00 	add    rbx,QWORD PTR [rip+0x4822]        # 0x7ffff7fb8ed8
    7ffff7fb46b6:	48 89 1d 1b 48 00 00 	mov    QWORD PTR [rip+0x481b],rbx        # 0x7ffff7fb8ed8
    7ffff7fb46bd:	4c 89 35 24 48 00 00 	mov    QWORD PTR [rip+0x4824],r14        # 0x7ffff7fb8ee8
    7ffff7fb46c4:	48 89 d8             	mov    rax,rbx
    7ffff7fb46c7:	48 83 c8 01          	or     rax,0x1
    7ffff7fb46cb:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb46cf:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb46d3:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb46d7:	5b                   	pop    rbx
    7ffff7fb46d8:	41 5c                	pop    r12
    7ffff7fb46da:	41 5d                	pop    r13
    7ffff7fb46dc:	41 5e                	pop    r14
    7ffff7fb46de:	41 5f                	pop    r15
    7ffff7fb46e0:	5d                   	pop    rbp
    7ffff7fb46e1:	c3                   	ret
    7ffff7fb46e2:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
    7ffff7fb46e5:	48 8d 04 37          	lea    rax,[rdi+rsi*1]
    7ffff7fb46e9:	48 8d 0d b8 45 00 00 	lea    rcx,[rip+0x45b8]        # 0x7ffff7fb8ca8
    7ffff7fb46f0:	45 31 ff             	xor    r15d,r15d
    7ffff7fb46f3:	48 85 c9             	test   rcx,rcx
    7ffff7fb46f6:	74 19                	je     0x7ffff7fb4711
    7ffff7fb46f8:	48 39 cf             	cmp    rdi,rcx
    7ffff7fb46fb:	41 0f 96 c0          	setbe  r8b
    7ffff7fb46ff:	48 39 c8             	cmp    rax,rcx
    7ffff7fb4702:	41 0f 97 c1          	seta   r9b
    7ffff7fb4706:	45 84 c8             	test   r8b,r9b
    7ffff7fb4709:	75 80                	jne    0x7ffff7fb468b
    7ffff7fb470b:	48 8b 49 10          	mov    rcx,QWORD PTR [rcx+0x10]
    7ffff7fb470f:	eb e2                	jmp    0x7ffff7fb46f3
    7ffff7fb4711:	6a 19                	push   0x19
    7ffff7fb4713:	58                   	pop    rax
    7ffff7fb4714:	45 31 d2             	xor    r10d,r10d
    7ffff7fb4717:	45 31 c0             	xor    r8d,r8d
    7ffff7fb471a:	45 31 c9             	xor    r9d,r9d
    7ffff7fb471d:	0f 05                	syscall
    7ffff7fb471f:	b1 01                	mov    cl,0x1
    7ffff7fb4721:	48 83 f8 ff          	cmp    rax,0xffffffffffffffff
    7ffff7fb4725:	75 1c                	jne    0x7ffff7fb4743
    7ffff7fb4727:	48 01 d7             	add    rdi,rdx
    7ffff7fb472a:	6a 0b                	push   0xb
    7ffff7fb472c:	58                   	pop    rax
    7ffff7fb472d:	48 89 de             	mov    rsi,rbx
    7ffff7fb4730:	31 d2                	xor    edx,edx
    7ffff7fb4732:	45 31 d2             	xor    r10d,r10d
    7ffff7fb4735:	45 31 c0             	xor    r8d,r8d
    7ffff7fb4738:	45 31 c9             	xor    r9d,r9d
    7ffff7fb473b:	0f 05                	syscall
    7ffff7fb473d:	48 85 c0             	test   rax,rax
    7ffff7fb4740:	0f 94 c1             	sete   cl
    7ffff7fb4743:	45 31 ff             	xor    r15d,r15d
    7ffff7fb4746:	84 c9                	test   cl,cl
    7ffff7fb4748:	0f 84 3d ff ff ff    	je     0x7ffff7fb468b
    7ffff7fb474e:	48 85 db             	test   rbx,rbx
    7ffff7fb4751:	0f 84 34 ff ff ff    	je     0x7ffff7fb468b
    7ffff7fb4757:	49 29 5e 08          	sub    QWORD PTR [r14+0x8],rbx
    7ffff7fb475b:	48 29 1d 96 47 00 00 	sub    QWORD PTR [rip+0x4796],rbx        # 0x7ffff7fb8ef8
    7ffff7fb4762:	48 8b 3d 87 47 00 00 	mov    rdi,QWORD PTR [rip+0x4787]        # 0x7ffff7fb8ef0
    7ffff7fb4769:	48 8b 35 70 47 00 00 	mov    rsi,QWORD PTR [rip+0x4770]        # 0x7ffff7fb8ee0
    7ffff7fb4770:	48 29 de             	sub    rsi,rbx
    7ffff7fb4773:	e8 68 01 00 00       	call   0x7ffff7fb48e0
    7ffff7fb4778:	49 89 df             	mov    r15,rbx
    7ffff7fb477b:	e9 0b ff ff ff       	jmp    0x7ffff7fb468b
    7ffff7fb4780:	48 8d 05 21 45 00 00 	lea    rax,[rip+0x4521]        # 0x7ffff7fb8ca8
    7ffff7fb4787:	48 85 c0             	test   rax,rax
    7ffff7fb478a:	74 17                	je     0x7ffff7fb47a3
    7ffff7fb478c:	48 8b 08             	mov    rcx,QWORD PTR [rax]
    7ffff7fb478f:	48 39 f9             	cmp    rcx,rdi
    7ffff7fb4792:	77 09                	ja     0x7ffff7fb479d
    7ffff7fb4794:	48 03 48 08          	add    rcx,QWORD PTR [rax+0x8]
    7ffff7fb4798:	48 39 f9             	cmp    rcx,rdi
    7ffff7fb479b:	77 08                	ja     0x7ffff7fb47a5
    7ffff7fb479d:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    7ffff7fb47a1:	eb e4                	jmp    0x7ffff7fb4787
    7ffff7fb47a3:	31 c0                	xor    eax,eax
    7ffff7fb47a5:	c3                   	ret
    7ffff7fb47a6:	55                   	push   rbp
    7ffff7fb47a7:	41 57                	push   r15
    7ffff7fb47a9:	41 56                	push   r14
    7ffff7fb47ab:	41 55                	push   r13
    7ffff7fb47ad:	41 54                	push   r12
    7ffff7fb47af:	53                   	push   rbx
    7ffff7fb47b0:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb47b4:	48 8d 05 ed 44 00 00 	lea    rax,[rip+0x44ed]        # 0x7ffff7fb8ca8
    7ffff7fb47bb:	48 89 04 24          	mov    QWORD PTR [rsp],rax
    7ffff7fb47bf:	48 8b 35 f2 44 00 00 	mov    rsi,QWORD PTR [rip+0x44f2]        # 0x7ffff7fb8cb8
    7ffff7fb47c6:	45 31 f6             	xor    r14d,r14d
    7ffff7fb47c9:	31 c0                	xor    eax,eax
    7ffff7fb47cb:	48 89 f3             	mov    rbx,rsi
    7ffff7fb47ce:	48 85 db             	test   rbx,rbx
    7ffff7fb47d1:	0f 84 e3 00 00 00    	je     0x7ffff7fb48ba
    7ffff7fb47d7:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
    7ffff7fb47db:	49 ff c6             	inc    r14
    7ffff7fb47de:	f6 43 18 01          	test   BYTE PTR [rbx+0x18],0x1
    7ffff7fb47e2:	0f 85 ab 00 00 00    	jne    0x7ffff7fb4893
    7ffff7fb47e8:	48 8b 2b             	mov    rbp,QWORD PTR [rbx]
    7ffff7fb47eb:	4c 8d 7d 1f          	lea    r15,[rbp+0x1f]
    7ffff7fb47ef:	49 83 e7 f0          	and    r15,0xfffffffffffffff0
    7ffff7fb47f3:	4d 8b 67 f8          	mov    r12,QWORD PTR [r15-0x8]
    7ffff7fb47f7:	44 89 e1             	mov    ecx,r12d
    7ffff7fb47fa:	83 e1 03             	and    ecx,0x3
    7ffff7fb47fd:	83 f9 01             	cmp    ecx,0x1
    7ffff7fb4800:	0f 85 8d 00 00 00    	jne    0x7ffff7fb4893
    7ffff7fb4806:	4c 8b 6b 08          	mov    r13,QWORD PTR [rbx+0x8]
    7ffff7fb480a:	49 83 e4 f8          	and    r12,0xfffffffffffffff8
    7ffff7fb480e:	4b 8d 14 27          	lea    rdx,[r15+r12*1]
    7ffff7fb4812:	48 83 c2 f0          	add    rdx,0xfffffffffffffff0
    7ffff7fb4816:	4a 8d 0c 2d b0 ff ff 	lea    rcx,[r13*1-0x50]
    7ffff7fb481d:	ff 
    7ffff7fb481e:	48 01 e9             	add    rcx,rbp
    7ffff7fb4821:	48 39 ca             	cmp    rdx,rcx
    7ffff7fb4824:	72 6d                	jb     0x7ffff7fb4893
    7ffff7fb4826:	48 89 74 24 08       	mov    QWORD PTR [rsp+0x8],rsi
    7ffff7fb482b:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
    7ffff7fb4830:	49 83 c7 f0          	add    r15,0xfffffffffffffff0
    7ffff7fb4834:	4c 3b 3d ad 46 00 00 	cmp    r15,QWORD PTR [rip+0x46ad]        # 0x7ffff7fb8ee8
    7ffff7fb483b:	74 0a                	je     0x7ffff7fb4847
    7ffff7fb483d:	4c 89 ff             	mov    rdi,r15
    7ffff7fb4840:	e8 16 02 00 00       	call   0x7ffff7fb4a5b
    7ffff7fb4845:	eb 10                	jmp    0x7ffff7fb4857
    7ffff7fb4847:	48 83 25 99 46 00 00 	and    QWORD PTR [rip+0x4699],0x0        # 0x7ffff7fb8ee8
    7ffff7fb484e:	00 
    7ffff7fb484f:	48 83 25 81 46 00 00 	and    QWORD PTR [rip+0x4681],0x0        # 0x7ffff7fb8ed8
    7ffff7fb4856:	00 
    7ffff7fb4857:	6a 0b                	push   0xb
    7ffff7fb4859:	58                   	pop    rax
    7ffff7fb485a:	48 89 ef             	mov    rdi,rbp
    7ffff7fb485d:	4c 89 ee             	mov    rsi,r13
    7ffff7fb4860:	31 d2                	xor    edx,edx
    7ffff7fb4862:	45 31 d2             	xor    r10d,r10d
    7ffff7fb4865:	45 31 c0             	xor    r8d,r8d
    7ffff7fb4868:	45 31 c9             	xor    r9d,r9d
    7ffff7fb486b:	0f 05                	syscall
    7ffff7fb486d:	48 85 c0             	test   rax,rax
    7ffff7fb4870:	75 2a                	jne    0x7ffff7fb489c
    7ffff7fb4872:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb4877:	4c 01 e8             	add    rax,r13
    7ffff7fb487a:	4c 29 2d 77 46 00 00 	sub    QWORD PTR [rip+0x4677],r13        # 0x7ffff7fb8ef8
    7ffff7fb4881:	48 8b 0c 24          	mov    rcx,QWORD PTR [rsp]
    7ffff7fb4885:	48 8b 5c 24 08       	mov    rbx,QWORD PTR [rsp+0x8]
    7ffff7fb488a:	48 89 59 10          	mov    QWORD PTR [rcx+0x10],rbx
    7ffff7fb488e:	e9 3b ff ff ff       	jmp    0x7ffff7fb47ce
    7ffff7fb4893:	48 89 1c 24          	mov    QWORD PTR [rsp],rbx
    7ffff7fb4897:	e9 2f ff ff ff       	jmp    0x7ffff7fb47cb
    7ffff7fb489c:	4c 89 ff             	mov    rdi,r15
    7ffff7fb489f:	4c 89 e6             	mov    rsi,r12
    7ffff7fb48a2:	e8 7d 00 00 00       	call   0x7ffff7fb4924
    7ffff7fb48a7:	48 89 1c 24          	mov    QWORD PTR [rsp],rbx
    7ffff7fb48ab:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb48b0:	48 8b 74 24 08       	mov    rsi,QWORD PTR [rsp+0x8]
    7ffff7fb48b5:	e9 11 ff ff ff       	jmp    0x7ffff7fb47cb
    7ffff7fb48ba:	49 81 fe 00 10 00 00 	cmp    r14,0x1000
    7ffff7fb48c1:	b9 ff 0f 00 00       	mov    ecx,0xfff
    7ffff7fb48c6:	49 0f 43 ce          	cmovae rcx,r14
    7ffff7fb48ca:	48 89 0d 47 46 00 00 	mov    QWORD PTR [rip+0x4647],rcx        # 0x7ffff7fb8f18
    7ffff7fb48d1:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb48d5:	5b                   	pop    rbx
    7ffff7fb48d6:	41 5c                	pop    r12
    7ffff7fb48d8:	41 5d                	pop    r13
    7ffff7fb48da:	41 5e                	pop    r14
    7ffff7fb48dc:	41 5f                	pop    r15
    7ffff7fb48de:	5d                   	pop    rbp
    7ffff7fb48df:	c3                   	ret
    7ffff7fb48e0:	48 8d 47 1f          	lea    rax,[rdi+0x1f]
    7ffff7fb48e4:	48 83 e0 f0          	and    rax,0xfffffffffffffff0
    7ffff7fb48e8:	48 8d 48 f0          	lea    rcx,[rax-0x10]
    7ffff7fb48ec:	48 89 fa             	mov    rdx,rdi
    7ffff7fb48ef:	48 29 c2             	sub    rdx,rax
    7ffff7fb48f2:	48 01 f2             	add    rdx,rsi
    7ffff7fb48f5:	48 83 c2 10          	add    rdx,0x10
    7ffff7fb48f9:	48 89 0d f0 45 00 00 	mov    QWORD PTR [rip+0x45f0],rcx        # 0x7ffff7fb8ef0
    7ffff7fb4900:	48 89 15 d9 45 00 00 	mov    QWORD PTR [rip+0x45d9],rdx        # 0x7ffff7fb8ee0
    7ffff7fb4907:	48 83 ca 01          	or     rdx,0x1
    7ffff7fb490b:	48 89 50 f8          	mov    QWORD PTR [rax-0x8],rdx
    7ffff7fb490f:	48 c7 44 37 08 50 00 	mov    QWORD PTR [rdi+rsi*1+0x8],0x50
    7ffff7fb4916:	00 00 
    7ffff7fb4918:	48 c7 05 e5 45 00 00 	mov    QWORD PTR [rip+0x45e5],0x200000        # 0x7ffff7fb8f08
    7ffff7fb491f:	00 00 20 00 
    7ffff7fb4923:	c3                   	ret
    7ffff7fb4924:	41 56                	push   r14
    7ffff7fb4926:	53                   	push   rbx
    7ffff7fb4927:	50                   	push   rax
    7ffff7fb4928:	49 89 f6             	mov    r14,rsi
    7ffff7fb492b:	48 89 fb             	mov    rbx,rdi
    7ffff7fb492e:	48 89 f7             	mov    rdi,rsi
    7ffff7fb4931:	e8 87 14 00 00       	call   0x7ffff7fb5dbd
    7ffff7fb4936:	89 c1                	mov    ecx,eax
    7ffff7fb4938:	48 8d 15 69 42 00 00 	lea    rdx,[rip+0x4269]        # 0x7ffff7fb8ba8
    7ffff7fb493f:	48 8d 0c ca          	lea    rcx,[rdx+rcx*8]
    7ffff7fb4943:	89 43 38             	mov    DWORD PTR [rbx+0x38],eax
    7ffff7fb4946:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb494a:	c5 f8 11 43 20       	vmovups XMMWORD PTR [rbx+0x20],xmm0
    7ffff7fb494f:	8b 15 cf 45 00 00    	mov    edx,DWORD PTR [rip+0x45cf]        # 0x7ffff7fb8f24
    7ffff7fb4955:	0f a3 c2             	bt     edx,eax
    7ffff7fb4958:	73 59                	jae    0x7ffff7fb49b3
    7ffff7fb495a:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
    7ffff7fb495d:	89 c2                	mov    edx,eax
    7ffff7fb495f:	d0 ea                	shr    dl,1
    7ffff7fb4961:	40 b6 39             	mov    sil,0x39
    7ffff7fb4964:	40 28 d6             	sub    sil,dl
    7ffff7fb4967:	40 80 e6 3f          	and    sil,0x3f
    7ffff7fb496b:	31 d2                	xor    edx,edx
    7ffff7fb496d:	83 f8 1f             	cmp    eax,0x1f
    7ffff7fb4970:	40 0f b6 c6          	movzx  eax,sil
    7ffff7fb4974:	0f 44 c2             	cmove  eax,edx
    7ffff7fb4977:	c4 c2 f9 f7 d6       	shlx   rdx,r14,rax
    7ffff7fb497c:	48 89 c8             	mov    rax,rcx
    7ffff7fb497f:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
    7ffff7fb4983:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb4987:	4c 39 f1             	cmp    rcx,r14
    7ffff7fb498a:	74 48                	je     0x7ffff7fb49d4
    7ffff7fb498c:	48 89 d6             	mov    rsi,rdx
    7ffff7fb498f:	48 c1 ee 3f          	shr    rsi,0x3f
    7ffff7fb4993:	48 8b 4c f0 20       	mov    rcx,QWORD PTR [rax+rsi*8+0x20]
    7ffff7fb4998:	48 01 d2             	add    rdx,rdx
    7ffff7fb499b:	48 85 c9             	test   rcx,rcx
    7ffff7fb499e:	75 dc                	jne    0x7ffff7fb497c
    7ffff7fb49a0:	48 8d 48 20          	lea    rcx,[rax+0x20]
    7ffff7fb49a4:	48 8d 0c f1          	lea    rcx,[rcx+rsi*8]
    7ffff7fb49a8:	6a 10                	push   0x10
    7ffff7fb49aa:	5a                   	pop    rdx
    7ffff7fb49ab:	6a 30                	push   0x30
    7ffff7fb49ad:	5e                   	pop    rsi
    7ffff7fb49ae:	48 89 c7             	mov    rdi,rax
    7ffff7fb49b1:	eb 19                	jmp    0x7ffff7fb49cc
    7ffff7fb49b3:	6a 01                	push   0x1
    7ffff7fb49b5:	5e                   	pop    rsi
    7ffff7fb49b6:	c4 e2 79 f7 c6       	shlx   eax,esi,eax
    7ffff7fb49bb:	09 c2                	or     edx,eax
    7ffff7fb49bd:	89 15 61 45 00 00    	mov    DWORD PTR [rip+0x4561],edx        # 0x7ffff7fb8f24
    7ffff7fb49c3:	6a 10                	push   0x10
    7ffff7fb49c5:	5a                   	pop    rdx
    7ffff7fb49c6:	6a 30                	push   0x30
    7ffff7fb49c8:	5e                   	pop    rsi
    7ffff7fb49c9:	48 89 cf             	mov    rdi,rcx
    7ffff7fb49cc:	48 89 d8             	mov    rax,rbx
    7ffff7fb49cf:	49 89 d8             	mov    r8,rbx
    7ffff7fb49d2:	eb 15                	jmp    0x7ffff7fb49e9
    7ffff7fb49d4:	48 8d 48 10          	lea    rcx,[rax+0x10]
    7ffff7fb49d8:	48 8b 78 10          	mov    rdi,QWORD PTR [rax+0x10]
    7ffff7fb49dc:	48 89 5f 18          	mov    QWORD PTR [rdi+0x18],rbx
    7ffff7fb49e0:	6a 30                	push   0x30
    7ffff7fb49e2:	5a                   	pop    rdx
    7ffff7fb49e3:	6a 10                	push   0x10
    7ffff7fb49e5:	5e                   	pop    rsi
    7ffff7fb49e6:	45 31 c0             	xor    r8d,r8d
    7ffff7fb49e9:	48 89 19             	mov    QWORD PTR [rcx],rbx
    7ffff7fb49ec:	48 89 3c 33          	mov    QWORD PTR [rbx+rsi*1],rdi
    7ffff7fb49f0:	48 89 43 18          	mov    QWORD PTR [rbx+0x18],rax
    7ffff7fb49f4:	4c 89 04 13          	mov    QWORD PTR [rbx+rdx*1],r8
    7ffff7fb49f8:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb49fc:	5b                   	pop    rbx
    7ffff7fb49fd:	41 5e                	pop    r14
    7ffff7fb49ff:	c3                   	ret
    7ffff7fb4a00:	48 b8 f8 ff ff ff 07 	movabs rax,0x7fffffff8
    7ffff7fb4a07:	00 00 00 
    7ffff7fb4a0a:	48 21 f0             	and    rax,rsi
    7ffff7fb4a0d:	48 8d 0d 94 41 00 00 	lea    rcx,[rip+0x4194]        # 0x7ffff7fb8ba8
    7ffff7fb4a14:	48 8d 04 41          	lea    rax,[rcx+rax*2]
    7ffff7fb4a18:	48 05 20 01 00 00    	add    rax,0x120
    7ffff7fb4a1e:	8b 0d fc 44 00 00    	mov    ecx,DWORD PTR [rip+0x44fc]        # 0x7ffff7fb8f20
    7ffff7fb4a24:	40 c0 ee 03          	shr    sil,0x3
    7ffff7fb4a28:	40 0f b6 d6          	movzx  edx,sil
    7ffff7fb4a2c:	0f a3 d1             	bt     ecx,edx
    7ffff7fb4a2f:	73 06                	jae    0x7ffff7fb4a37
    7ffff7fb4a31:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
    7ffff7fb4a35:	eb 13                	jmp    0x7ffff7fb4a4a
    7ffff7fb4a37:	6a 01                	push   0x1
    7ffff7fb4a39:	5a                   	pop    rdx
    7ffff7fb4a3a:	c4 e2 49 f7 d2       	shlx   edx,edx,esi
    7ffff7fb4a3f:	09 d1                	or     ecx,edx
    7ffff7fb4a41:	89 0d d9 44 00 00    	mov    DWORD PTR [rip+0x44d9],ecx        # 0x7ffff7fb8f20
    7ffff7fb4a47:	48 89 c1             	mov    rcx,rax
    7ffff7fb4a4a:	48 89 78 10          	mov    QWORD PTR [rax+0x10],rdi
    7ffff7fb4a4e:	48 89 79 18          	mov    QWORD PTR [rcx+0x18],rdi
    7ffff7fb4a52:	48 89 4f 10          	mov    QWORD PTR [rdi+0x10],rcx
    7ffff7fb4a56:	48 89 47 18          	mov    QWORD PTR [rdi+0x18],rax
    7ffff7fb4a5a:	c3                   	ret
    7ffff7fb4a5b:	48 8b 4f 18          	mov    rcx,QWORD PTR [rdi+0x18]
    7ffff7fb4a5f:	48 8b 47 30          	mov    rax,QWORD PTR [rdi+0x30]
    7ffff7fb4a63:	48 39 f9             	cmp    rcx,rdi
    7ffff7fb4a66:	74 0e                	je     0x7ffff7fb4a76
    7ffff7fb4a68:	48 8b 57 10          	mov    rdx,QWORD PTR [rdi+0x10]
    7ffff7fb4a6c:	48 89 4a 18          	mov    QWORD PTR [rdx+0x18],rcx
    7ffff7fb4a70:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
    7ffff7fb4a74:	eb 4b                	jmp    0x7ffff7fb4ac1
    7ffff7fb4a76:	48 8d 57 28          	lea    rdx,[rdi+0x28]
    7ffff7fb4a7a:	48 8d 4f 20          	lea    rcx,[rdi+0x20]
    7ffff7fb4a7e:	31 f6                	xor    esi,esi
    7ffff7fb4a80:	48 83 7f 28 00       	cmp    QWORD PTR [rdi+0x28],0x0
    7ffff7fb4a85:	40 0f 95 c6          	setne  sil
    7ffff7fb4a89:	48 0f 44 d1          	cmove  rdx,rcx
    7ffff7fb4a8d:	48 8b 74 f7 20       	mov    rsi,QWORD PTR [rdi+rsi*8+0x20]
    7ffff7fb4a92:	48 85 f6             	test   rsi,rsi
    7ffff7fb4a95:	74 28                	je     0x7ffff7fb4abf
    7ffff7fb4a97:	49 89 d0             	mov    r8,rdx
    7ffff7fb4a9a:	48 89 f1             	mov    rcx,rsi
    7ffff7fb4a9d:	48 8b 76 28          	mov    rsi,QWORD PTR [rsi+0x28]
    7ffff7fb4aa1:	48 85 f6             	test   rsi,rsi
    7ffff7fb4aa4:	74 06                	je     0x7ffff7fb4aac
    7ffff7fb4aa6:	48 8d 51 28          	lea    rdx,[rcx+0x28]
    7ffff7fb4aaa:	eb 08                	jmp    0x7ffff7fb4ab4
    7ffff7fb4aac:	48 8d 51 20          	lea    rdx,[rcx+0x20]
    7ffff7fb4ab0:	48 8b 71 20          	mov    rsi,QWORD PTR [rcx+0x20]
    7ffff7fb4ab4:	48 85 f6             	test   rsi,rsi
    7ffff7fb4ab7:	75 de                	jne    0x7ffff7fb4a97
    7ffff7fb4ab9:	49 83 20 00          	and    QWORD PTR [r8],0x0
    7ffff7fb4abd:	eb 02                	jmp    0x7ffff7fb4ac1
    7ffff7fb4abf:	31 c9                	xor    ecx,ecx
    7ffff7fb4ac1:	48 85 c0             	test   rax,rax
    7ffff7fb4ac4:	74 23                	je     0x7ffff7fb4ae9
    7ffff7fb4ac6:	8b 57 38             	mov    edx,DWORD PTR [rdi+0x38]
    7ffff7fb4ac9:	48 8d 35 d8 40 00 00 	lea    rsi,[rip+0x40d8]        # 0x7ffff7fb8ba8
    7ffff7fb4ad0:	48 39 3c d6          	cmp    QWORD PTR [rsi+rdx*8],rdi
    7ffff7fb4ad4:	74 14                	je     0x7ffff7fb4aea
    7ffff7fb4ad6:	31 d2                	xor    edx,edx
    7ffff7fb4ad8:	48 39 78 20          	cmp    QWORD PTR [rax+0x20],rdi
    7ffff7fb4adc:	0f 95 c2             	setne  dl
    7ffff7fb4adf:	48 89 4c d0 20       	mov    QWORD PTR [rax+rdx*8+0x20],rcx
    7ffff7fb4ae4:	48 85 c9             	test   rcx,rcx
    7ffff7fb4ae7:	75 0a                	jne    0x7ffff7fb4af3
    7ffff7fb4ae9:	c3                   	ret
    7ffff7fb4aea:	48 89 0c d6          	mov    QWORD PTR [rsi+rdx*8],rcx
    7ffff7fb4aee:	48 85 c9             	test   rcx,rcx
    7ffff7fb4af1:	74 27                	je     0x7ffff7fb4b1a
    7ffff7fb4af3:	48 89 41 30          	mov    QWORD PTR [rcx+0x30],rax
    7ffff7fb4af7:	48 8b 47 20          	mov    rax,QWORD PTR [rdi+0x20]
    7ffff7fb4afb:	48 85 c0             	test   rax,rax
    7ffff7fb4afe:	74 08                	je     0x7ffff7fb4b08
    7ffff7fb4b00:	48 89 41 20          	mov    QWORD PTR [rcx+0x20],rax
    7ffff7fb4b04:	48 89 48 30          	mov    QWORD PTR [rax+0x30],rcx
    7ffff7fb4b08:	48 8b 47 28          	mov    rax,QWORD PTR [rdi+0x28]
    7ffff7fb4b0c:	48 85 c0             	test   rax,rax
    7ffff7fb4b0f:	74 d8                	je     0x7ffff7fb4ae9
    7ffff7fb4b11:	48 89 41 28          	mov    QWORD PTR [rcx+0x28],rax
    7ffff7fb4b15:	48 89 48 30          	mov    QWORD PTR [rax+0x30],rcx
    7ffff7fb4b19:	c3                   	ret
    7ffff7fb4b1a:	8a 4f 38             	mov    cl,BYTE PTR [rdi+0x38]
    7ffff7fb4b1d:	6a fe                	push   0xfffffffffffffffe
    7ffff7fb4b1f:	58                   	pop    rax
    7ffff7fb4b20:	d3 c0                	rol    eax,cl
    7ffff7fb4b22:	21 05 fc 43 00 00    	and    DWORD PTR [rip+0x43fc],eax        # 0x7ffff7fb8f24
    7ffff7fb4b28:	c3                   	ret
    7ffff7fb4b29:	48 81 fe 00 01 00 00 	cmp    rsi,0x100
    7ffff7fb4b30:	0f 82 ca fe ff ff    	jb     0x7ffff7fb4a00
    7ffff7fb4b36:	e9 e9 fd ff ff       	jmp    0x7ffff7fb4924
    7ffff7fb4b3b:	48 39 fe             	cmp    rsi,rdi
    7ffff7fb4b3e:	74 09                	je     0x7ffff7fb4b49
    7ffff7fb4b40:	48 89 7e 18          	mov    QWORD PTR [rsi+0x18],rdi
    7ffff7fb4b44:	48 89 77 10          	mov    QWORD PTR [rdi+0x10],rsi
    7ffff7fb4b48:	c3                   	ret
    7ffff7fb4b49:	6a fe                	push   0xfffffffffffffffe
    7ffff7fb4b4b:	58                   	pop    rax
    7ffff7fb4b4c:	89 d1                	mov    ecx,edx
    7ffff7fb4b4e:	d3 c0                	rol    eax,cl
    7ffff7fb4b50:	21 05 ca 43 00 00    	and    DWORD PTR [rip+0x43ca],eax        # 0x7ffff7fb8f20
    7ffff7fb4b56:	c3                   	ret
    7ffff7fb4b57:	41 56                	push   r14
    7ffff7fb4b59:	53                   	push   rbx
    7ffff7fb4b5a:	50                   	push   rax
    7ffff7fb4b5b:	49 89 f6             	mov    r14,rsi
    7ffff7fb4b5e:	48 89 fb             	mov    rbx,rdi
    7ffff7fb4b61:	48 8b 35 70 43 00 00 	mov    rsi,QWORD PTR [rip+0x4370]        # 0x7ffff7fb8ed8
    7ffff7fb4b68:	48 85 f6             	test   rsi,rsi
    7ffff7fb4b6b:	74 0c                	je     0x7ffff7fb4b79
    7ffff7fb4b6d:	48 8b 3d 74 43 00 00 	mov    rdi,QWORD PTR [rip+0x4374]        # 0x7ffff7fb8ee8
    7ffff7fb4b74:	e8 87 fe ff ff       	call   0x7ffff7fb4a00
    7ffff7fb4b79:	4c 89 35 58 43 00 00 	mov    QWORD PTR [rip+0x4358],r14        # 0x7ffff7fb8ed8
    7ffff7fb4b80:	48 89 1d 61 43 00 00 	mov    QWORD PTR [rip+0x4361],rbx        # 0x7ffff7fb8ee8
    7ffff7fb4b87:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb4b8b:	5b                   	pop    rbx
    7ffff7fb4b8c:	41 5e                	pop    r14
    7ffff7fb4b8e:	c3                   	ret
    7ffff7fb4b8f:	48 89 f8             	mov    rax,rdi
    7ffff7fb4b92:	48 89 f7             	mov    rdi,rsi
    7ffff7fb4b95:	48 89 c6             	mov    rsi,rax
    7ffff7fb4b98:	e9 fe 03 00 00       	jmp    0x7ffff7fb4f9b
    7ffff7fb4b9d:	e9 58 0e 00 00       	jmp    0x7ffff7fb59fa
    7ffff7fb4ba2:	55                   	push   rbp
    7ffff7fb4ba3:	41 57                	push   r15
    7ffff7fb4ba5:	41 56                	push   r14
    7ffff7fb4ba7:	41 55                	push   r13
    7ffff7fb4ba9:	41 54                	push   r12
    7ffff7fb4bab:	53                   	push   rbx
    7ffff7fb4bac:	50                   	push   rax
    7ffff7fb4bad:	49 89 ce             	mov    r14,rcx
    7ffff7fb4bb0:	48 89 fb             	mov    rbx,rdi
    7ffff7fb4bb3:	48 83 fa 11          	cmp    rdx,0x11
    7ffff7fb4bb7:	0f 83 b2 00 00 00    	jae    0x7ffff7fb4c6f
    7ffff7fb4bbd:	49 81 fe 98 ff fe ff 	cmp    r14,0xfffffffffffeff98
    7ffff7fb4bc4:	0f 87 e5 01 00 00    	ja     0x7ffff7fb4daf
    7ffff7fb4bca:	49 8d 46 17          	lea    rax,[r14+0x17]
    7ffff7fb4bce:	48 83 e0 f0          	and    rax,0xfffffffffffffff0
    7ffff7fb4bd2:	49 83 fe 17          	cmp    r14,0x17
    7ffff7fb4bd6:	6a 20                	push   0x20
    7ffff7fb4bd8:	5d                   	pop    rbp
    7ffff7fb4bd9:	48 0f 43 e8          	cmovae rbp,rax
    7ffff7fb4bdd:	48 8b 43 f8          	mov    rax,QWORD PTR [rbx-0x8]
    7ffff7fb4be1:	49 89 c5             	mov    r13,rax
    7ffff7fb4be4:	49 83 e5 f8          	and    r13,0xfffffffffffffff8
    7ffff7fb4be8:	a8 03                	test   al,0x3
    7ffff7fb4bea:	0f 84 bf 00 00 00    	je     0x7ffff7fb4caf
    7ffff7fb4bf0:	4c 8d 7b f0          	lea    r15,[rbx-0x10]
    7ffff7fb4bf4:	4a 8d 3c 2b          	lea    rdi,[rbx+r13*1]
    7ffff7fb4bf8:	48 83 c7 f0          	add    rdi,0xfffffffffffffff0
    7ffff7fb4bfc:	4c 89 ee             	mov    rsi,r13
    7ffff7fb4bff:	48 29 ee             	sub    rsi,rbp
    7ffff7fb4c02:	0f 83 db 00 00 00    	jae    0x7ffff7fb4ce3
    7ffff7fb4c08:	48 3b 3d b1 46 00 00 	cmp    rdi,QWORD PTR [rip+0x46b1]        # 0x7ffff7fb92c0
    7ffff7fb4c0f:	0f 84 06 01 00 00    	je     0x7ffff7fb4d1b
    7ffff7fb4c15:	48 3b 3d 9c 46 00 00 	cmp    rdi,QWORD PTR [rip+0x469c]        # 0x7ffff7fb92b8
    7ffff7fb4c1c:	0f 84 32 01 00 00    	je     0x7ffff7fb4d54
    7ffff7fb4c22:	48 8b 77 08          	mov    rsi,QWORD PTR [rdi+0x8]
    7ffff7fb4c26:	40 f6 c6 02          	test   sil,0x2
    7ffff7fb4c2a:	0f 85 33 01 00 00    	jne    0x7ffff7fb4d63
    7ffff7fb4c30:	48 83 e6 f8          	and    rsi,0xfffffffffffffff8
    7ffff7fb4c34:	49 01 f5             	add    r13,rsi
    7ffff7fb4c37:	4d 89 ec             	mov    r12,r13
    7ffff7fb4c3a:	49 29 ec             	sub    r12,rbp
    7ffff7fb4c3d:	0f 82 20 01 00 00    	jb     0x7ffff7fb4d63
    7ffff7fb4c43:	e8 86 04 00 00       	call   0x7ffff7fb50ce
    7ffff7fb4c48:	49 83 fc 20          	cmp    r12,0x20
    7ffff7fb4c4c:	0f 83 ca 01 00 00    	jae    0x7ffff7fb4e1c
    7ffff7fb4c52:	48 8b 43 f8          	mov    rax,QWORD PTR [rbx-0x8]
    7ffff7fb4c56:	83 e0 01             	and    eax,0x1
    7ffff7fb4c59:	4c 01 e8             	add    rax,r13
    7ffff7fb4c5c:	48 83 c0 02          	add    rax,0x2
    7ffff7fb4c60:	48 89 43 f8          	mov    QWORD PTR [rbx-0x8],rax
    7ffff7fb4c64:	42 80 4c 2b f8 01    	or     BYTE PTR [rbx+r13*1-0x8],0x1
    7ffff7fb4c6a:	e9 42 01 00 00       	jmp    0x7ffff7fb4db1
    7ffff7fb4c6f:	49 89 f7             	mov    r15,rsi
    7ffff7fb4c72:	48 89 d7             	mov    rdi,rdx
    7ffff7fb4c75:	4c 89 f6             	mov    rsi,r14
    7ffff7fb4c78:	e8 1e 03 00 00       	call   0x7ffff7fb4f9b
    7ffff7fb4c7d:	48 85 c0             	test   rax,rax
    7ffff7fb4c80:	0f 84 29 01 00 00    	je     0x7ffff7fb4daf
    7ffff7fb4c86:	49 89 c4             	mov    r12,rax
    7ffff7fb4c89:	4d 39 f7             	cmp    r15,r14
    7ffff7fb4c8c:	4d 0f 42 f7          	cmovb  r14,r15
    7ffff7fb4c90:	48 89 c7             	mov    rdi,rax
    7ffff7fb4c93:	48 89 de             	mov    rsi,rbx
    7ffff7fb4c96:	4c 89 f2             	mov    rdx,r14
    7ffff7fb4c99:	ff 15 c9 3e 00 00    	call   QWORD PTR [rip+0x3ec9]        # 0x7ffff7fb8b68
    7ffff7fb4c9f:	48 89 df             	mov    rdi,rbx
    7ffff7fb4ca2:	e8 53 0d 00 00       	call   0x7ffff7fb59fa
    7ffff7fb4ca7:	4c 89 e3             	mov    rbx,r12
    7ffff7fb4caa:	e9 02 01 00 00       	jmp    0x7ffff7fb4db1
    7ffff7fb4caf:	48 81 fd 00 01 00 00 	cmp    rbp,0x100
    7ffff7fb4cb6:	0f 82 a7 00 00 00    	jb     0x7ffff7fb4d63
    7ffff7fb4cbc:	48 89 e8             	mov    rax,rbp
    7ffff7fb4cbf:	48 83 c8 08          	or     rax,0x8
    7ffff7fb4cc3:	49 39 c5             	cmp    r13,rax
    7ffff7fb4cc6:	0f 93 c0             	setae  al
    7ffff7fb4cc9:	49 29 ed             	sub    r13,rbp
    7ffff7fb4ccc:	49 81 fd 01 00 02 00 	cmp    r13,0x20001
    7ffff7fb4cd3:	0f 92 c1             	setb   cl
    7ffff7fb4cd6:	84 c8                	test   al,cl
    7ffff7fb4cd8:	0f 84 85 00 00 00    	je     0x7ffff7fb4d63
    7ffff7fb4cde:	e9 ce 00 00 00       	jmp    0x7ffff7fb4db1
    7ffff7fb4ce3:	48 83 fe 20          	cmp    rsi,0x20
    7ffff7fb4ce7:	0f 82 c4 00 00 00    	jb     0x7ffff7fb4db1
    7ffff7fb4ced:	49 01 ef             	add    r15,rbp
    7ffff7fb4cf0:	83 e0 01             	and    eax,0x1
    7ffff7fb4cf3:	48 01 e8             	add    rax,rbp
    7ffff7fb4cf6:	48 83 c0 02          	add    rax,0x2
    7ffff7fb4cfa:	48 89 43 f8          	mov    QWORD PTR [rbx-0x8],rax
    7ffff7fb4cfe:	48 89 f0             	mov    rax,rsi
    7ffff7fb4d01:	48 83 c8 03          	or     rax,0x3
    7ffff7fb4d05:	48 89 44 2b f8       	mov    QWORD PTR [rbx+rbp*1-0x8],rax
    7ffff7fb4d0a:	80 4f 08 01          	or     BYTE PTR [rdi+0x8],0x1
    7ffff7fb4d0e:	4c 89 ff             	mov    rdi,r15
    7ffff7fb4d11:	e8 ed 03 00 00       	call   0x7ffff7fb5103
    7ffff7fb4d16:	e9 96 00 00 00       	jmp    0x7ffff7fb4db1
    7ffff7fb4d1b:	4c 03 2d 8e 45 00 00 	add    r13,QWORD PTR [rip+0x458e]        # 0x7ffff7fb92b0
    7ffff7fb4d22:	49 29 ed             	sub    r13,rbp
    7ffff7fb4d25:	76 3c                	jbe    0x7ffff7fb4d63
    7ffff7fb4d27:	49 01 ef             	add    r15,rbp
    7ffff7fb4d2a:	83 e0 01             	and    eax,0x1
    7ffff7fb4d2d:	48 01 e8             	add    rax,rbp
    7ffff7fb4d30:	48 83 c0 02          	add    rax,0x2
    7ffff7fb4d34:	48 89 43 f8          	mov    QWORD PTR [rbx-0x8],rax
    7ffff7fb4d38:	4c 89 e8             	mov    rax,r13
    7ffff7fb4d3b:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4d3f:	48 89 44 2b f8       	mov    QWORD PTR [rbx+rbp*1-0x8],rax
    7ffff7fb4d44:	4c 89 3d 75 45 00 00 	mov    QWORD PTR [rip+0x4575],r15        # 0x7ffff7fb92c0
    7ffff7fb4d4b:	4c 89 2d 5e 45 00 00 	mov    QWORD PTR [rip+0x455e],r13        # 0x7ffff7fb92b0
    7ffff7fb4d52:	eb 5d                	jmp    0x7ffff7fb4db1
    7ffff7fb4d54:	4c 03 2d 4d 45 00 00 	add    r13,QWORD PTR [rip+0x454d]        # 0x7ffff7fb92a8
    7ffff7fb4d5b:	4c 89 e9             	mov    rcx,r13
    7ffff7fb4d5e:	48 29 e9             	sub    rcx,rbp
    7ffff7fb4d61:	73 60                	jae    0x7ffff7fb4dc3
    7ffff7fb4d63:	4c 89 f7             	mov    rdi,r14
    7ffff7fb4d66:	e8 2f 05 00 00       	call   0x7ffff7fb529a
    7ffff7fb4d6b:	48 85 c0             	test   rax,rax
    7ffff7fb4d6e:	74 3f                	je     0x7ffff7fb4daf
    7ffff7fb4d70:	49 89 c7             	mov    r15,rax
    7ffff7fb4d73:	48 8b 43 f8          	mov    rax,QWORD PTR [rbx-0x8]
    7ffff7fb4d77:	48 89 c1             	mov    rcx,rax
    7ffff7fb4d7a:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb4d7e:	31 d2                	xor    edx,edx
    7ffff7fb4d80:	a8 03                	test   al,0x3
    7ffff7fb4d82:	0f 95 c2             	setne  dl
    7ffff7fb4d85:	c1 e2 03             	shl    edx,0x3
    7ffff7fb4d88:	48 83 ca f0          	or     rdx,0xfffffffffffffff0
    7ffff7fb4d8c:	48 01 ca             	add    rdx,rcx
    7ffff7fb4d8f:	4c 39 f2             	cmp    rdx,r14
    7ffff7fb4d92:	49 0f 43 d6          	cmovae rdx,r14
    7ffff7fb4d96:	4c 89 ff             	mov    rdi,r15
    7ffff7fb4d99:	48 89 de             	mov    rsi,rbx
    7ffff7fb4d9c:	ff 15 c6 3d 00 00    	call   QWORD PTR [rip+0x3dc6]        # 0x7ffff7fb8b68
    7ffff7fb4da2:	48 89 df             	mov    rdi,rbx
    7ffff7fb4da5:	e8 50 0c 00 00       	call   0x7ffff7fb59fa
    7ffff7fb4daa:	4c 89 fb             	mov    rbx,r15
    7ffff7fb4dad:	eb 02                	jmp    0x7ffff7fb4db1
    7ffff7fb4daf:	31 db                	xor    ebx,ebx
    7ffff7fb4db1:	48 89 d8             	mov    rax,rbx
    7ffff7fb4db4:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb4db8:	5b                   	pop    rbx
    7ffff7fb4db9:	41 5c                	pop    r12
    7ffff7fb4dbb:	41 5d                	pop    r13
    7ffff7fb4dbd:	41 5e                	pop    r14
    7ffff7fb4dbf:	41 5f                	pop    r15
    7ffff7fb4dc1:	5d                   	pop    rbp
    7ffff7fb4dc2:	c3                   	ret
    7ffff7fb4dc3:	48 83 f9 1f          	cmp    rcx,0x1f
    7ffff7fb4dc7:	77 1b                	ja     0x7ffff7fb4de4
    7ffff7fb4dc9:	83 e0 01             	and    eax,0x1
    7ffff7fb4dcc:	4c 09 e8             	or     rax,r13
    7ffff7fb4dcf:	48 83 c8 02          	or     rax,0x2
    7ffff7fb4dd3:	48 89 43 f8          	mov    QWORD PTR [rbx-0x8],rax
    7ffff7fb4dd7:	42 80 4c 2b f8 01    	or     BYTE PTR [rbx+r13*1-0x8],0x1
    7ffff7fb4ddd:	31 c9                	xor    ecx,ecx
    7ffff7fb4ddf:	45 31 ff             	xor    r15d,r15d
    7ffff7fb4de2:	eb 28                	jmp    0x7ffff7fb4e0c
    7ffff7fb4de4:	49 01 ef             	add    r15,rbp
    7ffff7fb4de7:	83 e0 01             	and    eax,0x1
    7ffff7fb4dea:	48 01 e8             	add    rax,rbp
    7ffff7fb4ded:	48 83 c0 02          	add    rax,0x2
    7ffff7fb4df1:	48 89 43 f8          	mov    QWORD PTR [rbx-0x8],rax
    7ffff7fb4df5:	48 89 c8             	mov    rax,rcx
    7ffff7fb4df8:	48 83 c8 01          	or     rax,0x1
    7ffff7fb4dfc:	48 89 44 2b f8       	mov    QWORD PTR [rbx+rbp*1-0x8],rax
    7ffff7fb4e01:	4a 89 4c 2b f0       	mov    QWORD PTR [rbx+r13*1-0x10],rcx
    7ffff7fb4e06:	42 80 64 2b f8 fe    	and    BYTE PTR [rbx+r13*1-0x8],0xfe
    7ffff7fb4e0c:	48 89 0d 95 44 00 00 	mov    QWORD PTR [rip+0x4495],rcx        # 0x7ffff7fb92a8
    7ffff7fb4e13:	4c 89 3d 9e 44 00 00 	mov    QWORD PTR [rip+0x449e],r15        # 0x7ffff7fb92b8
    7ffff7fb4e1a:	eb 95                	jmp    0x7ffff7fb4db1
    7ffff7fb4e1c:	49 01 ef             	add    r15,rbp
    7ffff7fb4e1f:	48 8b 43 f8          	mov    rax,QWORD PTR [rbx-0x8]
    7ffff7fb4e23:	83 e0 01             	and    eax,0x1
    7ffff7fb4e26:	48 01 e8             	add    rax,rbp
    7ffff7fb4e29:	48 83 c0 02          	add    rax,0x2
    7ffff7fb4e2d:	48 89 43 f8          	mov    QWORD PTR [rbx-0x8],rax
    7ffff7fb4e31:	4c 89 e0             	mov    rax,r12
    7ffff7fb4e34:	48 83 c8 03          	or     rax,0x3
    7ffff7fb4e38:	48 89 44 2b f8       	mov    QWORD PTR [rbx+rbp*1-0x8],rax
    7ffff7fb4e3d:	42 80 4c 2b f8 01    	or     BYTE PTR [rbx+r13*1-0x8],0x1
    7ffff7fb4e43:	4c 89 ff             	mov    rdi,r15
    7ffff7fb4e46:	4c 89 e6             	mov    rsi,r12
    7ffff7fb4e49:	e9 c3 fe ff ff       	jmp    0x7ffff7fb4d11
    7ffff7fb4e4e:	41 57                	push   r15
    7ffff7fb4e50:	41 56                	push   r14
    7ffff7fb4e52:	56                   	push   rsi
    7ffff7fb4e53:	57                   	push   rdi
    7ffff7fb4e54:	53                   	push   rbx
    7ffff7fb4e55:	48 83 ec 50          	sub    rsp,0x50
    7ffff7fb4e59:	4c 89 c3             	mov    rbx,r8
    7ffff7fb4e5c:	49 89 d6             	mov    r14,rdx
    7ffff7fb4e5f:	48 89 ce             	mov    rsi,rcx
    7ffff7fb4e62:	4c 8d 3d bf 40 00 00 	lea    r15,[rip+0x40bf]        # 0x7ffff7fb8f28
    7ffff7fb4e69:	6a f6                	push   0xfffffffffffffff6
    7ffff7fb4e6b:	59                   	pop    rcx
    7ffff7fb4e6c:	ff 15 c6 40 00 00    	call   QWORD PTR [rip+0x40c6]        # 0x7ffff7fb8f38
    7ffff7fb4e72:	4c 8d 4c 24 2c       	lea    r9,[rsp+0x2c]
    7ffff7fb4e77:	41 83 21 00          	and    DWORD PTR [r9],0x0
    7ffff7fb4e7b:	48 89 c7             	mov    rdi,rax
    7ffff7fb4e7e:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb4e82:	48 8d 44 24 30       	lea    rax,[rsp+0x30]
    7ffff7fb4e87:	c5 fc 11 00          	vmovups YMMWORD PTR [rax],ymm0
    7ffff7fb4e8b:	49 8b 4c f7 38       	mov    rcx,QWORD PTR [r15+rsi*8+0x38]
    7ffff7fb4e90:	48 89 48 10          	mov    QWORD PTR [rax+0x10],rcx
    7ffff7fb4e94:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
    7ffff7fb4e99:	48 89 f9             	mov    rcx,rdi
    7ffff7fb4e9c:	4c 89 f2             	mov    rdx,r14
    7ffff7fb4e9f:	41 89 d8             	mov    r8d,ebx
    7ffff7fb4ea2:	c5 f8 77             	vzeroupper
    7ffff7fb4ea5:	ff 15 95 40 00 00    	call   QWORD PTR [rip+0x4095]        # 0x7ffff7fb8f40
    7ffff7fb4eab:	85 c0                	test   eax,eax
    7ffff7fb4ead:	75 2c                	jne    0x7ffff7fb4edb
    7ffff7fb4eaf:	ff 15 a3 40 00 00    	call   QWORD PTR [rip+0x40a3]        # 0x7ffff7fb8f58
    7ffff7fb4eb5:	3d e5 03 00 00       	cmp    eax,0x3e5
    7ffff7fb4eba:	75 1f                	jne    0x7ffff7fb4edb
    7ffff7fb4ebc:	48 8d 54 24 30       	lea    rdx,[rsp+0x30]
    7ffff7fb4ec1:	4c 8d 44 24 2c       	lea    r8,[rsp+0x2c]
    7ffff7fb4ec6:	6a 01                	push   0x1
    7ffff7fb4ec8:	41 59                	pop    r9
    7ffff7fb4eca:	48 89 f9             	mov    rcx,rdi
    7ffff7fb4ecd:	ff 15 7d 40 00 00    	call   QWORD PTR [rip+0x407d]        # 0x7ffff7fb8f50
    7ffff7fb4ed3:	85 c0                	test   eax,eax
    7ffff7fb4ed5:	74 04                	je     0x7ffff7fb4edb
    7ffff7fb4ed7:	31 c0                	xor    eax,eax
    7ffff7fb4ed9:	eb 09                	jmp    0x7ffff7fb4ee4
    7ffff7fb4edb:	8b 44 24 2c          	mov    eax,DWORD PTR [rsp+0x2c]
    7ffff7fb4edf:	49 01 44 f7 38       	add    QWORD PTR [r15+rsi*8+0x38],rax
    7ffff7fb4ee4:	48 83 c4 50          	add    rsp,0x50
    7ffff7fb4ee8:	5b                   	pop    rbx
    7ffff7fb4ee9:	5f                   	pop    rdi
    7ffff7fb4eea:	5e                   	pop    rsi
    7ffff7fb4eeb:	41 5e                	pop    r14
    7ffff7fb4eed:	41 5f                	pop    r15
    7ffff7fb4eef:	c3                   	ret
    7ffff7fb4ef0:	41 57                	push   r15
    7ffff7fb4ef2:	41 56                	push   r14
    7ffff7fb4ef4:	56                   	push   rsi
    7ffff7fb4ef5:	57                   	push   rdi
    7ffff7fb4ef6:	53                   	push   rbx
    7ffff7fb4ef7:	48 83 ec 50          	sub    rsp,0x50
    7ffff7fb4efb:	4c 89 c3             	mov    rbx,r8
    7ffff7fb4efe:	49 89 d6             	mov    r14,rdx
    7ffff7fb4f01:	48 89 ce             	mov    rsi,rcx
    7ffff7fb4f04:	31 c9                	xor    ecx,ecx
    7ffff7fb4f06:	48 83 fe 01          	cmp    rsi,0x1
    7ffff7fb4f0a:	0f 94 c1             	sete   cl
    7ffff7fb4f0d:	4c 8d 3d 14 40 00 00 	lea    r15,[rip+0x4014]        # 0x7ffff7fb8f28
    7ffff7fb4f14:	83 c9 f4             	or     ecx,0xfffffff4
    7ffff7fb4f17:	ff 15 1b 40 00 00    	call   QWORD PTR [rip+0x401b]        # 0x7ffff7fb8f38
    7ffff7fb4f1d:	4c 8d 4c 24 2c       	lea    r9,[rsp+0x2c]
    7ffff7fb4f22:	41 83 21 00          	and    DWORD PTR [r9],0x0
    7ffff7fb4f26:	48 89 c7             	mov    rdi,rax
    7ffff7fb4f29:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb4f2d:	48 8d 44 24 30       	lea    rax,[rsp+0x30]
    7ffff7fb4f32:	c5 fc 11 00          	vmovups YMMWORD PTR [rax],ymm0
    7ffff7fb4f36:	49 8b 4c f7 38       	mov    rcx,QWORD PTR [r15+rsi*8+0x38]
    7ffff7fb4f3b:	48 89 48 10          	mov    QWORD PTR [rax+0x10],rcx
    7ffff7fb4f3f:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
    7ffff7fb4f44:	48 89 f9             	mov    rcx,rdi
    7ffff7fb4f47:	4c 89 f2             	mov    rdx,r14
    7ffff7fb4f4a:	41 89 d8             	mov    r8d,ebx
    7ffff7fb4f4d:	c5 f8 77             	vzeroupper
    7ffff7fb4f50:	ff 15 f2 3f 00 00    	call   QWORD PTR [rip+0x3ff2]        # 0x7ffff7fb8f48
    7ffff7fb4f56:	85 c0                	test   eax,eax
    7ffff7fb4f58:	75 2c                	jne    0x7ffff7fb4f86
    7ffff7fb4f5a:	ff 15 f8 3f 00 00    	call   QWORD PTR [rip+0x3ff8]        # 0x7ffff7fb8f58
    7ffff7fb4f60:	3d e5 03 00 00       	cmp    eax,0x3e5
    7ffff7fb4f65:	75 1f                	jne    0x7ffff7fb4f86
    7ffff7fb4f67:	48 8d 54 24 30       	lea    rdx,[rsp+0x30]
    7ffff7fb4f6c:	4c 8d 44 24 2c       	lea    r8,[rsp+0x2c]
    7ffff7fb4f71:	6a 01                	push   0x1
    7ffff7fb4f73:	41 59                	pop    r9
    7ffff7fb4f75:	48 89 f9             	mov    rcx,rdi
    7ffff7fb4f78:	ff 15 d2 3f 00 00    	call   QWORD PTR [rip+0x3fd2]        # 0x7ffff7fb8f50
    7ffff7fb4f7e:	85 c0                	test   eax,eax
    7ffff7fb4f80:	74 04                	je     0x7ffff7fb4f86
    7ffff7fb4f82:	31 c0                	xor    eax,eax
    7ffff7fb4f84:	eb 09                	jmp    0x7ffff7fb4f8f
    7ffff7fb4f86:	8b 44 24 2c          	mov    eax,DWORD PTR [rsp+0x2c]
    7ffff7fb4f8a:	49 01 44 f7 38       	add    QWORD PTR [r15+rsi*8+0x38],rax
    7ffff7fb4f8f:	48 83 c4 50          	add    rsp,0x50
    7ffff7fb4f93:	5b                   	pop    rbx
    7ffff7fb4f94:	5f                   	pop    rdi
    7ffff7fb4f95:	5e                   	pop    rsi
    7ffff7fb4f96:	41 5e                	pop    r14
    7ffff7fb4f98:	41 5f                	pop    r15
    7ffff7fb4f9a:	c3                   	ret
    7ffff7fb4f9b:	41 56                	push   r14
    7ffff7fb4f9d:	53                   	push   rbx
    7ffff7fb4f9e:	50                   	push   rax
    7ffff7fb4f9f:	48 89 fb             	mov    rbx,rdi
    7ffff7fb4fa2:	48 83 ff 21          	cmp    rdi,0x21
    7ffff7fb4fa6:	6a 20                	push   0x20
    7ffff7fb4fa8:	58                   	pop    rax
    7ffff7fb4fa9:	48 0f 42 d8          	cmovb  rbx,rax
    7ffff7fb4fad:	48 c7 c1 99 ff fe ff 	mov    rcx,0xfffffffffffeff99
    7ffff7fb4fb4:	48 29 d9             	sub    rcx,rbx
    7ffff7fb4fb7:	48 39 f1             	cmp    rcx,rsi
    7ffff7fb4fba:	0f 86 a6 00 00 00    	jbe    0x7ffff7fb5066
    7ffff7fb4fc0:	4c 8d 76 17          	lea    r14,[rsi+0x17]
    7ffff7fb4fc4:	49 83 e6 f0          	and    r14,0xfffffffffffffff0
    7ffff7fb4fc8:	48 83 fe 17          	cmp    rsi,0x17
    7ffff7fb4fcc:	4c 0f 42 f0          	cmovb  r14,rax
    7ffff7fb4fd0:	4a 8d 3c 33          	lea    rdi,[rbx+r14*1]
    7ffff7fb4fd4:	48 83 c7 18          	add    rdi,0x18
    7ffff7fb4fd8:	e8 bd 02 00 00       	call   0x7ffff7fb529a
    7ffff7fb4fdd:	48 85 c0             	test   rax,rax
    7ffff7fb4fe0:	0f 84 80 00 00 00    	je     0x7ffff7fb5066
    7ffff7fb4fe6:	48 8d 78 f0          	lea    rdi,[rax-0x10]
    7ffff7fb4fea:	48 8d 4b ff          	lea    rcx,[rbx-0x1]
    7ffff7fb4fee:	48 85 c1             	test   rcx,rax
    7ffff7fb4ff1:	74 77                	je     0x7ffff7fb506a
    7ffff7fb4ff3:	48 01 c1             	add    rcx,rax
    7ffff7fb4ff6:	48 89 da             	mov    rdx,rbx
    7ffff7fb4ff9:	48 f7 da             	neg    rdx
    7ffff7fb4ffc:	48 21 ca             	and    rdx,rcx
    7ffff7fb4fff:	48 8d 4a f0          	lea    rcx,[rdx-0x10]
    7ffff7fb5003:	48 29 f9             	sub    rcx,rdi
    7ffff7fb5006:	31 f6                	xor    esi,esi
    7ffff7fb5008:	48 83 f9 21          	cmp    rcx,0x21
    7ffff7fb500c:	48 0f 42 f3          	cmovb  rsi,rbx
    7ffff7fb5010:	48 8d 1c 32          	lea    rbx,[rdx+rsi*1]
    7ffff7fb5014:	48 83 c3 f0          	add    rbx,0xfffffffffffffff0
    7ffff7fb5018:	48 89 de             	mov    rsi,rbx
    7ffff7fb501b:	48 29 fe             	sub    rsi,rdi
    7ffff7fb501e:	48 8b 50 f8          	mov    rdx,QWORD PTR [rax-0x8]
    7ffff7fb5022:	48 89 d1             	mov    rcx,rdx
    7ffff7fb5025:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb5029:	48 29 f1             	sub    rcx,rsi
    7ffff7fb502c:	f6 c2 03             	test   dl,0x3
    7ffff7fb502f:	74 3e                	je     0x7ffff7fb506f
    7ffff7fb5031:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
    7ffff7fb5035:	83 e2 01             	and    edx,0x1
    7ffff7fb5038:	48 09 ca             	or     rdx,rcx
    7ffff7fb503b:	48 83 ca 02          	or     rdx,0x2
    7ffff7fb503f:	48 89 53 08          	mov    QWORD PTR [rbx+0x8],rdx
    7ffff7fb5043:	80 4c 0b 08 01       	or     BYTE PTR [rbx+rcx*1+0x8],0x1
    7ffff7fb5048:	48 8b 48 f8          	mov    rcx,QWORD PTR [rax-0x8]
    7ffff7fb504c:	83 e1 01             	and    ecx,0x1
    7ffff7fb504f:	48 09 f1             	or     rcx,rsi
    7ffff7fb5052:	48 83 c9 02          	or     rcx,0x2
    7ffff7fb5056:	48 89 48 f8          	mov    QWORD PTR [rax-0x8],rcx
    7ffff7fb505a:	80 4c 30 f8 01       	or     BYTE PTR [rax+rsi*1-0x8],0x1
    7ffff7fb505f:	e8 9f 00 00 00       	call   0x7ffff7fb5103
    7ffff7fb5064:	eb 13                	jmp    0x7ffff7fb5079
    7ffff7fb5066:	31 db                	xor    ebx,ebx
    7ffff7fb5068:	eb 59                	jmp    0x7ffff7fb50c3
    7ffff7fb506a:	48 89 fb             	mov    rbx,rdi
    7ffff7fb506d:	eb 0a                	jmp    0x7ffff7fb5079
    7ffff7fb506f:	48 03 37             	add    rsi,QWORD PTR [rdi]
    7ffff7fb5072:	48 89 33             	mov    QWORD PTR [rbx],rsi
    7ffff7fb5075:	48 89 4b 08          	mov    QWORD PTR [rbx+0x8],rcx
    7ffff7fb5079:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
    7ffff7fb507d:	a8 03                	test   al,0x3
    7ffff7fb507f:	74 3e                	je     0x7ffff7fb50bf
    7ffff7fb5081:	48 89 c1             	mov    rcx,rax
    7ffff7fb5084:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb5088:	49 8d 56 20          	lea    rdx,[r14+0x20]
    7ffff7fb508c:	48 39 d1             	cmp    rcx,rdx
    7ffff7fb508f:	76 2e                	jbe    0x7ffff7fb50bf
    7ffff7fb5091:	48 89 ce             	mov    rsi,rcx
    7ffff7fb5094:	4c 29 f6             	sub    rsi,r14
    7ffff7fb5097:	4a 8d 3c 33          	lea    rdi,[rbx+r14*1]
    7ffff7fb509b:	83 e0 01             	and    eax,0x1
    7ffff7fb509e:	4c 01 f0             	add    rax,r14
    7ffff7fb50a1:	48 83 c0 02          	add    rax,0x2
    7ffff7fb50a5:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb50a9:	48 89 f0             	mov    rax,rsi
    7ffff7fb50ac:	48 83 c8 03          	or     rax,0x3
    7ffff7fb50b0:	4a 89 44 33 08       	mov    QWORD PTR [rbx+r14*1+0x8],rax
    7ffff7fb50b5:	80 4c 0b 08 01       	or     BYTE PTR [rbx+rcx*1+0x8],0x1
    7ffff7fb50ba:	e8 44 00 00 00       	call   0x7ffff7fb5103
    7ffff7fb50bf:	48 83 c3 10          	add    rbx,0x10
    7ffff7fb50c3:	48 89 d8             	mov    rax,rbx
    7ffff7fb50c6:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb50ca:	5b                   	pop    rbx
    7ffff7fb50cb:	41 5e                	pop    r14
    7ffff7fb50cd:	c3                   	ret
    7ffff7fb50ce:	48 81 fe 00 01 00 00 	cmp    rsi,0x100
    7ffff7fb50d5:	0f 83 19 0d 00 00    	jae    0x7ffff7fb5df4
    7ffff7fb50db:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
    7ffff7fb50df:	48 8b 4f 18          	mov    rcx,QWORD PTR [rdi+0x18]
    7ffff7fb50e3:	48 39 c1             	cmp    rcx,rax
    7ffff7fb50e6:	74 09                	je     0x7ffff7fb50f1
    7ffff7fb50e8:	48 89 48 18          	mov    QWORD PTR [rax+0x18],rcx
    7ffff7fb50ec:	48 89 41 10          	mov    QWORD PTR [rcx+0x10],rax
    7ffff7fb50f0:	c3                   	ret
    7ffff7fb50f1:	40 c0 ee 03          	shr    sil,0x3
    7ffff7fb50f5:	6a fe                	push   0xfffffffffffffffe
    7ffff7fb50f7:	58                   	pop    rax
    7ffff7fb50f8:	89 f1                	mov    ecx,esi
    7ffff7fb50fa:	d3 c0                	rol    eax,cl
    7ffff7fb50fc:	21 05 ee 41 00 00    	and    DWORD PTR [rip+0x41ee],eax        # 0x7ffff7fb92f0
    7ffff7fb5102:	c3                   	ret
    7ffff7fb5103:	55                   	push   rbp
    7ffff7fb5104:	41 57                	push   r15
    7ffff7fb5106:	41 56                	push   r14
    7ffff7fb5108:	41 55                	push   r13
    7ffff7fb510a:	41 54                	push   r12
    7ffff7fb510c:	53                   	push   rbx
    7ffff7fb510d:	50                   	push   rax
    7ffff7fb510e:	49 89 f4             	mov    r12,rsi
    7ffff7fb5111:	49 89 fd             	mov    r13,rdi
    7ffff7fb5114:	4c 8d 3c 37          	lea    r15,[rdi+rsi*1]
    7ffff7fb5118:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
    7ffff7fb511c:	49 89 f6             	mov    r14,rsi
    7ffff7fb511f:	48 89 fb             	mov    rbx,rdi
    7ffff7fb5122:	a8 01                	test   al,0x1
    7ffff7fb5124:	0f 85 81 00 00 00    	jne    0x7ffff7fb51ab
    7ffff7fb512a:	49 8b 6d 00          	mov    rbp,QWORD PTR [r13+0x0]
    7ffff7fb512e:	4c 89 eb             	mov    rbx,r13
    7ffff7fb5131:	48 29 eb             	sub    rbx,rbp
    7ffff7fb5134:	a8 02                	test   al,0x2
    7ffff7fb5136:	75 30                	jne    0x7ffff7fb5168
    7ffff7fb5138:	48 89 df             	mov    rdi,rbx
    7ffff7fb513b:	e8 d0 0a 00 00       	call   0x7ffff7fb5c10
    7ffff7fb5140:	84 c0                	test   al,al
    7ffff7fb5142:	0f 84 43 01 00 00    	je     0x7ffff7fb528b
    7ffff7fb5148:	49 01 ec             	add    r12,rbp
    7ffff7fb514b:	48 8b 05 76 41 00 00 	mov    rax,QWORD PTR [rip+0x4176]        # 0x7ffff7fb92c8
    7ffff7fb5152:	49 f7 dc             	neg    r12
    7ffff7fb5155:	4c 01 e0             	add    rax,r12
    7ffff7fb5158:	48 83 c0 e0          	add    rax,0xffffffffffffffe0
    7ffff7fb515c:	48 89 05 65 41 00 00 	mov    QWORD PTR [rip+0x4165],rax        # 0x7ffff7fb92c8
    7ffff7fb5163:	e9 23 01 00 00       	jmp    0x7ffff7fb528b
    7ffff7fb5168:	4d 8d 34 2c          	lea    r14,[r12+rbp*1]
    7ffff7fb516c:	48 3b 1d 45 41 00 00 	cmp    rbx,QWORD PTR [rip+0x4145]        # 0x7ffff7fb92b8
    7ffff7fb5173:	74 0d                	je     0x7ffff7fb5182
    7ffff7fb5175:	48 89 df             	mov    rdi,rbx
    7ffff7fb5178:	48 89 ee             	mov    rsi,rbp
    7ffff7fb517b:	e8 4e ff ff ff       	call   0x7ffff7fb50ce
    7ffff7fb5180:	eb 29                	jmp    0x7ffff7fb51ab
    7ffff7fb5182:	41 8b 47 08          	mov    eax,DWORD PTR [r15+0x8]
    7ffff7fb5186:	f7 d0                	not    eax
    7ffff7fb5188:	a8 03                	test   al,0x3
    7ffff7fb518a:	75 1f                	jne    0x7ffff7fb51ab
    7ffff7fb518c:	4c 89 35 15 41 00 00 	mov    QWORD PTR [rip+0x4115],r14        # 0x7ffff7fb92a8
    7ffff7fb5193:	41 80 67 08 fe       	and    BYTE PTR [r15+0x8],0xfe
    7ffff7fb5198:	4c 89 f0             	mov    rax,r14
    7ffff7fb519b:	48 83 c8 01          	or     rax,0x1
    7ffff7fb519f:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb51a3:	4d 89 37             	mov    QWORD PTR [r15],r14
    7ffff7fb51a6:	e9 e0 00 00 00       	jmp    0x7ffff7fb528b
    7ffff7fb51ab:	4b 8b 74 25 08       	mov    rsi,QWORD PTR [r13+r12*1+0x8]
    7ffff7fb51b0:	40 f6 c6 02          	test   sil,0x2
    7ffff7fb51b4:	75 49                	jne    0x7ffff7fb51ff
    7ffff7fb51b6:	4c 3b 3d 03 41 00 00 	cmp    r15,QWORD PTR [rip+0x4103]        # 0x7ffff7fb92c0
    7ffff7fb51bd:	74 70                	je     0x7ffff7fb522f
    7ffff7fb51bf:	4c 3b 3d f2 40 00 00 	cmp    r15,QWORD PTR [rip+0x40f2]        # 0x7ffff7fb92b8
    7ffff7fb51c6:	0f 84 9b 00 00 00    	je     0x7ffff7fb5267
    7ffff7fb51cc:	48 83 e6 f8          	and    rsi,0xfffffffffffffff8
    7ffff7fb51d0:	49 01 f6             	add    r14,rsi
    7ffff7fb51d3:	4c 89 ff             	mov    rdi,r15
    7ffff7fb51d6:	e8 f3 fe ff ff       	call   0x7ffff7fb50ce
    7ffff7fb51db:	4c 89 f0             	mov    rax,r14
    7ffff7fb51de:	48 83 c8 01          	or     rax,0x1
    7ffff7fb51e2:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb51e6:	4e 89 34 33          	mov    QWORD PTR [rbx+r14*1],r14
    7ffff7fb51ea:	48 3b 1d c7 40 00 00 	cmp    rbx,QWORD PTR [rip+0x40c7]        # 0x7ffff7fb92b8
    7ffff7fb51f1:	75 23                	jne    0x7ffff7fb5216
    7ffff7fb51f3:	4c 89 35 ae 40 00 00 	mov    QWORD PTR [rip+0x40ae],r14        # 0x7ffff7fb92a8
    7ffff7fb51fa:	e9 8c 00 00 00       	jmp    0x7ffff7fb528b
    7ffff7fb51ff:	48 83 e6 fe          	and    rsi,0xfffffffffffffffe
    7ffff7fb5203:	49 89 77 08          	mov    QWORD PTR [r15+0x8],rsi
    7ffff7fb5207:	4c 89 f0             	mov    rax,r14
    7ffff7fb520a:	48 83 c8 01          	or     rax,0x1
    7ffff7fb520e:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb5212:	4e 89 34 33          	mov    QWORD PTR [rbx+r14*1],r14
    7ffff7fb5216:	48 89 df             	mov    rdi,rbx
    7ffff7fb5219:	4c 89 f6             	mov    rsi,r14
    7ffff7fb521c:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb5220:	5b                   	pop    rbx
    7ffff7fb5221:	41 5c                	pop    r12
    7ffff7fb5223:	41 5d                	pop    r13
    7ffff7fb5225:	41 5e                	pop    r14
    7ffff7fb5227:	41 5f                	pop    r15
    7ffff7fb5229:	5d                   	pop    rbp
    7ffff7fb522a:	e9 93 0c 00 00       	jmp    0x7ffff7fb5ec2
    7ffff7fb522f:	4c 03 35 7a 40 00 00 	add    r14,QWORD PTR [rip+0x407a]        # 0x7ffff7fb92b0
    7ffff7fb5236:	4c 89 35 73 40 00 00 	mov    QWORD PTR [rip+0x4073],r14        # 0x7ffff7fb92b0
    7ffff7fb523d:	48 89 1d 7c 40 00 00 	mov    QWORD PTR [rip+0x407c],rbx        # 0x7ffff7fb92c0
    7ffff7fb5244:	49 83 ce 01          	or     r14,0x1
    7ffff7fb5248:	4c 89 73 08          	mov    QWORD PTR [rbx+0x8],r14
    7ffff7fb524c:	48 3b 1d 65 40 00 00 	cmp    rbx,QWORD PTR [rip+0x4065]        # 0x7ffff7fb92b8
    7ffff7fb5253:	75 36                	jne    0x7ffff7fb528b
    7ffff7fb5255:	48 83 25 5b 40 00 00 	and    QWORD PTR [rip+0x405b],0x0        # 0x7ffff7fb92b8
    7ffff7fb525c:	00 
    7ffff7fb525d:	48 83 25 43 40 00 00 	and    QWORD PTR [rip+0x4043],0x0        # 0x7ffff7fb92a8
    7ffff7fb5264:	00 
    7ffff7fb5265:	eb 24                	jmp    0x7ffff7fb528b
    7ffff7fb5267:	4c 03 35 3a 40 00 00 	add    r14,QWORD PTR [rip+0x403a]        # 0x7ffff7fb92a8
    7ffff7fb526e:	4c 89 35 33 40 00 00 	mov    QWORD PTR [rip+0x4033],r14        # 0x7ffff7fb92a8
    7ffff7fb5275:	48 89 1d 3c 40 00 00 	mov    QWORD PTR [rip+0x403c],rbx        # 0x7ffff7fb92b8
    7ffff7fb527c:	4c 89 f0             	mov    rax,r14
    7ffff7fb527f:	48 83 c8 01          	or     rax,0x1
    7ffff7fb5283:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb5287:	4e 89 34 33          	mov    QWORD PTR [rbx+r14*1],r14
    7ffff7fb528b:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb528f:	5b                   	pop    rbx
    7ffff7fb5290:	41 5c                	pop    r12
    7ffff7fb5292:	41 5d                	pop    r13
    7ffff7fb5294:	41 5e                	pop    r14
    7ffff7fb5296:	41 5f                	pop    r15
    7ffff7fb5298:	5d                   	pop    rbp
    7ffff7fb5299:	c3                   	ret
    7ffff7fb529a:	55                   	push   rbp
    7ffff7fb529b:	41 57                	push   r15
    7ffff7fb529d:	41 56                	push   r14
    7ffff7fb529f:	41 55                	push   r13
    7ffff7fb52a1:	41 54                	push   r12
    7ffff7fb52a3:	53                   	push   rbx
    7ffff7fb52a4:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb52a8:	48 89 fb             	mov    rbx,rdi
    7ffff7fb52ab:	6a 02                	push   0x2
    7ffff7fb52ad:	5d                   	pop    rbp
    7ffff7fb52ae:	48 81 ff e9 00 00 00 	cmp    rdi,0xe9
    7ffff7fb52b5:	73 79                	jae    0x7ffff7fb5330
    7ffff7fb52b7:	8d 43 17             	lea    eax,[rbx+0x17]
    7ffff7fb52ba:	25 f0 01 00 00       	and    eax,0x1f0
    7ffff7fb52bf:	48 83 fb 17          	cmp    rbx,0x17
    7ffff7fb52c3:	6a 20                	push   0x20
    7ffff7fb52c5:	5b                   	pop    rbx
    7ffff7fb52c6:	48 0f 43 d8          	cmovae rbx,rax
    7ffff7fb52ca:	89 d9                	mov    ecx,ebx
    7ffff7fb52cc:	c1 e9 03             	shr    ecx,0x3
    7ffff7fb52cf:	c4 62 73 f7 3d 18 40 	shrx   r15d,DWORD PTR [rip+0x4018],ecx        # 0x7ffff7fb92f0
    7ffff7fb52d6:	00 00 
    7ffff7fb52d8:	41 f6 c7 03          	test   r15b,0x3
    7ffff7fb52dc:	0f 84 1b 01 00 00    	je     0x7ffff7fb53fd
    7ffff7fb52e2:	41 83 e7 01          	and    r15d,0x1
    7ffff7fb52e6:	41 09 cf             	or     r15d,ecx
    7ffff7fb52e9:	41 83 f7 01          	xor    r15d,0x1
    7ffff7fb52ed:	44 89 f8             	mov    eax,r15d
    7ffff7fb52f0:	c1 e0 04             	shl    eax,0x4
    7ffff7fb52f3:	48 8d 0d 7e 3c 00 00 	lea    rcx,[rip+0x3c7e]        # 0x7ffff7fb8f78
    7ffff7fb52fa:	48 8d 3c 08          	lea    rdi,[rax+rcx*1]
    7ffff7fb52fe:	48 81 c7 20 01 00 00 	add    rdi,0x120
    7ffff7fb5305:	48 8b 5f 10          	mov    rbx,QWORD PTR [rdi+0x10]
    7ffff7fb5309:	4c 8d 73 10          	lea    r14,[rbx+0x10]
    7ffff7fb530d:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
    7ffff7fb5311:	44 89 fa             	mov    edx,r15d
    7ffff7fb5314:	e8 bb 0b 00 00       	call   0x7ffff7fb5ed4
    7ffff7fb5319:	41 c1 e7 03          	shl    r15d,0x3
    7ffff7fb531d:	49 8d 47 03          	lea    rax,[r15+0x3]
    7ffff7fb5321:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
    7ffff7fb5325:	42 80 4c 3b 08 01    	or     BYTE PTR [rbx+r15*1+0x8],0x1
    7ffff7fb532b:	e9 d3 05 00 00       	jmp    0x7ffff7fb5903
    7ffff7fb5330:	48 81 fb 99 ff fe ff 	cmp    rbx,0xfffffffffffeff99
    7ffff7fb5337:	0f 83 c3 05 00 00    	jae    0x7ffff7fb5900
    7ffff7fb533d:	48 83 c3 17          	add    rbx,0x17
    7ffff7fb5341:	48 83 e3 f0          	and    rbx,0xfffffffffffffff0
    7ffff7fb5345:	44 8b 25 a8 3f 00 00 	mov    r12d,DWORD PTR [rip+0x3fa8]        # 0x7ffff7fb92f4
    7ffff7fb534c:	45 85 e4             	test   r12d,r12d
    7ffff7fb534f:	0f 84 29 01 00 00    	je     0x7ffff7fb547e
    7ffff7fb5355:	49 89 df             	mov    r15,rbx
    7ffff7fb5358:	49 f7 df             	neg    r15
    7ffff7fb535b:	48 89 df             	mov    rdi,rbx
    7ffff7fb535e:	e8 5a 0a 00 00       	call   0x7ffff7fb5dbd
    7ffff7fb5363:	89 c1                	mov    ecx,eax
    7ffff7fb5365:	48 8d 15 0c 3c 00 00 	lea    rdx,[rip+0x3c0c]        # 0x7ffff7fb8f78
    7ffff7fb536c:	48 8b 0c ca          	mov    rcx,QWORD PTR [rdx+rcx*8]
    7ffff7fb5370:	48 85 c9             	test   rcx,rcx
    7ffff7fb5373:	0f 84 9c 01 00 00    	je     0x7ffff7fb5515
    7ffff7fb5379:	89 c6                	mov    esi,eax
    7ffff7fb537b:	40 d0 ee             	shr    sil,1
    7ffff7fb537e:	40 b7 39             	mov    dil,0x39
    7ffff7fb5381:	40 28 f7             	sub    dil,sil
    7ffff7fb5384:	40 80 e7 3f          	and    dil,0x3f
    7ffff7fb5388:	31 f6                	xor    esi,esi
    7ffff7fb538a:	83 f8 1f             	cmp    eax,0x1f
    7ffff7fb538d:	40 0f b6 ff          	movzx  edi,dil
    7ffff7fb5391:	0f 44 fe             	cmove  edi,esi
    7ffff7fb5394:	c4 e2 c1 f7 f3       	shlx   rsi,rbx,rdi
    7ffff7fb5399:	45 31 c0             	xor    r8d,r8d
    7ffff7fb539c:	45 31 f6             	xor    r14d,r14d
    7ffff7fb539f:	4c 89 c7             	mov    rdi,r8
    7ffff7fb53a2:	4c 8b 41 08          	mov    r8,QWORD PTR [rcx+0x8]
    7ffff7fb53a6:	49 83 e0 f8          	and    r8,0xfffffffffffffff8
    7ffff7fb53aa:	49 29 d8             	sub    r8,rbx
    7ffff7fb53ad:	72 14                	jb     0x7ffff7fb53c3
    7ffff7fb53af:	4d 39 f8             	cmp    r8,r15
    7ffff7fb53b2:	73 0f                	jae    0x7ffff7fb53c3
    7ffff7fb53b4:	4d 89 c7             	mov    r15,r8
    7ffff7fb53b7:	49 89 ce             	mov    r14,rcx
    7ffff7fb53ba:	4d 85 c0             	test   r8,r8
    7ffff7fb53bd:	0f 84 b7 01 00 00    	je     0x7ffff7fb557a
    7ffff7fb53c3:	4c 8b 49 28          	mov    r9,QWORD PTR [rcx+0x28]
    7ffff7fb53c7:	49 89 f0             	mov    r8,rsi
    7ffff7fb53ca:	49 c1 e8 3f          	shr    r8,0x3f
    7ffff7fb53ce:	4a 8b 4c c1 20       	mov    rcx,QWORD PTR [rcx+r8*8+0x20]
    7ffff7fb53d3:	49 39 c9             	cmp    r9,rcx
    7ffff7fb53d6:	4d 89 c8             	mov    r8,r9
    7ffff7fb53d9:	4c 0f 44 c7          	cmove  r8,rdi
    7ffff7fb53dd:	4d 85 c9             	test   r9,r9
    7ffff7fb53e0:	4c 0f 44 c7          	cmove  r8,rdi
    7ffff7fb53e4:	48 01 f6             	add    rsi,rsi
    7ffff7fb53e7:	48 85 c9             	test   rcx,rcx
    7ffff7fb53ea:	75 b3                	jne    0x7ffff7fb539f
    7ffff7fb53ec:	4d 85 c0             	test   r8,r8
    7ffff7fb53ef:	0f 84 17 01 00 00    	je     0x7ffff7fb550c
    7ffff7fb53f5:	4c 89 c1             	mov    rcx,r8
    7ffff7fb53f8:	e9 83 01 00 00       	jmp    0x7ffff7fb5580
    7ffff7fb53fd:	48 8b 05 a4 3e 00 00 	mov    rax,QWORD PTR [rip+0x3ea4]        # 0x7ffff7fb92a8
    7ffff7fb5404:	48 39 c3             	cmp    rbx,rax
    7ffff7fb5407:	0f 86 d5 01 00 00    	jbe    0x7ffff7fb55e2
    7ffff7fb540d:	45 85 ff             	test   r15d,r15d
    7ffff7fb5410:	74 78                	je     0x7ffff7fb548a
    7ffff7fb5412:	c4 c2 71 f7 c7       	shlx   eax,r15d,ecx
    7ffff7fb5417:	c4 e2 71 f7 cd       	shlx   ecx,ebp,ecx
    7ffff7fb541c:	89 ca                	mov    edx,ecx
    7ffff7fb541e:	f7 da                	neg    edx
    7ffff7fb5420:	09 ca                	or     edx,ecx
    7ffff7fb5422:	21 c2                	and    edx,eax
    7ffff7fb5424:	f3 44 0f bc fa       	tzcnt  r15d,edx
    7ffff7fb5429:	44 89 f8             	mov    eax,r15d
    7ffff7fb542c:	c1 e0 04             	shl    eax,0x4
    7ffff7fb542f:	48 8d 0d 42 3b 00 00 	lea    rcx,[rip+0x3b42]        # 0x7ffff7fb8f78
    7ffff7fb5436:	48 8d 3c 08          	lea    rdi,[rax+rcx*1]
    7ffff7fb543a:	48 81 c7 20 01 00 00 	add    rdi,0x120
    7ffff7fb5441:	4c 8b 67 10          	mov    r12,QWORD PTR [rdi+0x10]
    7ffff7fb5445:	4d 8d 74 24 10       	lea    r14,[r12+0x10]
    7ffff7fb544a:	49 8b 74 24 10       	mov    rsi,QWORD PTR [r12+0x10]
    7ffff7fb544f:	44 89 fa             	mov    edx,r15d
    7ffff7fb5452:	e8 7d 0a 00 00       	call   0x7ffff7fb5ed4
    7ffff7fb5457:	41 c1 e7 03          	shl    r15d,0x3
    7ffff7fb545b:	4c 89 fe             	mov    rsi,r15
    7ffff7fb545e:	48 29 de             	sub    rsi,rbx
    7ffff7fb5461:	48 83 fe 20          	cmp    rsi,0x20
    7ffff7fb5465:	73 7b                	jae    0x7ffff7fb54e2
    7ffff7fb5467:	4c 89 f8             	mov    rax,r15
    7ffff7fb546a:	48 83 c8 03          	or     rax,0x3
    7ffff7fb546e:	49 89 44 24 08       	mov    QWORD PTR [r12+0x8],rax
    7ffff7fb5473:	43 80 4c 3c 08 01    	or     BYTE PTR [r12+r15*1+0x8],0x1
    7ffff7fb5479:	e9 85 04 00 00       	jmp    0x7ffff7fb5903
    7ffff7fb547e:	48 8b 05 23 3e 00 00 	mov    rax,QWORD PTR [rip+0x3e23]        # 0x7ffff7fb92a8
    7ffff7fb5485:	e9 58 01 00 00       	jmp    0x7ffff7fb55e2
    7ffff7fb548a:	8b 0d 64 3e 00 00    	mov    ecx,DWORD PTR [rip+0x3e64]        # 0x7ffff7fb92f4
    7ffff7fb5490:	85 c9                	test   ecx,ecx
    7ffff7fb5492:	0f 84 4a 01 00 00    	je     0x7ffff7fb55e2
    7ffff7fb5498:	f3 0f bc c1          	tzcnt  eax,ecx
    7ffff7fb549c:	48 8d 0d d5 3a 00 00 	lea    rcx,[rip+0x3ad5]        # 0x7ffff7fb8f78
    7ffff7fb54a3:	48 8b 0c c1          	mov    rcx,QWORD PTR [rcx+rax*8]
    7ffff7fb54a7:	4c 8b 79 08          	mov    r15,QWORD PTR [rcx+0x8]
    7ffff7fb54ab:	49 83 e7 f8          	and    r15,0xfffffffffffffff8
    7ffff7fb54af:	49 29 df             	sub    r15,rbx
    7ffff7fb54b2:	49 89 ce             	mov    r14,rcx
    7ffff7fb54b5:	48 8b 41 20          	mov    rax,QWORD PTR [rcx+0x20]
    7ffff7fb54b9:	48 85 c0             	test   rax,rax
    7ffff7fb54bc:	75 09                	jne    0x7ffff7fb54c7
    7ffff7fb54be:	48 8b 41 28          	mov    rax,QWORD PTR [rcx+0x28]
    7ffff7fb54c2:	48 85 c0             	test   rax,rax
    7ffff7fb54c5:	74 75                	je     0x7ffff7fb553c
    7ffff7fb54c7:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
    7ffff7fb54cb:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb54cf:	48 29 d9             	sub    rcx,rbx
    7ffff7fb54d2:	4c 39 f9             	cmp    rcx,r15
    7ffff7fb54d5:	4c 0f 42 f9          	cmovb  r15,rcx
    7ffff7fb54d9:	4c 0f 42 f0          	cmovb  r14,rax
    7ffff7fb54dd:	48 89 c1             	mov    rcx,rax
    7ffff7fb54e0:	eb d3                	jmp    0x7ffff7fb54b5
    7ffff7fb54e2:	48 89 d8             	mov    rax,rbx
    7ffff7fb54e5:	48 83 c8 03          	or     rax,0x3
    7ffff7fb54e9:	49 89 44 24 08       	mov    QWORD PTR [r12+0x8],rax
    7ffff7fb54ee:	49 8d 3c 1c          	lea    rdi,[r12+rbx*1]
    7ffff7fb54f2:	48 89 f0             	mov    rax,rsi
    7ffff7fb54f5:	48 83 c8 01          	or     rax,0x1
    7ffff7fb54f9:	49 89 44 1c 08       	mov    QWORD PTR [r12+rbx*1+0x8],rax
    7ffff7fb54fe:	4b 89 34 3c          	mov    QWORD PTR [r12+r15*1],rsi
    7ffff7fb5502:	e8 e9 09 00 00       	call   0x7ffff7fb5ef0
    7ffff7fb5507:	e9 f7 03 00 00       	jmp    0x7ffff7fb5903
    7ffff7fb550c:	4d 85 f6             	test   r14,r14
    7ffff7fb550f:	74 04                	je     0x7ffff7fb5515
    7ffff7fb5511:	31 c9                	xor    ecx,ecx
    7ffff7fb5513:	eb 6b                	jmp    0x7ffff7fb5580
    7ffff7fb5515:	c4 e2 79 f7 cd       	shlx   ecx,ebp,eax
    7ffff7fb551a:	89 c8                	mov    eax,ecx
    7ffff7fb551c:	f7 d8                	neg    eax
    7ffff7fb551e:	09 c8                	or     eax,ecx
    7ffff7fb5520:	44 21 e0             	and    eax,r12d
    7ffff7fb5523:	74 10                	je     0x7ffff7fb5535
    7ffff7fb5525:	f3 0f bc c0          	tzcnt  eax,eax
    7ffff7fb5529:	48 8d 04 c2          	lea    rax,[rdx+rax*8]
    7ffff7fb552d:	45 31 f6             	xor    r14d,r14d
    7ffff7fb5530:	e9 87 00 00 00       	jmp    0x7ffff7fb55bc
    7ffff7fb5535:	31 c9                	xor    ecx,ecx
    7ffff7fb5537:	45 31 f6             	xor    r14d,r14d
    7ffff7fb553a:	eb 44                	jmp    0x7ffff7fb5580
    7ffff7fb553c:	4c 89 f7             	mov    rdi,r14
    7ffff7fb553f:	e8 b0 08 00 00       	call   0x7ffff7fb5df4
    7ffff7fb5544:	49 83 ff 20          	cmp    r15,0x20
    7ffff7fb5548:	0f 82 ae 01 00 00    	jb     0x7ffff7fb56fc
    7ffff7fb554e:	49 8d 3c 1e          	lea    rdi,[r14+rbx*1]
    7ffff7fb5552:	48 89 d8             	mov    rax,rbx
    7ffff7fb5555:	48 83 c8 03          	or     rax,0x3
    7ffff7fb5559:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb555d:	4c 89 f8             	mov    rax,r15
    7ffff7fb5560:	48 83 c8 01          	or     rax,0x1
    7ffff7fb5564:	49 89 44 1e 08       	mov    QWORD PTR [r14+rbx*1+0x8],rax
    7ffff7fb5569:	4d 89 3c 3f          	mov    QWORD PTR [r15+rdi*1],r15
    7ffff7fb556d:	4c 89 fe             	mov    rsi,r15
    7ffff7fb5570:	e8 7b 09 00 00       	call   0x7ffff7fb5ef0
    7ffff7fb5575:	e9 80 03 00 00       	jmp    0x7ffff7fb58fa
    7ffff7fb557a:	45 31 ff             	xor    r15d,r15d
    7ffff7fb557d:	49 89 ce             	mov    r14,rcx
    7ffff7fb5580:	48 85 c9             	test   rcx,rcx
    7ffff7fb5583:	74 3c                	je     0x7ffff7fb55c1
    7ffff7fb5585:	48 89 c8             	mov    rax,rcx
    7ffff7fb5588:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
    7ffff7fb558c:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb5590:	48 89 ca             	mov    rdx,rcx
    7ffff7fb5593:	48 29 da             	sub    rdx,rbx
    7ffff7fb5596:	4c 39 fa             	cmp    rdx,r15
    7ffff7fb5599:	49 0f 43 d7          	cmovae rdx,r15
    7ffff7fb559d:	4c 89 f6             	mov    rsi,r14
    7ffff7fb55a0:	48 0f 42 f0          	cmovb  rsi,rax
    7ffff7fb55a4:	48 39 d9             	cmp    rcx,rbx
    7ffff7fb55a7:	4c 0f 43 fa          	cmovae r15,rdx
    7ffff7fb55ab:	48 8b 48 20          	mov    rcx,QWORD PTR [rax+0x20]
    7ffff7fb55af:	4c 0f 43 f6          	cmovae r14,rsi
    7ffff7fb55b3:	48 85 c9             	test   rcx,rcx
    7ffff7fb55b6:	75 c8                	jne    0x7ffff7fb5580
    7ffff7fb55b8:	48 83 c0 28          	add    rax,0x28
    7ffff7fb55bc:	48 8b 08             	mov    rcx,QWORD PTR [rax]
    7ffff7fb55bf:	eb bf                	jmp    0x7ffff7fb5580
    7ffff7fb55c1:	48 8b 05 e0 3c 00 00 	mov    rax,QWORD PTR [rip+0x3ce0]        # 0x7ffff7fb92a8
    7ffff7fb55c8:	4d 85 f6             	test   r14,r14
    7ffff7fb55cb:	74 15                	je     0x7ffff7fb55e2
    7ffff7fb55cd:	48 89 c1             	mov    rcx,rax
    7ffff7fb55d0:	48 29 d9             	sub    rcx,rbx
    7ffff7fb55d3:	0f 82 15 01 00 00    	jb     0x7ffff7fb56ee
    7ffff7fb55d9:	49 39 cf             	cmp    r15,rcx
    7ffff7fb55dc:	0f 82 0c 01 00 00    	jb     0x7ffff7fb56ee
    7ffff7fb55e2:	48 89 c1             	mov    rcx,rax
    7ffff7fb55e5:	48 29 d9             	sub    rcx,rbx
    7ffff7fb55e8:	0f 83 a6 00 00 00    	jae    0x7ffff7fb5694
    7ffff7fb55ee:	48 8b 05 bb 3c 00 00 	mov    rax,QWORD PTR [rip+0x3cbb]        # 0x7ffff7fb92b0
    7ffff7fb55f5:	48 29 d8             	sub    rax,rbx
    7ffff7fb55f8:	0f 87 d2 02 00 00    	ja     0x7ffff7fb58d0
    7ffff7fb55fe:	4c 8d bb 5f 00 01 00 	lea    r15,[rbx+0x1005f]
    7ffff7fb5605:	49 81 e7 00 00 ff ff 	and    r15,0xffffffffffff0000
    7ffff7fb560c:	45 31 f6             	xor    r14d,r14d
    7ffff7fb560f:	6a 04                	push   0x4
    7ffff7fb5611:	41 59                	pop    r9
    7ffff7fb5613:	31 c9                	xor    ecx,ecx
    7ffff7fb5615:	4c 89 fa             	mov    rdx,r15
    7ffff7fb5618:	41 b8 00 30 00 00    	mov    r8d,0x3000
    7ffff7fb561e:	ff 15 04 39 00 00    	call   QWORD PTR [rip+0x3904]        # 0x7ffff7fb8f28
    7ffff7fb5624:	48 85 c0             	test   rax,rax
    7ffff7fb5627:	4c 0f 44 f8          	cmove  r15,rax
    7ffff7fb562b:	0f 84 d2 02 00 00    	je     0x7ffff7fb5903
    7ffff7fb5631:	49 89 c4             	mov    r12,rax
    7ffff7fb5634:	48 8b 05 8d 3c 00 00 	mov    rax,QWORD PTR [rip+0x3c8d]        # 0x7ffff7fb92c8
    7ffff7fb563b:	4c 01 f8             	add    rax,r15
    7ffff7fb563e:	48 89 05 83 3c 00 00 	mov    QWORD PTR [rip+0x3c83],rax        # 0x7ffff7fb92c8
    7ffff7fb5645:	48 8b 0d 84 3c 00 00 	mov    rcx,QWORD PTR [rip+0x3c84]        # 0x7ffff7fb92d0
    7ffff7fb564c:	48 39 c1             	cmp    rcx,rax
    7ffff7fb564f:	48 0f 47 c1          	cmova  rax,rcx
    7ffff7fb5653:	48 89 05 76 3c 00 00 	mov    QWORD PTR [rip+0x3c76],rax        # 0x7ffff7fb92d0
    7ffff7fb565a:	4c 8b 35 5f 3c 00 00 	mov    r14,QWORD PTR [rip+0x3c5f]        # 0x7ffff7fb92c0
    7ffff7fb5661:	4d 85 f6             	test   r14,r14
    7ffff7fb5664:	0f 84 d7 00 00 00    	je     0x7ffff7fb5741
    7ffff7fb566a:	48 8d 05 07 3a 00 00 	lea    rax,[rip+0x3a07]        # 0x7ffff7fb9078
    7ffff7fb5671:	48 85 c0             	test   rax,rax
    7ffff7fb5674:	0f 84 58 01 00 00    	je     0x7ffff7fb57d2
    7ffff7fb567a:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    7ffff7fb567d:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
    7ffff7fb5681:	48 8d 34 0a          	lea    rsi,[rdx+rcx*1]
    7ffff7fb5685:	49 39 f4             	cmp    r12,rsi
    7ffff7fb5688:	0f 84 12 01 00 00    	je     0x7ffff7fb57a0
    7ffff7fb568e:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    7ffff7fb5692:	eb dd                	jmp    0x7ffff7fb5671
    7ffff7fb5694:	4c 8b 35 1d 3c 00 00 	mov    r14,QWORD PTR [rip+0x3c1d]        # 0x7ffff7fb92b8
    7ffff7fb569b:	48 83 f9 20          	cmp    rcx,0x20
    7ffff7fb569f:	73 26                	jae    0x7ffff7fb56c7
    7ffff7fb56a1:	48 83 25 ff 3b 00 00 	and    QWORD PTR [rip+0x3bff],0x0        # 0x7ffff7fb92a8
    7ffff7fb56a8:	00 
    7ffff7fb56a9:	48 83 25 07 3c 00 00 	and    QWORD PTR [rip+0x3c07],0x0        # 0x7ffff7fb92b8
    7ffff7fb56b0:	00 
    7ffff7fb56b1:	48 89 c1             	mov    rcx,rax
    7ffff7fb56b4:	48 83 c9 03          	or     rcx,0x3
    7ffff7fb56b8:	49 89 4e 08          	mov    QWORD PTR [r14+0x8],rcx
    7ffff7fb56bc:	41 80 4c 06 08 01    	or     BYTE PTR [r14+rax*1+0x8],0x1
    7ffff7fb56c2:	e9 33 02 00 00       	jmp    0x7ffff7fb58fa
    7ffff7fb56c7:	49 8d 14 1e          	lea    rdx,[r14+rbx*1]
    7ffff7fb56cb:	48 89 15 e6 3b 00 00 	mov    QWORD PTR [rip+0x3be6],rdx        # 0x7ffff7fb92b8
    7ffff7fb56d2:	48 89 0d cf 3b 00 00 	mov    QWORD PTR [rip+0x3bcf],rcx        # 0x7ffff7fb92a8
    7ffff7fb56d9:	48 89 ca             	mov    rdx,rcx
    7ffff7fb56dc:	48 83 ca 01          	or     rdx,0x1
    7ffff7fb56e0:	49 89 54 1e 08       	mov    QWORD PTR [r14+rbx*1+0x8],rdx
    7ffff7fb56e5:	49 89 0c 06          	mov    QWORD PTR [r14+rax*1],rcx
    7ffff7fb56e9:	e9 04 02 00 00       	jmp    0x7ffff7fb58f2
    7ffff7fb56ee:	4c 89 f7             	mov    rdi,r14
    7ffff7fb56f1:	e8 fe 06 00 00       	call   0x7ffff7fb5df4
    7ffff7fb56f6:	49 83 ff 20          	cmp    r15,0x20
    7ffff7fb56fa:	73 19                	jae    0x7ffff7fb5715
    7ffff7fb56fc:	49 01 df             	add    r15,rbx
    7ffff7fb56ff:	4c 89 f8             	mov    rax,r15
    7ffff7fb5702:	48 83 c8 03          	or     rax,0x3
    7ffff7fb5706:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb570a:	43 80 4c 3e 08 01    	or     BYTE PTR [r14+r15*1+0x8],0x1
    7ffff7fb5710:	e9 e5 01 00 00       	jmp    0x7ffff7fb58fa
    7ffff7fb5715:	49 8d 3c 1e          	lea    rdi,[r14+rbx*1]
    7ffff7fb5719:	48 89 d8             	mov    rax,rbx
    7ffff7fb571c:	48 83 c8 03          	or     rax,0x3
    7ffff7fb5720:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb5724:	4c 89 f8             	mov    rax,r15
    7ffff7fb5727:	48 83 c8 01          	or     rax,0x1
    7ffff7fb572b:	49 89 44 1e 08       	mov    QWORD PTR [r14+rbx*1+0x8],rax
    7ffff7fb5730:	4d 89 3c 3f          	mov    QWORD PTR [r15+rdi*1],r15
    7ffff7fb5734:	4c 89 fe             	mov    rsi,r15
    7ffff7fb5737:	e8 86 07 00 00       	call   0x7ffff7fb5ec2
    7ffff7fb573c:	e9 b9 01 00 00       	jmp    0x7ffff7fb58fa
    7ffff7fb5741:	48 8b 05 98 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b98]        # 0x7ffff7fb92e0
    7ffff7fb5748:	48 85 c0             	test   rax,rax
    7ffff7fb574b:	74 05                	je     0x7ffff7fb5752
    7ffff7fb574d:	49 39 c4             	cmp    r12,rax
    7ffff7fb5750:	73 07                	jae    0x7ffff7fb5759
    7ffff7fb5752:	4c 89 25 87 3b 00 00 	mov    QWORD PTR [rip+0x3b87],r12        # 0x7ffff7fb92e0
    7ffff7fb5759:	4c 89 25 18 39 00 00 	mov    QWORD PTR [rip+0x3918],r12        # 0x7ffff7fb9078
    7ffff7fb5760:	4c 89 3d 19 39 00 00 	mov    QWORD PTR [rip+0x3919],r15        # 0x7ffff7fb9080
    7ffff7fb5767:	83 25 22 39 00 00 00 	and    DWORD PTR [rip+0x3922],0x0        # 0x7ffff7fb9090
    7ffff7fb576e:	6a 20                	push   0x20
    7ffff7fb5770:	58                   	pop    rax
    7ffff7fb5771:	48 c7 05 6c 3b 00 00 	mov    QWORD PTR [rip+0x3b6c],0xfff        # 0x7ffff7fb92e8
    7ffff7fb5778:	ff 0f 00 00 
    7ffff7fb577c:	48 8d 0d 15 39 00 00 	lea    rcx,[rip+0x3915]        # 0x7ffff7fb9098
    7ffff7fb5783:	48 83 e8 01          	sub    rax,0x1
    7ffff7fb5787:	72 0e                	jb     0x7ffff7fb5797
    7ffff7fb5789:	48 89 49 18          	mov    QWORD PTR [rcx+0x18],rcx
    7ffff7fb578d:	48 89 49 10          	mov    QWORD PTR [rcx+0x10],rcx
    7ffff7fb5791:	48 83 c1 10          	add    rcx,0x10
    7ffff7fb5795:	eb ec                	jmp    0x7ffff7fb5783
    7ffff7fb5797:	49 83 c7 b0          	add    r15,0xffffffffffffffb0
    7ffff7fb579b:	4c 89 e7             	mov    rdi,r12
    7ffff7fb579e:	eb 25                	jmp    0x7ffff7fb57c5
    7ffff7fb57a0:	4d 39 f4             	cmp    r12,r14
    7ffff7fb57a3:	76 2d                	jbe    0x7ffff7fb57d2
    7ffff7fb57a5:	4c 39 f2             	cmp    rdx,r14
    7ffff7fb57a8:	77 28                	ja     0x7ffff7fb57d2
    7ffff7fb57aa:	83 78 18 00          	cmp    DWORD PTR [rax+0x18],0x0
    7ffff7fb57ae:	75 22                	jne    0x7ffff7fb57d2
    7ffff7fb57b0:	4c 01 f9             	add    rcx,r15
    7ffff7fb57b3:	48 89 48 08          	mov    QWORD PTR [rax+0x8],rcx
    7ffff7fb57b7:	48 8b 3d 02 3b 00 00 	mov    rdi,QWORD PTR [rip+0x3b02]        # 0x7ffff7fb92c0
    7ffff7fb57be:	4c 03 3d eb 3a 00 00 	add    r15,QWORD PTR [rip+0x3aeb]        # 0x7ffff7fb92b0
    7ffff7fb57c5:	4c 89 fe             	mov    rsi,r15
    7ffff7fb57c8:	e8 5b 07 00 00       	call   0x7ffff7fb5f28
    7ffff7fb57cd:	e9 f2 00 00 00       	jmp    0x7ffff7fb58c4
    7ffff7fb57d2:	48 8b 05 07 3b 00 00 	mov    rax,QWORD PTR [rip+0x3b07]        # 0x7ffff7fb92e0
    7ffff7fb57d9:	49 39 c4             	cmp    r12,rax
    7ffff7fb57dc:	49 0f 46 c4          	cmovbe rax,r12
    7ffff7fb57e0:	48 89 05 f9 3a 00 00 	mov    QWORD PTR [rip+0x3af9],rax        # 0x7ffff7fb92e0
    7ffff7fb57e7:	4b 8d 0c 3c          	lea    rcx,[r12+r15*1]
    7ffff7fb57eb:	48 8d 05 86 38 00 00 	lea    rax,[rip+0x3886]        # 0x7ffff7fb9078
    7ffff7fb57f2:	48 85 c0             	test   rax,rax
    7ffff7fb57f5:	74 18                	je     0x7ffff7fb580f
    7ffff7fb57f7:	48 8b 28             	mov    rbp,QWORD PTR [rax]
    7ffff7fb57fa:	48 39 cd             	cmp    rbp,rcx
    7ffff7fb57fd:	74 06                	je     0x7ffff7fb5805
    7ffff7fb57ff:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    7ffff7fb5803:	eb ed                	jmp    0x7ffff7fb57f2
    7ffff7fb5805:	83 78 18 00          	cmp    DWORD PTR [rax+0x18],0x0
    7ffff7fb5809:	0f 84 09 01 00 00    	je     0x7ffff7fb5918
    7ffff7fb580f:	4c 89 f7             	mov    rdi,r14
    7ffff7fb5812:	e8 18 04 00 00       	call   0x7ffff7fb5c2f
    7ffff7fb5817:	48 8b 08             	mov    rcx,QWORD PTR [rax]
    7ffff7fb581a:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
    7ffff7fb581e:	48 8d 2c 01          	lea    rbp,[rcx+rax*1]
    7ffff7fb5822:	4c 8d 2c 01          	lea    r13,[rcx+rax*1]
    7ffff7fb5826:	49 83 c5 c0          	add    r13,0xffffffffffffffc0
    7ffff7fb582a:	49 83 e5 f0          	and    r13,0xfffffffffffffff0
    7ffff7fb582e:	49 83 c5 f0          	add    r13,0xfffffffffffffff0
    7ffff7fb5832:	49 8d 46 20          	lea    rax,[r14+0x20]
    7ffff7fb5836:	49 39 c5             	cmp    r13,rax
    7ffff7fb5839:	4d 0f 42 ee          	cmovb  r13,r14
    7ffff7fb583d:	49 8d 45 10          	lea    rax,[r13+0x10]
    7ffff7fb5841:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
    7ffff7fb5846:	49 8d 77 b0          	lea    rsi,[r15-0x50]
    7ffff7fb584a:	4c 89 e7             	mov    rdi,r12
    7ffff7fb584d:	e8 d6 06 00 00       	call   0x7ffff7fb5f28
    7ffff7fb5852:	49 c7 45 08 33 00 00 	mov    QWORD PTR [r13+0x8],0x33
    7ffff7fb5859:	00 
    7ffff7fb585a:	c5 fc 10 05 16 38 00 	vmovups ymm0,YMMWORD PTR [rip+0x3816]        # 0x7ffff7fb9078
    7ffff7fb5861:	00 
    7ffff7fb5862:	c4 c1 7c 11 45 10    	vmovups YMMWORD PTR [r13+0x10],ymm0
    7ffff7fb5868:	4c 89 25 09 38 00 00 	mov    QWORD PTR [rip+0x3809],r12        # 0x7ffff7fb9078
    7ffff7fb586f:	4c 89 3d 0a 38 00 00 	mov    QWORD PTR [rip+0x380a],r15        # 0x7ffff7fb9080
    7ffff7fb5876:	83 25 13 38 00 00 00 	and    DWORD PTR [rip+0x3813],0x0        # 0x7ffff7fb9090
    7ffff7fb587d:	48 8b 44 24 20       	mov    rax,QWORD PTR [rsp+0x20]
    7ffff7fb5882:	48 89 05 ff 37 00 00 	mov    QWORD PTR [rip+0x37ff],rax        # 0x7ffff7fb9088
    7ffff7fb5889:	49 8d 45 38          	lea    rax,[r13+0x38]
    7ffff7fb588d:	48 c7 00 0b 00 00 00 	mov    QWORD PTR [rax],0xb
    7ffff7fb5894:	48 83 c0 08          	add    rax,0x8
    7ffff7fb5898:	48 39 e8             	cmp    rax,rbp
    7ffff7fb589b:	72 f0                	jb     0x7ffff7fb588d
    7ffff7fb589d:	4c 89 ee             	mov    rsi,r13
    7ffff7fb58a0:	4c 29 f6             	sub    rsi,r14
    7ffff7fb58a3:	74 1f                	je     0x7ffff7fb58c4
    7ffff7fb58a5:	41 80 65 08 fe       	and    BYTE PTR [r13+0x8],0xfe
    7ffff7fb58aa:	48 89 f0             	mov    rax,rsi
    7ffff7fb58ad:	48 83 c8 01          	or     rax,0x1
    7ffff7fb58b1:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb58b5:	49 89 75 00          	mov    QWORD PTR [r13+0x0],rsi
    7ffff7fb58b9:	4c 89 f7             	mov    rdi,r14
    7ffff7fb58bc:	c5 f8 77             	vzeroupper
    7ffff7fb58bf:	e8 fe 05 00 00       	call   0x7ffff7fb5ec2
    7ffff7fb58c4:	48 8b 05 e5 39 00 00 	mov    rax,QWORD PTR [rip+0x39e5]        # 0x7ffff7fb92b0
    7ffff7fb58cb:	48 29 d8             	sub    rax,rbx
    7ffff7fb58ce:	76 30                	jbe    0x7ffff7fb5900
    7ffff7fb58d0:	48 89 05 d9 39 00 00 	mov    QWORD PTR [rip+0x39d9],rax        # 0x7ffff7fb92b0
    7ffff7fb58d7:	4c 8b 35 e2 39 00 00 	mov    r14,QWORD PTR [rip+0x39e2]        # 0x7ffff7fb92c0
    7ffff7fb58de:	49 8d 0c 1e          	lea    rcx,[r14+rbx*1]
    7ffff7fb58e2:	48 89 0d d7 39 00 00 	mov    QWORD PTR [rip+0x39d7],rcx        # 0x7ffff7fb92c0
    7ffff7fb58e9:	48 83 c8 01          	or     rax,0x1
    7ffff7fb58ed:	49 89 44 1e 08       	mov    QWORD PTR [r14+rbx*1+0x8],rax
    7ffff7fb58f2:	48 83 cb 03          	or     rbx,0x3
    7ffff7fb58f6:	49 89 5e 08          	mov    QWORD PTR [r14+0x8],rbx
    7ffff7fb58fa:	49 83 c6 10          	add    r14,0x10
    7ffff7fb58fe:	eb 03                	jmp    0x7ffff7fb5903
    7ffff7fb5900:	45 31 f6             	xor    r14d,r14d
    7ffff7fb5903:	4c 89 f0             	mov    rax,r14
    7ffff7fb5906:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb590a:	5b                   	pop    rbx
    7ffff7fb590b:	41 5c                	pop    r12
    7ffff7fb590d:	41 5d                	pop    r13
    7ffff7fb590f:	41 5e                	pop    r14
    7ffff7fb5911:	41 5f                	pop    r15
    7ffff7fb5913:	5d                   	pop    rbp
    7ffff7fb5914:	c5 f8 77             	vzeroupper
    7ffff7fb5917:	c3                   	ret
    7ffff7fb5918:	4c 89 20             	mov    QWORD PTR [rax],r12
    7ffff7fb591b:	4c 01 78 08          	add    QWORD PTR [rax+0x8],r15
    7ffff7fb591f:	49 83 c4 1f          	add    r12,0x1f
    7ffff7fb5923:	49 83 e4 f0          	and    r12,0xfffffffffffffff0
    7ffff7fb5927:	4d 8d 74 24 f0       	lea    r14,[r12-0x10]
    7ffff7fb592c:	48 83 c5 1f          	add    rbp,0x1f
    7ffff7fb5930:	48 83 e5 f0          	and    rbp,0xfffffffffffffff0
    7ffff7fb5934:	48 83 c5 f0          	add    rbp,0xfffffffffffffff0
    7ffff7fb5938:	4d 8d 3c 1c          	lea    r15,[r12+rbx*1]
    7ffff7fb593c:	49 83 c7 f0          	add    r15,0xfffffffffffffff0
    7ffff7fb5940:	49 89 ed             	mov    r13,rbp
    7ffff7fb5943:	4d 29 fd             	sub    r13,r15
    7ffff7fb5946:	48 83 cb 03          	or     rbx,0x3
    7ffff7fb594a:	49 89 5c 24 f8       	mov    QWORD PTR [r12-0x8],rbx
    7ffff7fb594f:	48 3b 2d 6a 39 00 00 	cmp    rbp,QWORD PTR [rip+0x396a]        # 0x7ffff7fb92c0
    7ffff7fb5956:	74 57                	je     0x7ffff7fb59af
    7ffff7fb5958:	48 3b 2d 59 39 00 00 	cmp    rbp,QWORD PTR [rip+0x3959]        # 0x7ffff7fb92b8
    7ffff7fb595f:	74 70                	je     0x7ffff7fb59d1
    7ffff7fb5961:	48 8b 5d 08          	mov    rbx,QWORD PTR [rbp+0x8]
    7ffff7fb5965:	89 d8                	mov    eax,ebx
    7ffff7fb5967:	83 e0 03             	and    eax,0x3
    7ffff7fb596a:	83 f8 01             	cmp    eax,0x1
    7ffff7fb596d:	75 1e                	jne    0x7ffff7fb598d
    7ffff7fb596f:	48 83 e3 f8          	and    rbx,0xfffffffffffffff8
    7ffff7fb5973:	48 89 ef             	mov    rdi,rbp
    7ffff7fb5976:	48 89 de             	mov    rsi,rbx
    7ffff7fb5979:	e8 50 f7 ff ff       	call   0x7ffff7fb50ce
    7ffff7fb597e:	48 8d 04 2b          	lea    rax,[rbx+rbp*1]
    7ffff7fb5982:	49 01 dd             	add    r13,rbx
    7ffff7fb5985:	48 8b 5c 1d 08       	mov    rbx,QWORD PTR [rbp+rbx*1+0x8]
    7ffff7fb598a:	48 89 c5             	mov    rbp,rax
    7ffff7fb598d:	48 83 e3 fe          	and    rbx,0xfffffffffffffffe
    7ffff7fb5991:	48 89 5d 08          	mov    QWORD PTR [rbp+0x8],rbx
    7ffff7fb5995:	4c 89 e8             	mov    rax,r13
    7ffff7fb5998:	48 83 c8 01          	or     rax,0x1
    7ffff7fb599c:	49 89 47 08          	mov    QWORD PTR [r15+0x8],rax
    7ffff7fb59a0:	4f 89 2c 2f          	mov    QWORD PTR [r15+r13*1],r13
    7ffff7fb59a4:	4c 89 ff             	mov    rdi,r15
    7ffff7fb59a7:	4c 89 ee             	mov    rsi,r13
    7ffff7fb59aa:	e9 88 fd ff ff       	jmp    0x7ffff7fb5737
    7ffff7fb59af:	4c 03 2d fa 38 00 00 	add    r13,QWORD PTR [rip+0x38fa]        # 0x7ffff7fb92b0
    7ffff7fb59b6:	4c 89 2d f3 38 00 00 	mov    QWORD PTR [rip+0x38f3],r13        # 0x7ffff7fb92b0
    7ffff7fb59bd:	4c 89 3d fc 38 00 00 	mov    QWORD PTR [rip+0x38fc],r15        # 0x7ffff7fb92c0
    7ffff7fb59c4:	49 83 cd 01          	or     r13,0x1
    7ffff7fb59c8:	4d 89 6f 08          	mov    QWORD PTR [r15+0x8],r13
    7ffff7fb59cc:	e9 29 ff ff ff       	jmp    0x7ffff7fb58fa
    7ffff7fb59d1:	4c 03 2d d0 38 00 00 	add    r13,QWORD PTR [rip+0x38d0]        # 0x7ffff7fb92a8
    7ffff7fb59d8:	4c 89 2d c9 38 00 00 	mov    QWORD PTR [rip+0x38c9],r13        # 0x7ffff7fb92a8
    7ffff7fb59df:	4c 89 3d d2 38 00 00 	mov    QWORD PTR [rip+0x38d2],r15        # 0x7ffff7fb92b8
    7ffff7fb59e6:	4c 89 e8             	mov    rax,r13
    7ffff7fb59e9:	48 83 c8 01          	or     rax,0x1
    7ffff7fb59ed:	49 89 47 08          	mov    QWORD PTR [r15+0x8],rax
    7ffff7fb59f1:	4f 89 2c 2f          	mov    QWORD PTR [r15+r13*1],r13
    7ffff7fb59f5:	e9 00 ff ff ff       	jmp    0x7ffff7fb58fa
    7ffff7fb59fa:	55                   	push   rbp
    7ffff7fb59fb:	41 57                	push   r15
    7ffff7fb59fd:	41 56                	push   r14
    7ffff7fb59ff:	41 55                	push   r13
    7ffff7fb5a01:	41 54                	push   r12
    7ffff7fb5a03:	53                   	push   rbx
    7ffff7fb5a04:	50                   	push   rax
    7ffff7fb5a05:	48 8d 6f f0          	lea    rbp,[rdi-0x10]
    7ffff7fb5a09:	48 8b 47 f8          	mov    rax,QWORD PTR [rdi-0x8]
    7ffff7fb5a0d:	49 89 c5             	mov    r13,rax
    7ffff7fb5a10:	49 83 e5 f8          	and    r13,0xfffffffffffffff8
    7ffff7fb5a14:	4e 8d 3c 2f          	lea    r15,[rdi+r13*1]
    7ffff7fb5a18:	49 83 c7 f0          	add    r15,0xfffffffffffffff0
    7ffff7fb5a1c:	4c 89 eb             	mov    rbx,r13
    7ffff7fb5a1f:	49 89 ee             	mov    r14,rbp
    7ffff7fb5a22:	a8 01                	test   al,0x1
    7ffff7fb5a24:	0f 85 81 00 00 00    	jne    0x7ffff7fb5aab
    7ffff7fb5a2a:	4c 8b 65 00          	mov    r12,QWORD PTR [rbp+0x0]
    7ffff7fb5a2e:	49 89 ee             	mov    r14,rbp
    7ffff7fb5a31:	4d 29 e6             	sub    r14,r12
    7ffff7fb5a34:	a8 02                	test   al,0x2
    7ffff7fb5a36:	75 30                	jne    0x7ffff7fb5a68
    7ffff7fb5a38:	4c 89 f7             	mov    rdi,r14
    7ffff7fb5a3b:	e8 d0 01 00 00       	call   0x7ffff7fb5c10
    7ffff7fb5a40:	84 c0                	test   al,al
    7ffff7fb5a42:	0f 84 b9 01 00 00    	je     0x7ffff7fb5c01
    7ffff7fb5a48:	4d 01 e5             	add    r13,r12
    7ffff7fb5a4b:	48 8b 05 76 38 00 00 	mov    rax,QWORD PTR [rip+0x3876]        # 0x7ffff7fb92c8
    7ffff7fb5a52:	49 f7 dd             	neg    r13
    7ffff7fb5a55:	4c 01 e8             	add    rax,r13
    7ffff7fb5a58:	48 83 c0 e0          	add    rax,0xffffffffffffffe0
    7ffff7fb5a5c:	48 89 05 65 38 00 00 	mov    QWORD PTR [rip+0x3865],rax        # 0x7ffff7fb92c8
    7ffff7fb5a63:	e9 99 01 00 00       	jmp    0x7ffff7fb5c01
    7ffff7fb5a68:	4b 8d 1c 2c          	lea    rbx,[r12+r13*1]
    7ffff7fb5a6c:	4c 3b 35 45 38 00 00 	cmp    r14,QWORD PTR [rip+0x3845]        # 0x7ffff7fb92b8
    7ffff7fb5a73:	74 0d                	je     0x7ffff7fb5a82
    7ffff7fb5a75:	4c 89 f7             	mov    rdi,r14
    7ffff7fb5a78:	4c 89 e6             	mov    rsi,r12
    7ffff7fb5a7b:	e8 4e f6 ff ff       	call   0x7ffff7fb50ce
    7ffff7fb5a80:	eb 29                	jmp    0x7ffff7fb5aab
    7ffff7fb5a82:	41 8b 47 08          	mov    eax,DWORD PTR [r15+0x8]
    7ffff7fb5a86:	f7 d0                	not    eax
    7ffff7fb5a88:	a8 03                	test   al,0x3
    7ffff7fb5a8a:	75 1f                	jne    0x7ffff7fb5aab
    7ffff7fb5a8c:	48 89 1d 15 38 00 00 	mov    QWORD PTR [rip+0x3815],rbx        # 0x7ffff7fb92a8
    7ffff7fb5a93:	41 80 67 08 fe       	and    BYTE PTR [r15+0x8],0xfe
    7ffff7fb5a98:	48 89 d8             	mov    rax,rbx
    7ffff7fb5a9b:	48 83 c8 01          	or     rax,0x1
    7ffff7fb5a9f:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb5aa3:	49 89 1f             	mov    QWORD PTR [r15],rbx
    7ffff7fb5aa6:	e9 56 01 00 00       	jmp    0x7ffff7fb5c01
    7ffff7fb5aab:	4a 8b 74 2d 08       	mov    rsi,QWORD PTR [rbp+r13*1+0x8]
    7ffff7fb5ab0:	40 f6 c6 02          	test   sil,0x2
    7ffff7fb5ab4:	75 4d                	jne    0x7ffff7fb5b03
    7ffff7fb5ab6:	4c 3b 3d 03 38 00 00 	cmp    r15,QWORD PTR [rip+0x3803]        # 0x7ffff7fb92c0
    7ffff7fb5abd:	0f 84 9e 00 00 00    	je     0x7ffff7fb5b61
    7ffff7fb5ac3:	4c 3b 3d ee 37 00 00 	cmp    r15,QWORD PTR [rip+0x37ee]        # 0x7ffff7fb92b8
    7ffff7fb5aca:	0f 84 0d 01 00 00    	je     0x7ffff7fb5bdd
    7ffff7fb5ad0:	48 83 e6 f8          	and    rsi,0xfffffffffffffff8
    7ffff7fb5ad4:	48 01 f3             	add    rbx,rsi
    7ffff7fb5ad7:	4c 89 ff             	mov    rdi,r15
    7ffff7fb5ada:	e8 ef f5 ff ff       	call   0x7ffff7fb50ce
    7ffff7fb5adf:	48 89 d8             	mov    rax,rbx
    7ffff7fb5ae2:	48 83 c8 01          	or     rax,0x1
    7ffff7fb5ae6:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb5aea:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb5aee:	4c 3b 35 c3 37 00 00 	cmp    r14,QWORD PTR [rip+0x37c3]        # 0x7ffff7fb92b8
    7ffff7fb5af5:	75 23                	jne    0x7ffff7fb5b1a
    7ffff7fb5af7:	48 89 1d aa 37 00 00 	mov    QWORD PTR [rip+0x37aa],rbx        # 0x7ffff7fb92a8
    7ffff7fb5afe:	e9 fe 00 00 00       	jmp    0x7ffff7fb5c01
    7ffff7fb5b03:	48 83 e6 fe          	and    rsi,0xfffffffffffffffe
    7ffff7fb5b07:	49 89 77 08          	mov    QWORD PTR [r15+0x8],rsi
    7ffff7fb5b0b:	48 89 d8             	mov    rax,rbx
    7ffff7fb5b0e:	48 83 c8 01          	or     rax,0x1
    7ffff7fb5b12:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb5b16:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb5b1a:	4c 89 f7             	mov    rdi,r14
    7ffff7fb5b1d:	48 89 de             	mov    rsi,rbx
    7ffff7fb5b20:	48 81 fb 00 01 00 00 	cmp    rbx,0x100
    7ffff7fb5b27:	73 13                	jae    0x7ffff7fb5b3c
    7ffff7fb5b29:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb5b2d:	5b                   	pop    rbx
    7ffff7fb5b2e:	41 5c                	pop    r12
    7ffff7fb5b30:	41 5d                	pop    r13
    7ffff7fb5b32:	41 5e                	pop    r14
    7ffff7fb5b34:	41 5f                	pop    r15
    7ffff7fb5b36:	5d                   	pop    rbp
    7ffff7fb5b37:	e9 26 02 00 00       	jmp    0x7ffff7fb5d62
    7ffff7fb5b3c:	e8 45 01 00 00       	call   0x7ffff7fb5c86
    7ffff7fb5b41:	48 ff 0d a0 37 00 00 	dec    QWORD PTR [rip+0x37a0]        # 0x7ffff7fb92e8
    7ffff7fb5b48:	0f 85 b3 00 00 00    	jne    0x7ffff7fb5c01
    7ffff7fb5b4e:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb5b52:	5b                   	pop    rbx
    7ffff7fb5b53:	41 5c                	pop    r12
    7ffff7fb5b55:	41 5d                	pop    r13
    7ffff7fb5b57:	41 5e                	pop    r14
    7ffff7fb5b59:	41 5f                	pop    r15
    7ffff7fb5b5b:	5d                   	pop    rbp
    7ffff7fb5b5c:	e9 f4 00 00 00       	jmp    0x7ffff7fb5c55
    7ffff7fb5b61:	48 03 1d 48 37 00 00 	add    rbx,QWORD PTR [rip+0x3748]        # 0x7ffff7fb92b0
    7ffff7fb5b68:	48 89 1d 41 37 00 00 	mov    QWORD PTR [rip+0x3741],rbx        # 0x7ffff7fb92b0
    7ffff7fb5b6f:	4c 89 35 4a 37 00 00 	mov    QWORD PTR [rip+0x374a],r14        # 0x7ffff7fb92c0
    7ffff7fb5b76:	48 89 d8             	mov    rax,rbx
    7ffff7fb5b79:	48 83 c8 01          	or     rax,0x1
    7ffff7fb5b7d:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb5b81:	4c 3b 35 30 37 00 00 	cmp    r14,QWORD PTR [rip+0x3730]        # 0x7ffff7fb92b8
    7ffff7fb5b88:	75 10                	jne    0x7ffff7fb5b9a
    7ffff7fb5b8a:	48 83 25 26 37 00 00 	and    QWORD PTR [rip+0x3726],0x0        # 0x7ffff7fb92b8
    7ffff7fb5b91:	00 
    7ffff7fb5b92:	48 83 25 0e 37 00 00 	and    QWORD PTR [rip+0x370e],0x0        # 0x7ffff7fb92a8
    7ffff7fb5b99:	00 
    7ffff7fb5b9a:	48 39 1d 37 37 00 00 	cmp    QWORD PTR [rip+0x3737],rbx        # 0x7ffff7fb92d8
    7ffff7fb5ba1:	73 5e                	jae    0x7ffff7fb5c01
    7ffff7fb5ba3:	48 8b 3d 16 37 00 00 	mov    rdi,QWORD PTR [rip+0x3716]        # 0x7ffff7fb92c0
    7ffff7fb5baa:	48 85 ff             	test   rdi,rdi
    7ffff7fb5bad:	74 52                	je     0x7ffff7fb5c01
    7ffff7fb5baf:	48 83 3d f9 36 00 00 	cmp    QWORD PTR [rip+0x36f9],0x51        # 0x7ffff7fb92b0
    7ffff7fb5bb6:	51 
    7ffff7fb5bb7:	72 05                	jb     0x7ffff7fb5bbe
    7ffff7fb5bb9:	e8 71 00 00 00       	call   0x7ffff7fb5c2f
    7ffff7fb5bbe:	e8 92 00 00 00       	call   0x7ffff7fb5c55
    7ffff7fb5bc3:	48 8b 05 e6 36 00 00 	mov    rax,QWORD PTR [rip+0x36e6]        # 0x7ffff7fb92b0
    7ffff7fb5bca:	48 3b 05 07 37 00 00 	cmp    rax,QWORD PTR [rip+0x3707]        # 0x7ffff7fb92d8
    7ffff7fb5bd1:	76 2e                	jbe    0x7ffff7fb5c01
    7ffff7fb5bd3:	48 83 0d fd 36 00 00 	or     QWORD PTR [rip+0x36fd],0xffffffffffffffff        # 0x7ffff7fb92d8
    7ffff7fb5bda:	ff 
    7ffff7fb5bdb:	eb 24                	jmp    0x7ffff7fb5c01
    7ffff7fb5bdd:	48 03 1d c4 36 00 00 	add    rbx,QWORD PTR [rip+0x36c4]        # 0x7ffff7fb92a8
    7ffff7fb5be4:	48 89 1d bd 36 00 00 	mov    QWORD PTR [rip+0x36bd],rbx        # 0x7ffff7fb92a8
    7ffff7fb5beb:	4c 89 35 c6 36 00 00 	mov    QWORD PTR [rip+0x36c6],r14        # 0x7ffff7fb92b8
    7ffff7fb5bf2:	48 89 d8             	mov    rax,rbx
    7ffff7fb5bf5:	48 83 c8 01          	or     rax,0x1
    7ffff7fb5bf9:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb5bfd:	49 89 1c 1e          	mov    QWORD PTR [r14+rbx*1],rbx
    7ffff7fb5c01:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb5c05:	5b                   	pop    rbx
    7ffff7fb5c06:	41 5c                	pop    r12
    7ffff7fb5c08:	41 5d                	pop    r13
    7ffff7fb5c0a:	41 5e                	pop    r14
    7ffff7fb5c0c:	41 5f                	pop    r15
    7ffff7fb5c0e:	5d                   	pop    rbp
    7ffff7fb5c0f:	c3                   	ret
    7ffff7fb5c10:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb5c14:	48 89 f9             	mov    rcx,rdi
    7ffff7fb5c17:	31 d2                	xor    edx,edx
    7ffff7fb5c19:	41 b8 00 80 00 00    	mov    r8d,0x8000
    7ffff7fb5c1f:	ff 15 0b 33 00 00    	call   QWORD PTR [rip+0x330b]        # 0x7ffff7fb8f30
    7ffff7fb5c25:	85 c0                	test   eax,eax
    7ffff7fb5c27:	0f 95 c0             	setne  al
    7ffff7fb5c2a:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb5c2e:	c3                   	ret
    7ffff7fb5c2f:	48 8d 05 42 34 00 00 	lea    rax,[rip+0x3442]        # 0x7ffff7fb9078
    7ffff7fb5c36:	48 85 c0             	test   rax,rax
    7ffff7fb5c39:	74 17                	je     0x7ffff7fb5c52
    7ffff7fb5c3b:	48 8b 08             	mov    rcx,QWORD PTR [rax]
    7ffff7fb5c3e:	48 39 f9             	cmp    rcx,rdi
    7ffff7fb5c41:	77 09                	ja     0x7ffff7fb5c4c
    7ffff7fb5c43:	48 03 48 08          	add    rcx,QWORD PTR [rax+0x8]
    7ffff7fb5c47:	48 39 f9             	cmp    rcx,rdi
    7ffff7fb5c4a:	77 08                	ja     0x7ffff7fb5c54
    7ffff7fb5c4c:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
    7ffff7fb5c50:	eb e4                	jmp    0x7ffff7fb5c36
    7ffff7fb5c52:	31 c0                	xor    eax,eax
    7ffff7fb5c54:	c3                   	ret
    7ffff7fb5c55:	48 8d 0d 2c 34 00 00 	lea    rcx,[rip+0x342c]        # 0x7ffff7fb9088
    7ffff7fb5c5c:	31 c0                	xor    eax,eax
    7ffff7fb5c5e:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
    7ffff7fb5c61:	48 85 c9             	test   rcx,rcx
    7ffff7fb5c64:	74 09                	je     0x7ffff7fb5c6f
    7ffff7fb5c66:	48 83 c1 10          	add    rcx,0x10
    7ffff7fb5c6a:	48 ff c0             	inc    rax
    7ffff7fb5c6d:	eb ef                	jmp    0x7ffff7fb5c5e
    7ffff7fb5c6f:	48 3d 00 10 00 00    	cmp    rax,0x1000
    7ffff7fb5c75:	b9 ff 0f 00 00       	mov    ecx,0xfff
    7ffff7fb5c7a:	48 0f 43 c8          	cmovae rcx,rax
    7ffff7fb5c7e:	48 89 0d 63 36 00 00 	mov    QWORD PTR [rip+0x3663],rcx        # 0x7ffff7fb92e8
    7ffff7fb5c85:	c3                   	ret
    7ffff7fb5c86:	41 56                	push   r14
    7ffff7fb5c88:	53                   	push   rbx
    7ffff7fb5c89:	50                   	push   rax
    7ffff7fb5c8a:	49 89 f6             	mov    r14,rsi
    7ffff7fb5c8d:	48 89 fb             	mov    rbx,rdi
    7ffff7fb5c90:	48 89 f7             	mov    rdi,rsi
    7ffff7fb5c93:	e8 25 01 00 00       	call   0x7ffff7fb5dbd
    7ffff7fb5c98:	89 c1                	mov    ecx,eax
    7ffff7fb5c9a:	48 8d 15 d7 32 00 00 	lea    rdx,[rip+0x32d7]        # 0x7ffff7fb8f78
    7ffff7fb5ca1:	48 8d 0c ca          	lea    rcx,[rdx+rcx*8]
    7ffff7fb5ca5:	89 43 38             	mov    DWORD PTR [rbx+0x38],eax
    7ffff7fb5ca8:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb5cac:	c5 f8 11 43 20       	vmovups XMMWORD PTR [rbx+0x20],xmm0
    7ffff7fb5cb1:	8b 15 3d 36 00 00    	mov    edx,DWORD PTR [rip+0x363d]        # 0x7ffff7fb92f4
    7ffff7fb5cb7:	0f a3 c2             	bt     edx,eax
    7ffff7fb5cba:	73 59                	jae    0x7ffff7fb5d15
    7ffff7fb5cbc:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
    7ffff7fb5cbf:	89 c2                	mov    edx,eax
    7ffff7fb5cc1:	d0 ea                	shr    dl,1
    7ffff7fb5cc3:	40 b6 39             	mov    sil,0x39
    7ffff7fb5cc6:	40 28 d6             	sub    sil,dl
    7ffff7fb5cc9:	40 80 e6 3f          	and    sil,0x3f
    7ffff7fb5ccd:	31 d2                	xor    edx,edx
    7ffff7fb5ccf:	83 f8 1f             	cmp    eax,0x1f
    7ffff7fb5cd2:	40 0f b6 c6          	movzx  eax,sil
    7ffff7fb5cd6:	0f 44 c2             	cmove  eax,edx
    7ffff7fb5cd9:	c4 c2 f9 f7 d6       	shlx   rdx,r14,rax
    7ffff7fb5cde:	48 89 c8             	mov    rax,rcx
    7ffff7fb5ce1:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
    7ffff7fb5ce5:	48 83 e1 f8          	and    rcx,0xfffffffffffffff8
    7ffff7fb5ce9:	4c 39 f1             	cmp    rcx,r14
    7ffff7fb5cec:	74 48                	je     0x7ffff7fb5d36
    7ffff7fb5cee:	48 89 d6             	mov    rsi,rdx
    7ffff7fb5cf1:	48 c1 ee 3f          	shr    rsi,0x3f
    7ffff7fb5cf5:	48 8b 4c f0 20       	mov    rcx,QWORD PTR [rax+rsi*8+0x20]
    7ffff7fb5cfa:	48 01 d2             	add    rdx,rdx
    7ffff7fb5cfd:	48 85 c9             	test   rcx,rcx
    7ffff7fb5d00:	75 dc                	jne    0x7ffff7fb5cde
    7ffff7fb5d02:	48 8d 48 20          	lea    rcx,[rax+0x20]
    7ffff7fb5d06:	48 8d 0c f1          	lea    rcx,[rcx+rsi*8]
    7ffff7fb5d0a:	6a 10                	push   0x10
    7ffff7fb5d0c:	5a                   	pop    rdx
    7ffff7fb5d0d:	6a 30                	push   0x30
    7ffff7fb5d0f:	5e                   	pop    rsi
    7ffff7fb5d10:	48 89 c7             	mov    rdi,rax
    7ffff7fb5d13:	eb 19                	jmp    0x7ffff7fb5d2e
    7ffff7fb5d15:	6a 01                	push   0x1
    7ffff7fb5d17:	5e                   	pop    rsi
    7ffff7fb5d18:	c4 e2 79 f7 c6       	shlx   eax,esi,eax
    7ffff7fb5d1d:	09 c2                	or     edx,eax
    7ffff7fb5d1f:	89 15 cf 35 00 00    	mov    DWORD PTR [rip+0x35cf],edx        # 0x7ffff7fb92f4
    7ffff7fb5d25:	6a 10                	push   0x10
    7ffff7fb5d27:	5a                   	pop    rdx
    7ffff7fb5d28:	6a 30                	push   0x30
    7ffff7fb5d2a:	5e                   	pop    rsi
    7ffff7fb5d2b:	48 89 cf             	mov    rdi,rcx
    7ffff7fb5d2e:	48 89 d8             	mov    rax,rbx
    7ffff7fb5d31:	49 89 d8             	mov    r8,rbx
    7ffff7fb5d34:	eb 15                	jmp    0x7ffff7fb5d4b
    7ffff7fb5d36:	48 8d 48 10          	lea    rcx,[rax+0x10]
    7ffff7fb5d3a:	48 8b 78 10          	mov    rdi,QWORD PTR [rax+0x10]
    7ffff7fb5d3e:	48 89 5f 18          	mov    QWORD PTR [rdi+0x18],rbx
    7ffff7fb5d42:	6a 30                	push   0x30
    7ffff7fb5d44:	5a                   	pop    rdx
    7ffff7fb5d45:	6a 10                	push   0x10
    7ffff7fb5d47:	5e                   	pop    rsi
    7ffff7fb5d48:	45 31 c0             	xor    r8d,r8d
    7ffff7fb5d4b:	48 89 19             	mov    QWORD PTR [rcx],rbx
    7ffff7fb5d4e:	48 89 3c 33          	mov    QWORD PTR [rbx+rsi*1],rdi
    7ffff7fb5d52:	48 89 43 18          	mov    QWORD PTR [rbx+0x18],rax
    7ffff7fb5d56:	4c 89 04 13          	mov    QWORD PTR [rbx+rdx*1],r8
    7ffff7fb5d5a:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb5d5e:	5b                   	pop    rbx
    7ffff7fb5d5f:	41 5e                	pop    r14
    7ffff7fb5d61:	c3                   	ret
    7ffff7fb5d62:	48 b8 f8 ff ff ff 07 	movabs rax,0x7fffffff8
    7ffff7fb5d69:	00 00 00 
    7ffff7fb5d6c:	48 21 f0             	and    rax,rsi
    7ffff7fb5d6f:	48 8d 0d 02 32 00 00 	lea    rcx,[rip+0x3202]        # 0x7ffff7fb8f78
    7ffff7fb5d76:	48 8d 04 41          	lea    rax,[rcx+rax*2]
    7ffff7fb5d7a:	48 05 20 01 00 00    	add    rax,0x120
    7ffff7fb5d80:	8b 0d 6a 35 00 00    	mov    ecx,DWORD PTR [rip+0x356a]        # 0x7ffff7fb92f0
    7ffff7fb5d86:	40 c0 ee 03          	shr    sil,0x3
    7ffff7fb5d8a:	40 0f b6 d6          	movzx  edx,sil
    7ffff7fb5d8e:	0f a3 d1             	bt     ecx,edx
    7ffff7fb5d91:	73 06                	jae    0x7ffff7fb5d99
    7ffff7fb5d93:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
    7ffff7fb5d97:	eb 13                	jmp    0x7ffff7fb5dac
    7ffff7fb5d99:	6a 01                	push   0x1
    7ffff7fb5d9b:	5a                   	pop    rdx
    7ffff7fb5d9c:	c4 e2 49 f7 d2       	shlx   edx,edx,esi
    7ffff7fb5da1:	09 d1                	or     ecx,edx
    7ffff7fb5da3:	89 0d 47 35 00 00    	mov    DWORD PTR [rip+0x3547],ecx        # 0x7ffff7fb92f0
    7ffff7fb5da9:	48 89 c1             	mov    rcx,rax
    7ffff7fb5dac:	48 89 78 10          	mov    QWORD PTR [rax+0x10],rdi
    7ffff7fb5db0:	48 89 79 18          	mov    QWORD PTR [rcx+0x18],rdi
    7ffff7fb5db4:	48 89 4f 10          	mov    QWORD PTR [rdi+0x10],rcx
    7ffff7fb5db8:	48 89 47 18          	mov    QWORD PTR [rdi+0x18],rax
    7ffff7fb5dbc:	c3                   	ret
    7ffff7fb5dbd:	31 c0                	xor    eax,eax
    7ffff7fb5dbf:	48 81 ff 00 01 00 00 	cmp    rdi,0x100
    7ffff7fb5dc6:	72 0c                	jb     0x7ffff7fb5dd4
    7ffff7fb5dc8:	48 81 ff 00 00 00 01 	cmp    rdi,0x1000000
    7ffff7fb5dcf:	72 04                	jb     0x7ffff7fb5dd5
    7ffff7fb5dd1:	6a 1f                	push   0x1f
    7ffff7fb5dd3:	58                   	pop    rax
    7ffff7fb5dd4:	c3                   	ret
    7ffff7fb5dd5:	48 89 f8             	mov    rax,rdi
    7ffff7fb5dd8:	48 c1 e8 08          	shr    rax,0x8
    7ffff7fb5ddc:	f3 48 0f bd c8       	lzcnt  rcx,rax
    7ffff7fb5de1:	6a 06                	push   0x6
    7ffff7fb5de3:	5a                   	pop    rdx
    7ffff7fb5de4:	29 ca                	sub    edx,ecx
    7ffff7fb5de6:	01 c9                	add    ecx,ecx
    7ffff7fb5de8:	31 c0                	xor    eax,eax
    7ffff7fb5dea:	48 0f a3 d7          	bt     rdi,rdx
    7ffff7fb5dee:	83 d0 7e             	adc    eax,0x7e
    7ffff7fb5df1:	29 c8                	sub    eax,ecx
    7ffff7fb5df3:	c3                   	ret
    7ffff7fb5df4:	48 8b 4f 18          	mov    rcx,QWORD PTR [rdi+0x18]
    7ffff7fb5df8:	48 8b 47 30          	mov    rax,QWORD PTR [rdi+0x30]
    7ffff7fb5dfc:	48 39 f9             	cmp    rcx,rdi
    7ffff7fb5dff:	74 0e                	je     0x7ffff7fb5e0f
    7ffff7fb5e01:	48 8b 57 10          	mov    rdx,QWORD PTR [rdi+0x10]
    7ffff7fb5e05:	48 89 4a 18          	mov    QWORD PTR [rdx+0x18],rcx
    7ffff7fb5e09:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
    7ffff7fb5e0d:	eb 4b                	jmp    0x7ffff7fb5e5a
    7ffff7fb5e0f:	48 8d 57 28          	lea    rdx,[rdi+0x28]
    7ffff7fb5e13:	48 8d 4f 20          	lea    rcx,[rdi+0x20]
    7ffff7fb5e17:	31 f6                	xor    esi,esi
    7ffff7fb5e19:	48 83 7f 28 00       	cmp    QWORD PTR [rdi+0x28],0x0
    7ffff7fb5e1e:	40 0f 95 c6          	setne  sil
    7ffff7fb5e22:	48 0f 44 d1          	cmove  rdx,rcx
    7ffff7fb5e26:	48 8b 74 f7 20       	mov    rsi,QWORD PTR [rdi+rsi*8+0x20]
    7ffff7fb5e2b:	48 85 f6             	test   rsi,rsi
    7ffff7fb5e2e:	74 28                	je     0x7ffff7fb5e58
    7ffff7fb5e30:	49 89 d0             	mov    r8,rdx
    7ffff7fb5e33:	48 89 f1             	mov    rcx,rsi
    7ffff7fb5e36:	48 8b 76 28          	mov    rsi,QWORD PTR [rsi+0x28]
    7ffff7fb5e3a:	48 85 f6             	test   rsi,rsi
    7ffff7fb5e3d:	74 06                	je     0x7ffff7fb5e45
    7ffff7fb5e3f:	48 8d 51 28          	lea    rdx,[rcx+0x28]
    7ffff7fb5e43:	eb 08                	jmp    0x7ffff7fb5e4d
    7ffff7fb5e45:	48 8d 51 20          	lea    rdx,[rcx+0x20]
    7ffff7fb5e49:	48 8b 71 20          	mov    rsi,QWORD PTR [rcx+0x20]
    7ffff7fb5e4d:	48 85 f6             	test   rsi,rsi
    7ffff7fb5e50:	75 de                	jne    0x7ffff7fb5e30
    7ffff7fb5e52:	49 83 20 00          	and    QWORD PTR [r8],0x0
    7ffff7fb5e56:	eb 02                	jmp    0x7ffff7fb5e5a
    7ffff7fb5e58:	31 c9                	xor    ecx,ecx
    7ffff7fb5e5a:	48 85 c0             	test   rax,rax
    7ffff7fb5e5d:	74 23                	je     0x7ffff7fb5e82
    7ffff7fb5e5f:	8b 57 38             	mov    edx,DWORD PTR [rdi+0x38]
    7ffff7fb5e62:	48 8d 35 0f 31 00 00 	lea    rsi,[rip+0x310f]        # 0x7ffff7fb8f78
    7ffff7fb5e69:	48 39 3c d6          	cmp    QWORD PTR [rsi+rdx*8],rdi
    7ffff7fb5e6d:	74 14                	je     0x7ffff7fb5e83
    7ffff7fb5e6f:	31 d2                	xor    edx,edx
    7ffff7fb5e71:	48 39 78 20          	cmp    QWORD PTR [rax+0x20],rdi
    7ffff7fb5e75:	0f 95 c2             	setne  dl
    7ffff7fb5e78:	48 89 4c d0 20       	mov    QWORD PTR [rax+rdx*8+0x20],rcx
    7ffff7fb5e7d:	48 85 c9             	test   rcx,rcx
    7ffff7fb5e80:	75 0a                	jne    0x7ffff7fb5e8c
    7ffff7fb5e82:	c3                   	ret
    7ffff7fb5e83:	48 89 0c d6          	mov    QWORD PTR [rsi+rdx*8],rcx
    7ffff7fb5e87:	48 85 c9             	test   rcx,rcx
    7ffff7fb5e8a:	74 27                	je     0x7ffff7fb5eb3
    7ffff7fb5e8c:	48 89 41 30          	mov    QWORD PTR [rcx+0x30],rax
    7ffff7fb5e90:	48 8b 47 20          	mov    rax,QWORD PTR [rdi+0x20]
    7ffff7fb5e94:	48 85 c0             	test   rax,rax
    7ffff7fb5e97:	74 08                	je     0x7ffff7fb5ea1
    7ffff7fb5e99:	48 89 41 20          	mov    QWORD PTR [rcx+0x20],rax
    7ffff7fb5e9d:	48 89 48 30          	mov    QWORD PTR [rax+0x30],rcx
    7ffff7fb5ea1:	48 8b 47 28          	mov    rax,QWORD PTR [rdi+0x28]
    7ffff7fb5ea5:	48 85 c0             	test   rax,rax
    7ffff7fb5ea8:	74 d8                	je     0x7ffff7fb5e82
    7ffff7fb5eaa:	48 89 41 28          	mov    QWORD PTR [rcx+0x28],rax
    7ffff7fb5eae:	48 89 48 30          	mov    QWORD PTR [rax+0x30],rcx
    7ffff7fb5eb2:	c3                   	ret
    7ffff7fb5eb3:	8a 4f 38             	mov    cl,BYTE PTR [rdi+0x38]
    7ffff7fb5eb6:	6a fe                	push   0xfffffffffffffffe
    7ffff7fb5eb8:	58                   	pop    rax
    7ffff7fb5eb9:	d3 c0                	rol    eax,cl
    7ffff7fb5ebb:	21 05 33 34 00 00    	and    DWORD PTR [rip+0x3433],eax        # 0x7ffff7fb92f4
    7ffff7fb5ec1:	c3                   	ret
    7ffff7fb5ec2:	48 81 fe 00 01 00 00 	cmp    rsi,0x100
    7ffff7fb5ec9:	0f 82 93 fe ff ff    	jb     0x7ffff7fb5d62
    7ffff7fb5ecf:	e9 b2 fd ff ff       	jmp    0x7ffff7fb5c86
    7ffff7fb5ed4:	48 39 fe             	cmp    rsi,rdi
    7ffff7fb5ed7:	74 09                	je     0x7ffff7fb5ee2
    7ffff7fb5ed9:	48 89 7e 18          	mov    QWORD PTR [rsi+0x18],rdi
    7ffff7fb5edd:	48 89 77 10          	mov    QWORD PTR [rdi+0x10],rsi
    7ffff7fb5ee1:	c3                   	ret
    7ffff7fb5ee2:	6a fe                	push   0xfffffffffffffffe
    7ffff7fb5ee4:	58                   	pop    rax
    7ffff7fb5ee5:	89 d1                	mov    ecx,edx
    7ffff7fb5ee7:	d3 c0                	rol    eax,cl
    7ffff7fb5ee9:	21 05 01 34 00 00    	and    DWORD PTR [rip+0x3401],eax        # 0x7ffff7fb92f0
    7ffff7fb5eef:	c3                   	ret
    7ffff7fb5ef0:	41 56                	push   r14
    7ffff7fb5ef2:	53                   	push   rbx
    7ffff7fb5ef3:	50                   	push   rax
    7ffff7fb5ef4:	49 89 f6             	mov    r14,rsi
    7ffff7fb5ef7:	48 89 fb             	mov    rbx,rdi
    7ffff7fb5efa:	48 8b 35 a7 33 00 00 	mov    rsi,QWORD PTR [rip+0x33a7]        # 0x7ffff7fb92a8
    7ffff7fb5f01:	48 85 f6             	test   rsi,rsi
    7ffff7fb5f04:	74 0c                	je     0x7ffff7fb5f12
    7ffff7fb5f06:	48 8b 3d ab 33 00 00 	mov    rdi,QWORD PTR [rip+0x33ab]        # 0x7ffff7fb92b8
    7ffff7fb5f0d:	e8 50 fe ff ff       	call   0x7ffff7fb5d62
    7ffff7fb5f12:	4c 89 35 8f 33 00 00 	mov    QWORD PTR [rip+0x338f],r14        # 0x7ffff7fb92a8
    7ffff7fb5f19:	48 89 1d 98 33 00 00 	mov    QWORD PTR [rip+0x3398],rbx        # 0x7ffff7fb92b8
    7ffff7fb5f20:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb5f24:	5b                   	pop    rbx
    7ffff7fb5f25:	41 5e                	pop    r14
    7ffff7fb5f27:	c3                   	ret
    7ffff7fb5f28:	48 8d 47 1f          	lea    rax,[rdi+0x1f]
    7ffff7fb5f2c:	48 83 e0 f0          	and    rax,0xfffffffffffffff0
    7ffff7fb5f30:	48 8d 48 f0          	lea    rcx,[rax-0x10]
    7ffff7fb5f34:	48 89 fa             	mov    rdx,rdi
    7ffff7fb5f37:	48 29 c2             	sub    rdx,rax
    7ffff7fb5f3a:	48 01 f2             	add    rdx,rsi
    7ffff7fb5f3d:	48 83 c2 10          	add    rdx,0x10
    7ffff7fb5f41:	48 89 0d 78 33 00 00 	mov    QWORD PTR [rip+0x3378],rcx        # 0x7ffff7fb92c0
    7ffff7fb5f48:	48 89 15 61 33 00 00 	mov    QWORD PTR [rip+0x3361],rdx        # 0x7ffff7fb92b0
    7ffff7fb5f4f:	48 83 ca 01          	or     rdx,0x1
    7ffff7fb5f53:	48 89 50 f8          	mov    QWORD PTR [rax-0x8],rdx
    7ffff7fb5f57:	48 c7 44 37 08 50 00 	mov    QWORD PTR [rdi+rsi*1+0x8],0x50
    7ffff7fb5f5e:	00 00 
    7ffff7fb5f60:	48 c7 05 6d 33 00 00 	mov    QWORD PTR [rip+0x336d],0x200000        # 0x7ffff7fb92d8
    7ffff7fb5f67:	00 00 20 00 
    7ffff7fb5f6b:	c3                   	ret
    7ffff7fb5f6c:	48 89 f2             	mov    rdx,rsi
    7ffff7fb5f6f:	31 c9                	xor    ecx,ecx
    7ffff7fb5f71:	6a 01                	push   0x1
    7ffff7fb5f73:	58                   	pop    rax
    7ffff7fb5f74:	48 39 ca             	cmp    rdx,rcx
    7ffff7fb5f77:	74 0b                	je     0x7ffff7fb5f84
    7ffff7fb5f79:	80 3c 0f 0a          	cmp    BYTE PTR [rdi+rcx*1],0xa
    7ffff7fb5f7d:	74 08                	je     0x7ffff7fb5f87
    7ffff7fb5f7f:	48 ff c1             	inc    rcx
    7ffff7fb5f82:	eb f0                	jmp    0x7ffff7fb5f74
    7ffff7fb5f84:	31 c0                	xor    eax,eax
    7ffff7fb5f86:	c3                   	ret
    7ffff7fb5f87:	48 89 ca             	mov    rdx,rcx
    7ffff7fb5f8a:	c3                   	ret
    7ffff7fb5f8b:	48 89 f8             	mov    rax,rdi
    7ffff7fb5f8e:	8a 0d 6c 33 00 00    	mov    cl,BYTE PTR [rip+0x336c]        # 0x7ffff7fb9300
    7ffff7fb5f94:	48 89 f7             	mov    rdi,rsi
    7ffff7fb5f97:	48 89 c6             	mov    rsi,rax
    7ffff7fb5f9a:	e9 66 d3 ff ff       	jmp    0x7ffff7fb3305
    7ffff7fb5f9f:	48 c1 e6 03          	shl    rsi,0x3
    7ffff7fb5fa3:	31 c9                	xor    ecx,ecx
    7ffff7fb5fa5:	48 89 c8             	mov    rax,rcx
    7ffff7fb5fa8:	48 39 ce             	cmp    rsi,rcx
    7ffff7fb5fab:	74 0a                	je     0x7ffff7fb5fb7
    7ffff7fb5fad:	48 8d 48 08          	lea    rcx,[rax+0x8]
    7ffff7fb5fb1:	48 ff 04 07          	inc    QWORD PTR [rdi+rax*1]
    7ffff7fb5fb5:	74 ee                	je     0x7ffff7fb5fa5
    7ffff7fb5fb7:	48 39 c6             	cmp    rsi,rax
    7ffff7fb5fba:	0f 94 c0             	sete   al
    7ffff7fb5fbd:	c3                   	ret
    7ffff7fb5fbe:	48 c1 e6 03          	shl    rsi,0x3
    7ffff7fb5fc2:	31 c9                	xor    ecx,ecx
    7ffff7fb5fc4:	48 89 c8             	mov    rax,rcx
    7ffff7fb5fc7:	48 39 ce             	cmp    rsi,rcx
    7ffff7fb5fca:	74 0b                	je     0x7ffff7fb5fd7
    7ffff7fb5fcc:	48 8d 48 08          	lea    rcx,[rax+0x8]
    7ffff7fb5fd0:	48 83 2c 07 01       	sub    QWORD PTR [rdi+rax*1],0x1
    7ffff7fb5fd5:	72 ed                	jb     0x7ffff7fb5fc4
    7ffff7fb5fd7:	48 39 c6             	cmp    rsi,rax
    7ffff7fb5fda:	0f 94 c0             	sete   al
    7ffff7fb5fdd:	c3                   	ret
    7ffff7fb5fde:	48 39 ce             	cmp    rsi,rcx
    7ffff7fb5fe1:	48 0f 42 ce          	cmovb  rcx,rsi
    7ffff7fb5fe5:	31 f6                	xor    esi,esi
    7ffff7fb5fe7:	31 c0                	xor    eax,eax
    7ffff7fb5fe9:	48 39 f1             	cmp    rcx,rsi
    7ffff7fb5fec:	74 18                	je     0x7ffff7fb6006
    7ffff7fb5fee:	4c 8b 04 f2          	mov    r8,QWORD PTR [rdx+rsi*8]
    7ffff7fb5ff2:	0f b6 c0             	movzx  eax,al
    7ffff7fb5ff5:	0f ba e0 00          	bt     eax,0x0
    7ffff7fb5ff9:	4c 11 04 f7          	adc    QWORD PTR [rdi+rsi*8],r8
    7ffff7fb5ffd:	48 8d 76 01          	lea    rsi,[rsi+0x1]
    7ffff7fb6001:	0f 92 c0             	setb   al
    7ffff7fb6004:	eb e3                	jmp    0x7ffff7fb5fe9
    7ffff7fb6006:	24 01                	and    al,0x1
    7ffff7fb6008:	c3                   	ret
    7ffff7fb6009:	41 57                	push   r15
    7ffff7fb600b:	41 56                	push   r14
    7ffff7fb600d:	53                   	push   rbx
    7ffff7fb600e:	48 89 cb             	mov    rbx,rcx
    7ffff7fb6011:	49 89 f6             	mov    r14,rsi
    7ffff7fb6014:	49 89 ff             	mov    r15,rdi
    7ffff7fb6017:	48 89 ce             	mov    rsi,rcx
    7ffff7fb601a:	e8 bf ff ff ff       	call   0x7ffff7fb5fde
    7ffff7fb601f:	84 c0                	test   al,al
    7ffff7fb6021:	74 14                	je     0x7ffff7fb6037
    7ffff7fb6023:	49 29 de             	sub    r14,rbx
    7ffff7fb6026:	49 8d 3c df          	lea    rdi,[r15+rbx*8]
    7ffff7fb602a:	4c 89 f6             	mov    rsi,r14
    7ffff7fb602d:	5b                   	pop    rbx
    7ffff7fb602e:	41 5e                	pop    r14
    7ffff7fb6030:	41 5f                	pop    r15
    7ffff7fb6032:	e9 68 ff ff ff       	jmp    0x7ffff7fb5f9f
    7ffff7fb6037:	31 c0                	xor    eax,eax
    7ffff7fb6039:	5b                   	pop    rbx
    7ffff7fb603a:	41 5e                	pop    r14
    7ffff7fb603c:	41 5f                	pop    r15
    7ffff7fb603e:	c3                   	ret
    7ffff7fb603f:	41 57                	push   r15
    7ffff7fb6041:	41 56                	push   r14
    7ffff7fb6043:	53                   	push   rbx
    7ffff7fb6044:	48 89 cb             	mov    rbx,rcx
    7ffff7fb6047:	49 89 f6             	mov    r14,rsi
    7ffff7fb604a:	49 89 ff             	mov    r15,rdi
    7ffff7fb604d:	48 89 ce             	mov    rsi,rcx
    7ffff7fb6050:	e8 20 00 00 00       	call   0x7ffff7fb6075
    7ffff7fb6055:	84 c0                	test   al,al
    7ffff7fb6057:	74 14                	je     0x7ffff7fb606d
    7ffff7fb6059:	49 29 de             	sub    r14,rbx
    7ffff7fb605c:	49 8d 3c df          	lea    rdi,[r15+rbx*8]
    7ffff7fb6060:	4c 89 f6             	mov    rsi,r14
    7ffff7fb6063:	5b                   	pop    rbx
    7ffff7fb6064:	41 5e                	pop    r14
    7ffff7fb6066:	41 5f                	pop    r15
    7ffff7fb6068:	e9 51 ff ff ff       	jmp    0x7ffff7fb5fbe
    7ffff7fb606d:	31 c0                	xor    eax,eax
    7ffff7fb606f:	5b                   	pop    rbx
    7ffff7fb6070:	41 5e                	pop    r14
    7ffff7fb6072:	41 5f                	pop    r15
    7ffff7fb6074:	c3                   	ret
    7ffff7fb6075:	48 39 ce             	cmp    rsi,rcx
    7ffff7fb6078:	48 0f 42 ce          	cmovb  rcx,rsi
    7ffff7fb607c:	31 f6                	xor    esi,esi
    7ffff7fb607e:	31 c0                	xor    eax,eax
    7ffff7fb6080:	48 39 f1             	cmp    rcx,rsi
    7ffff7fb6083:	74 18                	je     0x7ffff7fb609d
    7ffff7fb6085:	4c 8b 04 f2          	mov    r8,QWORD PTR [rdx+rsi*8]
    7ffff7fb6089:	0f b6 c0             	movzx  eax,al
    7ffff7fb608c:	0f ba e0 00          	bt     eax,0x0
    7ffff7fb6090:	4c 19 04 f7          	sbb    QWORD PTR [rdi+rsi*8],r8
    7ffff7fb6094:	48 8d 76 01          	lea    rsi,[rsi+0x1]
    7ffff7fb6098:	0f 92 c0             	setb   al
    7ffff7fb609b:	eb e3                	jmp    0x7ffff7fb6080
    7ffff7fb609d:	24 01                	and    al,0x1
    7ffff7fb609f:	c3                   	ret
    7ffff7fb60a0:	48 39 ce             	cmp    rsi,rcx
    7ffff7fb60a3:	48 0f 42 ce          	cmovb  rcx,rsi
    7ffff7fb60a7:	31 f6                	xor    esi,esi
    7ffff7fb60a9:	31 c0                	xor    eax,eax
    7ffff7fb60ab:	48 39 f1             	cmp    rcx,rsi
    7ffff7fb60ae:	74 1c                	je     0x7ffff7fb60cc
    7ffff7fb60b0:	4c 8b 04 f7          	mov    r8,QWORD PTR [rdi+rsi*8]
    7ffff7fb60b4:	0f b6 c0             	movzx  eax,al
    7ffff7fb60b7:	0f ba e0 00          	bt     eax,0x0
    7ffff7fb60bb:	4c 1b 04 f2          	sbb    r8,QWORD PTR [rdx+rsi*8]
    7ffff7fb60bf:	4c 89 04 f2          	mov    QWORD PTR [rdx+rsi*8],r8
    7ffff7fb60c3:	48 8d 76 01          	lea    rsi,[rsi+0x1]
    7ffff7fb60c7:	0f 92 c0             	setb   al
    7ffff7fb60ca:	eb df                	jmp    0x7ffff7fb60ab
    7ffff7fb60cc:	24 01                	and    al,0x1
    7ffff7fb60ce:	c3                   	ret
    7ffff7fb60cf:	55                   	push   rbp
    7ffff7fb60d0:	41 57                	push   r15
    7ffff7fb60d2:	41 56                	push   r14
    7ffff7fb60d4:	41 54                	push   r12
    7ffff7fb60d6:	53                   	push   rbx
    7ffff7fb60d7:	48 89 d3             	mov    rbx,rdx
    7ffff7fb60da:	49 89 fe             	mov    r14,rdi
    7ffff7fb60dd:	48 ff ce             	dec    rsi
    7ffff7fb60e0:	45 31 ff             	xor    r15d,r15d
    7ffff7fb60e3:	48 89 f2             	mov    rdx,rsi
    7ffff7fb60e6:	48 83 fe ff          	cmp    rsi,0xffffffffffffffff
    7ffff7fb60ea:	74 12                	je     0x7ffff7fb60fe
    7ffff7fb60ec:	48 8d 72 ff          	lea    rsi,[rdx-0x1]
    7ffff7fb60f0:	49 83 3c d6 00       	cmp    QWORD PTR [r14+rdx*8],0x0
    7ffff7fb60f5:	74 ec                	je     0x7ffff7fb60e3
    7ffff7fb60f7:	48 83 c6 02          	add    rsi,0x2
    7ffff7fb60fb:	49 89 f7             	mov    r15,rsi
    7ffff7fb60fe:	48 ff c1             	inc    rcx
    7ffff7fb6101:	48 83 f9 01          	cmp    rcx,0x1
    7ffff7fb6105:	74 11                	je     0x7ffff7fb6118
    7ffff7fb6107:	48 8d 41 ff          	lea    rax,[rcx-0x1]
    7ffff7fb610b:	48 83 7c cb f0 00    	cmp    QWORD PTR [rbx+rcx*8-0x10],0x0
    7ffff7fb6111:	48 89 c1             	mov    rcx,rax
    7ffff7fb6114:	74 eb                	je     0x7ffff7fb6101
    7ffff7fb6116:	eb 02                	jmp    0x7ffff7fb611a
    7ffff7fb6118:	31 c0                	xor    eax,eax
    7ffff7fb611a:	31 f6                	xor    esi,esi
    7ffff7fb611c:	49 89 c4             	mov    r12,rax
    7ffff7fb611f:	4d 29 fc             	sub    r12,r15
    7ffff7fb6122:	40 0f 95 c6          	setne  sil
    7ffff7fb6126:	b9 ff 00 00 00       	mov    ecx,0xff
    7ffff7fb612b:	0f 46 ce             	cmovbe ecx,esi
    7ffff7fb612e:	80 f9 ff             	cmp    cl,0xff
    7ffff7fb6131:	74 1e                	je     0x7ffff7fb6151
    7ffff7fb6133:	0f b6 c9             	movzx  ecx,cl
    7ffff7fb6136:	83 f9 01             	cmp    ecx,0x1
    7ffff7fb6139:	75 56                	jne    0x7ffff7fb6191
    7ffff7fb613b:	4c 89 f7             	mov    rdi,r14
    7ffff7fb613e:	4c 89 fe             	mov    rsi,r15
    7ffff7fb6141:	48 89 da             	mov    rdx,rbx
    7ffff7fb6144:	48 89 c1             	mov    rcx,rax
    7ffff7fb6147:	e8 f3 fe ff ff       	call   0x7ffff7fb603f
    7ffff7fb614c:	e9 84 00 00 00       	jmp    0x7ffff7fb61d5
    7ffff7fb6151:	48 89 df             	mov    rdi,rbx
    7ffff7fb6154:	4c 89 fe             	mov    rsi,r15
    7ffff7fb6157:	4c 89 f2             	mov    rdx,r14
    7ffff7fb615a:	4c 89 f9             	mov    rcx,r15
    7ffff7fb615d:	e8 3e ff ff ff       	call   0x7ffff7fb60a0
    7ffff7fb6162:	89 c5                	mov    ebp,eax
    7ffff7fb6164:	4a 8d 34 fb          	lea    rsi,[rbx+r15*8]
    7ffff7fb6168:	4f 8d 34 fe          	lea    r14,[r14+r15*8]
    7ffff7fb616c:	4a 8d 14 e5 00 00 00 	lea    rdx,[r12*8+0x0]
    7ffff7fb6173:	00 
    7ffff7fb6174:	4c 89 f7             	mov    rdi,r14
    7ffff7fb6177:	ff 15 eb 29 00 00    	call   QWORD PTR [rip+0x29eb]        # 0x7ffff7fb8b68
    7ffff7fb617d:	b3 01                	mov    bl,0x1
    7ffff7fb617f:	40 84 ed             	test   bpl,bpl
    7ffff7fb6182:	74 53                	je     0x7ffff7fb61d7
    7ffff7fb6184:	4c 89 f7             	mov    rdi,r14
    7ffff7fb6187:	4c 89 e6             	mov    rsi,r12
    7ffff7fb618a:	e8 2f fe ff ff       	call   0x7ffff7fb5fbe
    7ffff7fb618f:	eb 46                	jmp    0x7ffff7fb61d7
    7ffff7fb6191:	b8 ff 00 00 00       	mov    eax,0xff
    7ffff7fb6196:	48 89 d1             	mov    rcx,rdx
    7ffff7fb6199:	48 ff c1             	inc    rcx
    7ffff7fb619c:	74 37                	je     0x7ffff7fb61d5
    7ffff7fb619e:	49 8b 3c d6          	mov    rdi,QWORD PTR [r14+rdx*8]
    7ffff7fb61a2:	31 f6                	xor    esi,esi
    7ffff7fb61a4:	48 3b 3c d3          	cmp    rdi,QWORD PTR [rbx+rdx*8]
    7ffff7fb61a8:	40 0f 95 c6          	setne  sil
    7ffff7fb61ac:	0f 42 f0             	cmovb  esi,eax
    7ffff7fb61af:	40 84 f6             	test   sil,sil
    7ffff7fb61b2:	75 0a                	jne    0x7ffff7fb61be
    7ffff7fb61b4:	49 83 24 d6 00       	and    QWORD PTR [r14+rdx*8],0x0
    7ffff7fb61b9:	48 ff ca             	dec    rdx
    7ffff7fb61bc:	eb d8                	jmp    0x7ffff7fb6196
    7ffff7fb61be:	40 0f b6 c6          	movzx  eax,sil
    7ffff7fb61c2:	83 f8 01             	cmp    eax,0x1
    7ffff7fb61c5:	75 1b                	jne    0x7ffff7fb61e2
    7ffff7fb61c7:	4c 89 f7             	mov    rdi,r14
    7ffff7fb61ca:	48 89 ce             	mov    rsi,rcx
    7ffff7fb61cd:	48 89 da             	mov    rdx,rbx
    7ffff7fb61d0:	e8 a0 fe ff ff       	call   0x7ffff7fb6075
    7ffff7fb61d5:	31 db                	xor    ebx,ebx
    7ffff7fb61d7:	89 d8                	mov    eax,ebx
    7ffff7fb61d9:	5b                   	pop    rbx
    7ffff7fb61da:	41 5c                	pop    r12
    7ffff7fb61dc:	41 5e                	pop    r14
    7ffff7fb61de:	41 5f                	pop    r15
    7ffff7fb61e0:	5d                   	pop    rbp
    7ffff7fb61e1:	c3                   	ret
    7ffff7fb61e2:	48 89 df             	mov    rdi,rbx
    7ffff7fb61e5:	48 89 ce             	mov    rsi,rcx
    7ffff7fb61e8:	4c 89 f2             	mov    rdx,r14
    7ffff7fb61eb:	e8 b0 fe ff ff       	call   0x7ffff7fb60a0
    7ffff7fb61f0:	b3 01                	mov    bl,0x1
    7ffff7fb61f2:	eb e3                	jmp    0x7ffff7fb61d7
    7ffff7fb61f4:	41 56                	push   r14
    7ffff7fb61f6:	53                   	push   rbx
    7ffff7fb61f7:	50                   	push   rax
    7ffff7fb61f8:	48 89 f3             	mov    rbx,rsi
    7ffff7fb61fb:	49 89 fe             	mov    r14,rdi
    7ffff7fb61fe:	48 8b 76 08          	mov    rsi,QWORD PTR [rsi+0x8]
    7ffff7fb6202:	48 85 f6             	test   rsi,rsi
    7ffff7fb6205:	74 49                	je     0x7ffff7fb6250
    7ffff7fb6207:	48 8b 03             	mov    rax,QWORD PTR [rbx]
    7ffff7fb620a:	48 83 7c f0 f8 00    	cmp    QWORD PTR [rax+rsi*8-0x8],0x0
    7ffff7fb6210:	75 0b                	jne    0x7ffff7fb621d
    7ffff7fb6212:	48 ff ce             	dec    rsi
    7ffff7fb6215:	48 89 73 08          	mov    QWORD PTR [rbx+0x8],rsi
    7ffff7fb6219:	75 ef                	jne    0x7ffff7fb620a
    7ffff7fb621b:	eb 33                	jmp    0x7ffff7fb6250
    7ffff7fb621d:	48 85 f6             	test   rsi,rsi
    7ffff7fb6220:	74 2e                	je     0x7ffff7fb6250
    7ffff7fb6222:	48 83 fe 01          	cmp    rsi,0x1
    7ffff7fb6226:	74 4c                	je     0x7ffff7fb6274
    7ffff7fb6228:	48 83 fe 02          	cmp    rsi,0x2
    7ffff7fb622c:	75 5e                	jne    0x7ffff7fb628c
    7ffff7fb622e:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
    7ffff7fb6231:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
    7ffff7fb6235:	48 83 f8 01          	cmp    rax,0x1
    7ffff7fb6239:	6a 02                	push   0x2
    7ffff7fb623b:	59                   	pop    rcx
    7ffff7fb623c:	48 83 d9 00          	sbb    rcx,0x0
    7ffff7fb6240:	48 8b 17             	mov    rdx,QWORD PTR [rdi]
    7ffff7fb6243:	49 89 16             	mov    QWORD PTR [r14],rdx
    7ffff7fb6246:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
    7ffff7fb624a:	49 89 4e 10          	mov    QWORD PTR [r14+0x10],rcx
    7ffff7fb624e:	eb 14                	jmp    0x7ffff7fb6264
    7ffff7fb6250:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb6254:	c4 c1 78 11 06       	vmovups XMMWORD PTR [r14],xmm0
    7ffff7fb6259:	49 c7 46 10 01 00 00 	mov    QWORD PTR [r14+0x10],0x1
    7ffff7fb6260:	00 
    7ffff7fb6261:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
    7ffff7fb6264:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
    7ffff7fb6268:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb626c:	5b                   	pop    rbx
    7ffff7fb626d:	41 5e                	pop    r14
    7ffff7fb626f:	e9 fc 00 00 00       	jmp    0x7ffff7fb6370
    7ffff7fb6274:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
    7ffff7fb6277:	48 8b 07             	mov    rax,QWORD PTR [rdi]
    7ffff7fb627a:	49 89 06             	mov    QWORD PTR [r14],rax
    7ffff7fb627d:	49 83 66 08 00       	and    QWORD PTR [r14+0x8],0x0
    7ffff7fb6282:	49 c7 46 10 01 00 00 	mov    QWORD PTR [r14+0x10],0x1
    7ffff7fb6289:	00 
    7ffff7fb628a:	eb d8                	jmp    0x7ffff7fb6264
    7ffff7fb628c:	48 89 f0             	mov    rax,rsi
    7ffff7fb628f:	48 c1 e8 02          	shr    rax,0x2
    7ffff7fb6293:	48 01 f0             	add    rax,rsi
    7ffff7fb6296:	48 83 c0 04          	add    rax,0x4
    7ffff7fb629a:	48 b9 ff ff ff ff ff 	movabs rcx,0x3ffffffffffffff
    7ffff7fb62a1:	ff ff 03 
    7ffff7fb62a4:	48 39 c8             	cmp    rax,rcx
    7ffff7fb62a7:	48 0f 42 c8          	cmovb  rcx,rax
    7ffff7fb62ab:	48 39 4b 10          	cmp    QWORD PTR [rbx+0x10],rcx
    7ffff7fb62af:	76 08                	jbe    0x7ffff7fb62b9
    7ffff7fb62b1:	48 89 df             	mov    rdi,rbx
    7ffff7fb62b4:	e8 5f 00 00 00       	call   0x7ffff7fb6318
    7ffff7fb62b9:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    7ffff7fb62bd:	49 89 46 10          	mov    QWORD PTR [r14+0x10],rax
    7ffff7fb62c1:	c5 f8 10 03          	vmovups xmm0,XMMWORD PTR [rbx]
    7ffff7fb62c5:	c4 c1 78 11 06       	vmovups XMMWORD PTR [r14],xmm0
    7ffff7fb62ca:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb62ce:	5b                   	pop    rbx
    7ffff7fb62cf:	41 5e                	pop    r14
    7ffff7fb62d1:	c3                   	ret
    7ffff7fb62d2:	48 85 f6             	test   rsi,rsi
    7ffff7fb62d5:	74 2f                	je     0x7ffff7fb6306
    7ffff7fb62d7:	41 56                	push   r14
    7ffff7fb62d9:	53                   	push   rbx
    7ffff7fb62da:	50                   	push   rax
    7ffff7fb62db:	49 89 f6             	mov    r14,rsi
    7ffff7fb62de:	48 89 fb             	mov    rbx,rdi
    7ffff7fb62e1:	48 8b 77 08          	mov    rsi,QWORD PTR [rdi+0x8]
    7ffff7fb62e5:	48 ff c6             	inc    rsi
    7ffff7fb62e8:	e8 1a 00 00 00       	call   0x7ffff7fb6307
    7ffff7fb62ed:	48 8b 03             	mov    rax,QWORD PTR [rbx]
    7ffff7fb62f0:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
    7ffff7fb62f4:	4c 89 34 c8          	mov    QWORD PTR [rax+rcx*8],r14
    7ffff7fb62f8:	48 ff c1             	inc    rcx
    7ffff7fb62fb:	48 89 4b 08          	mov    QWORD PTR [rbx+0x8],rcx
    7ffff7fb62ff:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb6303:	5b                   	pop    rbx
    7ffff7fb6304:	41 5e                	pop    r14
    7ffff7fb6306:	c3                   	ret
    7ffff7fb6307:	48 83 fe 03          	cmp    rsi,0x3
    7ffff7fb630b:	72 0a                	jb     0x7ffff7fb6317
    7ffff7fb630d:	48 39 77 10          	cmp    QWORD PTR [rdi+0x10],rsi
    7ffff7fb6311:	0f 82 01 00 00 00    	jb     0x7ffff7fb6318
    7ffff7fb6317:	c3                   	ret
    7ffff7fb6318:	48 89 f0             	mov    rax,rsi
    7ffff7fb631b:	48 c1 e8 03          	shr    rax,0x3
    7ffff7fb631f:	48 01 f0             	add    rax,rsi
    7ffff7fb6322:	48 83 c0 02          	add    rax,0x2
    7ffff7fb6326:	48 be ff ff ff ff ff 	movabs rsi,0x3ffffffffffffff
    7ffff7fb632d:	ff ff 03 
    7ffff7fb6330:	48 39 f0             	cmp    rax,rsi
    7ffff7fb6333:	48 0f 42 f0          	cmovb  rsi,rax
    7ffff7fb6337:	e9 00 00 00 00       	jmp    0x7ffff7fb633c
    7ffff7fb633c:	41 56                	push   r14
    7ffff7fb633e:	53                   	push   rbx
    7ffff7fb633f:	50                   	push   rax
    7ffff7fb6340:	48 89 f3             	mov    rbx,rsi
    7ffff7fb6343:	49 89 fe             	mov    r14,rdi
    7ffff7fb6346:	48 8b 3f             	mov    rdi,QWORD PTR [rdi]
    7ffff7fb6349:	49 8b 76 10          	mov    rsi,QWORD PTR [r14+0x10]
    7ffff7fb634d:	48 c1 e6 03          	shl    rsi,0x3
    7ffff7fb6351:	48 8d 0c dd 00 00 00 	lea    rcx,[rbx*8+0x0]
    7ffff7fb6358:	00 
    7ffff7fb6359:	6a 08                	push   0x8
    7ffff7fb635b:	5a                   	pop    rdx
    7ffff7fb635c:	e8 b6 cf ff ff       	call   0x7ffff7fb3317
    7ffff7fb6361:	49 89 06             	mov    QWORD PTR [r14],rax
    7ffff7fb6364:	49 89 5e 10          	mov    QWORD PTR [r14+0x10],rbx
    7ffff7fb6368:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb636c:	5b                   	pop    rbx
    7ffff7fb636d:	41 5e                	pop    r14
    7ffff7fb636f:	c3                   	ret
    7ffff7fb6370:	e9 00 00 00 00       	jmp    0x7ffff7fb6375
    7ffff7fb6375:	48 c1 e6 03          	shl    rsi,0x3
    7ffff7fb6379:	6a 08                	push   0x8
    7ffff7fb637b:	5a                   	pop    rdx
    7ffff7fb637c:	e9 8d cf ff ff       	jmp    0x7ffff7fb330e
    7ffff7fb6381:	48 89 f0             	mov    rax,rsi
    7ffff7fb6384:	48 c1 e8 03          	shr    rax,0x3
    7ffff7fb6388:	48 01 f0             	add    rax,rsi
    7ffff7fb638b:	48 83 c0 02          	add    rax,0x2
    7ffff7fb638f:	48 be ff ff ff ff ff 	movabs rsi,0x3ffffffffffffff
    7ffff7fb6396:	ff ff 03 
    7ffff7fb6399:	48 39 f0             	cmp    rax,rsi
    7ffff7fb639c:	48 0f 42 f0          	cmovb  rsi,rax
    7ffff7fb63a0:	e9 00 00 00 00       	jmp    0x7ffff7fb63a5
    7ffff7fb63a5:	41 56                	push   r14
    7ffff7fb63a7:	53                   	push   rbx
    7ffff7fb63a8:	50                   	push   rax
    7ffff7fb63a9:	48 89 f3             	mov    rbx,rsi
    7ffff7fb63ac:	49 89 fe             	mov    r14,rdi
    7ffff7fb63af:	48 89 f7             	mov    rdi,rsi
    7ffff7fb63b2:	e8 14 00 00 00       	call   0x7ffff7fb63cb
    7ffff7fb63b7:	49 89 06             	mov    QWORD PTR [r14],rax
    7ffff7fb63ba:	49 83 66 08 00       	and    QWORD PTR [r14+0x8],0x0
    7ffff7fb63bf:	49 89 5e 10          	mov    QWORD PTR [r14+0x10],rbx
    7ffff7fb63c3:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb63c7:	5b                   	pop    rbx
    7ffff7fb63c8:	41 5e                	pop    r14
    7ffff7fb63ca:	c3                   	ret
    7ffff7fb63cb:	48 8d 34 fd 00 00 00 	lea    rsi,[rdi*8+0x0]
    7ffff7fb63d2:	00 
    7ffff7fb63d3:	6a 08                	push   0x8
    7ffff7fb63d5:	5f                   	pop    rdi
    7ffff7fb63d6:	e9 b0 fb ff ff       	jmp    0x7ffff7fb5f8b
    7ffff7fb63db:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
    7ffff7fb63df:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
    7ffff7fb63e6:	00 
    7ffff7fb63e7:	48 03 0f             	add    rcx,QWORD PTR [rdi]
    7ffff7fb63ea:	31 d2                	xor    edx,edx
    7ffff7fb63ec:	48 39 d6             	cmp    rsi,rdx
    7ffff7fb63ef:	74 0a                	je     0x7ffff7fb63fb
    7ffff7fb63f1:	48 83 24 d1 00       	and    QWORD PTR [rcx+rdx*8],0x0
    7ffff7fb63f6:	48 ff c2             	inc    rdx
    7ffff7fb63f9:	eb f1                	jmp    0x7ffff7fb63ec
    7ffff7fb63fb:	48 01 f0             	add    rax,rsi
    7ffff7fb63fe:	48 89 47 08          	mov    QWORD PTR [rdi+0x8],rax
    7ffff7fb6402:	c3                   	ret
    7ffff7fb6403:	55                   	push   rbp
    7ffff7fb6404:	41 57                	push   r15
    7ffff7fb6406:	41 56                	push   r14
    7ffff7fb6408:	41 54                	push   r12
    7ffff7fb640a:	53                   	push   rbx
    7ffff7fb640b:	89 d5                	mov    ebp,edx
    7ffff7fb640d:	85 d2                	test   edx,edx
    7ffff7fb640f:	74 2b                	je     0x7ffff7fb643c
    7ffff7fb6411:	48 89 f3             	mov    rbx,rsi
    7ffff7fb6414:	49 89 fe             	mov    r14,rdi
    7ffff7fb6417:	83 fd 40             	cmp    ebp,0x40
    7ffff7fb641a:	75 2f                	jne    0x7ffff7fb644b
    7ffff7fb641c:	4d 8b 3e             	mov    r15,QWORD PTR [r14]
    7ffff7fb641f:	49 8d 76 08          	lea    rsi,[r14+0x8]
    7ffff7fb6423:	48 8d 14 dd f8 ff ff 	lea    rdx,[rbx*8-0x8]
    7ffff7fb642a:	ff 
    7ffff7fb642b:	4c 89 f7             	mov    rdi,r14
    7ffff7fb642e:	ff 15 64 27 00 00    	call   QWORD PTR [rip+0x2764]        # 0x7ffff7fb8b98
    7ffff7fb6434:	49 83 64 de f8 00    	and    QWORD PTR [r14+rbx*8-0x8],0x0
    7ffff7fb643a:	eb 03                	jmp    0x7ffff7fb643f
    7ffff7fb643c:	41 89 ef             	mov    r15d,ebp
    7ffff7fb643f:	4c 89 f8             	mov    rax,r15
    7ffff7fb6442:	5b                   	pop    rbx
    7ffff7fb6443:	41 5c                	pop    r12
    7ffff7fb6445:	41 5e                	pop    r14
    7ffff7fb6447:	41 5f                	pop    r15
    7ffff7fb6449:	5d                   	pop    rbp
    7ffff7fb644a:	c3                   	ret
    7ffff7fb644b:	83 e5 7f             	and    ebp,0x7f
    7ffff7fb644e:	48 c1 e3 03          	shl    rbx,0x3
    7ffff7fb6452:	45 31 ff             	xor    r15d,r15d
    7ffff7fb6455:	4c 8b 25 2c 27 00 00 	mov    r12,QWORD PTR [rip+0x272c]        # 0x7ffff7fb8b88
    7ffff7fb645c:	48 85 db             	test   rbx,rbx
    7ffff7fb645f:	74 de                	je     0x7ffff7fb643f
    7ffff7fb6461:	49 8b 74 1e f8       	mov    rsi,QWORD PTR [r14+rbx*1-0x8]
    7ffff7fb6466:	31 ff                	xor    edi,edi
    7ffff7fb6468:	89 ea                	mov    edx,ebp
    7ffff7fb646a:	41 ff d4             	call   r12
    7ffff7fb646d:	49 09 d7             	or     r15,rdx
    7ffff7fb6470:	4d 89 7c 1e f8       	mov    QWORD PTR [r14+rbx*1-0x8],r15
    7ffff7fb6475:	48 83 c3 f8          	add    rbx,0xfffffffffffffff8
    7ffff7fb6479:	49 89 c7             	mov    r15,rax
    7ffff7fb647c:	eb de                	jmp    0x7ffff7fb645c
    7ffff7fb647e:	48 85 f6             	test   rsi,rsi
    7ffff7fb6481:	74 05                	je     0x7ffff7fb6488
    7ffff7fb6483:	8a 07                	mov    al,BYTE PTR [rdi]
    7ffff7fb6485:	24 01                	and    al,0x1
    7ffff7fb6487:	c3                   	ret
    7ffff7fb6488:	b0 01                	mov    al,0x1
    7ffff7fb648a:	c3                   	ret
    7ffff7fb648b:	4c 8d 04 ca          	lea    r8,[rdx+rcx*8]
    7ffff7fb648f:	48 c1 e1 03          	shl    rcx,0x3
    7ffff7fb6493:	48 f7 d9             	neg    rcx
    7ffff7fb6496:	48 8d 3c f7          	lea    rdi,[rdi+rsi*8]
    7ffff7fb649a:	48 83 c7 f8          	add    rdi,0xfffffffffffffff8
    7ffff7fb649e:	48 c1 e6 03          	shl    rsi,0x3
    7ffff7fb64a2:	48 f7 de             	neg    rsi
    7ffff7fb64a5:	45 31 c9             	xor    r9d,r9d
    7ffff7fb64a8:	41 ba ff 00 00 00    	mov    r10d,0xff
    7ffff7fb64ae:	4c 39 ce             	cmp    rsi,r9
    7ffff7fb64b1:	74 20                	je     0x7ffff7fb64d3
    7ffff7fb64b3:	4c 39 c9             	cmp    rcx,r9
    7ffff7fb64b6:	74 27                	je     0x7ffff7fb64df
    7ffff7fb64b8:	4e 8b 1c 0f          	mov    r11,QWORD PTR [rdi+r9*1]
    7ffff7fb64bc:	31 c0                	xor    eax,eax
    7ffff7fb64be:	4f 3b 5c 08 f8       	cmp    r11,QWORD PTR [r8+r9*1-0x8]
    7ffff7fb64c3:	0f 95 c0             	setne  al
    7ffff7fb64c6:	41 0f 42 c2          	cmovb  eax,r10d
    7ffff7fb64ca:	49 83 c1 f8          	add    r9,0xfffffffffffffff8
    7ffff7fb64ce:	84 c0                	test   al,al
    7ffff7fb64d0:	74 dc                	je     0x7ffff7fb64ae
    7ffff7fb64d2:	c3                   	ret
    7ffff7fb64d3:	4d 01 c8             	add    r8,r9
    7ffff7fb64d6:	49 39 d0             	cmp    r8,rdx
    7ffff7fb64d9:	0f 95 c0             	setne  al
    7ffff7fb64dc:	f6 d8                	neg    al
    7ffff7fb64de:	c3                   	ret
    7ffff7fb64df:	b0 01                	mov    al,0x1
    7ffff7fb64e1:	c3                   	ret
    7ffff7fb64e2:	49 89 d0             	mov    r8,rdx
    7ffff7fb64e5:	48 89 ca             	mov    rdx,rcx
    7ffff7fb64e8:	c4 e2 fb f6 f6       	mulx   rsi,rax,rsi
    7ffff7fb64ed:	4c 01 c0             	add    rax,r8
    7ffff7fb64f0:	48 11 ce             	adc    rsi,rcx
    7ffff7fb64f3:	48 8d 4e 01          	lea    rcx,[rsi+0x1]
    7ffff7fb64f7:	48 0f af cf          	imul   rcx,rdi
    7ffff7fb64fb:	49 29 c8             	sub    r8,rcx
    7ffff7fb64fe:	31 c9                	xor    ecx,ecx
    7ffff7fb6500:	4c 39 c0             	cmp    rax,r8
    7ffff7fb6503:	ba 00 00 00 00       	mov    edx,0x0
    7ffff7fb6508:	48 19 d2             	sbb    rdx,rdx
    7ffff7fb650b:	48 8d 04 16          	lea    rax,[rsi+rdx*1]
    7ffff7fb650f:	48 ff c0             	inc    rax
    7ffff7fb6512:	48 21 fa             	and    rdx,rdi
    7ffff7fb6515:	4c 01 c2             	add    rdx,r8
    7ffff7fb6518:	48 39 fa             	cmp    rdx,rdi
    7ffff7fb651b:	48 0f 43 cf          	cmovae rcx,rdi
    7ffff7fb651f:	48 83 d8 ff          	sbb    rax,0xffffffffffffffff
    7ffff7fb6523:	48 29 ca             	sub    rdx,rcx
    7ffff7fb6526:	c3                   	ret
    7ffff7fb6527:	41 57                	push   r15
    7ffff7fb6529:	41 56                	push   r14
    7ffff7fb652b:	53                   	push   rbx
    7ffff7fb652c:	48 89 d3             	mov    rbx,rdx
    7ffff7fb652f:	49 89 f7             	mov    r15,rsi
    7ffff7fb6532:	49 89 fe             	mov    r14,rdi
    7ffff7fb6535:	6a ff                	push   0xffffffffffffffff
    7ffff7fb6537:	5f                   	pop    rdi
    7ffff7fb6538:	48 89 fe             	mov    rsi,rdi
    7ffff7fb653b:	31 c9                	xor    ecx,ecx
    7ffff7fb653d:	ff 15 35 26 00 00    	call   QWORD PTR [rip+0x2635]        # 0x7ffff7fb8b78
    7ffff7fb6543:	48 89 c1             	mov    rcx,rax
    7ffff7fb6546:	48 0f af cb          	imul   rcx,rbx
    7ffff7fb654a:	4c 01 f9             	add    rcx,r15
    7ffff7fb654d:	73 1c                	jae    0x7ffff7fb656b
    7ffff7fb654f:	31 d2                	xor    edx,edx
    7ffff7fb6551:	31 f6                	xor    esi,esi
    7ffff7fb6553:	48 39 d9             	cmp    rcx,rbx
    7ffff7fb6556:	40 0f 92 c6          	setb   sil
    7ffff7fb655a:	48 0f 43 d3          	cmovae rdx,rbx
    7ffff7fb655e:	48 83 ce fe          	or     rsi,0xfffffffffffffffe
    7ffff7fb6562:	48 01 f0             	add    rax,rsi
    7ffff7fb6565:	48 01 da             	add    rdx,rbx
    7ffff7fb6568:	48 29 d1             	sub    rcx,rdx
    7ffff7fb656b:	4c 89 fa             	mov    rdx,r15
    7ffff7fb656e:	c4 e2 cb f6 d0       	mulx   rdx,rsi,rax
    7ffff7fb6573:	48 01 ca             	add    rdx,rcx
    7ffff7fb6576:	73 13                	jae    0x7ffff7fb658b
    7ffff7fb6578:	4c 39 fe             	cmp    rsi,r15
    7ffff7fb657b:	48 19 da             	sbb    rdx,rbx
    7ffff7fb657e:	0f 92 c1             	setb   cl
    7ffff7fb6581:	0f b6 c9             	movzx  ecx,cl
    7ffff7fb6584:	48 83 c9 fe          	or     rcx,0xfffffffffffffffe
    7ffff7fb6588:	48 01 c8             	add    rax,rcx
    7ffff7fb658b:	4d 89 3e             	mov    QWORD PTR [r14],r15
    7ffff7fb658e:	49 89 5e 08          	mov    QWORD PTR [r14+0x8],rbx
    7ffff7fb6592:	49 89 46 10          	mov    QWORD PTR [r14+0x10],rax
    7ffff7fb6596:	5b                   	pop    rbx
    7ffff7fb6597:	41 5e                	pop    r14
    7ffff7fb6599:	41 5f                	pop    r15
    7ffff7fb659b:	c3                   	ret
    7ffff7fb659c:	48 83 ff 19          	cmp    rdi,0x19
    7ffff7fb65a0:	73 06                	jae    0x7ffff7fb65a8
    7ffff7fb65a2:	6a 01                	push   0x1
    7ffff7fb65a4:	58                   	pop    rax
    7ffff7fb65a5:	31 d2                	xor    edx,edx
    7ffff7fb65a7:	c3                   	ret
    7ffff7fb65a8:	48 8d 47 ff          	lea    rax,[rdi-0x1]
    7ffff7fb65ac:	f3 48 0f bd c0       	lzcnt  rax,rax
    7ffff7fb65b1:	48 81 ff c1 00 00 00 	cmp    rdi,0xc1
    7ffff7fb65b8:	73 0d                	jae    0x7ffff7fb65c7
    7ffff7fb65ba:	48 29 c7             	sub    rdi,rax
    7ffff7fb65bd:	48 8d 14 7d 80 00 00 	lea    rdx,[rdi*2+0x80]
    7ffff7fb65c4:	00 
    7ffff7fb65c5:	eb 0e                	jmp    0x7ffff7fb65d5
    7ffff7fb65c7:	6a 40                	push   0x40
    7ffff7fb65c9:	59                   	pop    rcx
    7ffff7fb65ca:	48 29 c1             	sub    rcx,rax
    7ffff7fb65cd:	48 6b c1 0d          	imul   rax,rcx,0xd
    7ffff7fb65d1:	48 8d 14 b8          	lea    rdx,[rax+rdi*4]
    7ffff7fb65d5:	48 c1 e2 03          	shl    rdx,0x3
    7ffff7fb65d9:	6a 08                	push   0x8
    7ffff7fb65db:	58                   	pop    rax
    7ffff7fb65dc:	c3                   	ret
    7ffff7fb65dd:	55                   	push   rbp
    7ffff7fb65de:	41 57                	push   r15
    7ffff7fb65e0:	41 56                	push   r14
    7ffff7fb65e2:	41 55                	push   r13
    7ffff7fb65e4:	41 54                	push   r12
    7ffff7fb65e6:	53                   	push   rbx
    7ffff7fb65e7:	50                   	push   rax
    7ffff7fb65e8:	85 d2                	test   edx,edx
    7ffff7fb65ea:	74 3b                	je     0x7ffff7fb6627
    7ffff7fb65ec:	89 d3                	mov    ebx,edx
    7ffff7fb65ee:	49 89 f6             	mov    r14,rsi
    7ffff7fb65f1:	49 89 ff             	mov    r15,rdi
    7ffff7fb65f4:	83 e3 7f             	and    ebx,0x7f
    7ffff7fb65f7:	49 c1 e6 03          	shl    r14,0x3
    7ffff7fb65fb:	45 31 ed             	xor    r13d,r13d
    7ffff7fb65fe:	48 8b 2d 7b 25 00 00 	mov    rbp,QWORD PTR [rip+0x257b]        # 0x7ffff7fb8b80
    7ffff7fb6605:	45 31 e4             	xor    r12d,r12d
    7ffff7fb6608:	4d 39 ee             	cmp    r14,r13
    7ffff7fb660b:	74 1d                	je     0x7ffff7fb662a
    7ffff7fb660d:	4b 8b 3c 2f          	mov    rdi,QWORD PTR [r15+r13*1]
    7ffff7fb6611:	31 f6                	xor    esi,esi
    7ffff7fb6613:	89 da                	mov    edx,ebx
    7ffff7fb6615:	ff d5                	call   rbp
    7ffff7fb6617:	49 09 c4             	or     r12,rax
    7ffff7fb661a:	4f 89 24 2f          	mov    QWORD PTR [r15+r13*1],r12
    7ffff7fb661e:	49 83 c5 08          	add    r13,0x8
    7ffff7fb6622:	49 89 d4             	mov    r12,rdx
    7ffff7fb6625:	eb e1                	jmp    0x7ffff7fb6608
    7ffff7fb6627:	45 31 e4             	xor    r12d,r12d
    7ffff7fb662a:	4c 89 e0             	mov    rax,r12
    7ffff7fb662d:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb6631:	5b                   	pop    rbx
    7ffff7fb6632:	41 5c                	pop    r12
    7ffff7fb6634:	41 5d                	pop    r13
    7ffff7fb6636:	41 5e                	pop    r14
    7ffff7fb6638:	41 5f                	pop    r15
    7ffff7fb663a:	5d                   	pop    rbp
    7ffff7fb663b:	c3                   	ret
    7ffff7fb663c:	55                   	push   rbp
    7ffff7fb663d:	41 57                	push   r15
    7ffff7fb663f:	41 56                	push   r14
    7ffff7fb6641:	41 55                	push   r13
    7ffff7fb6643:	41 54                	push   r12
    7ffff7fb6645:	53                   	push   rbx
    7ffff7fb6646:	48 83 ec 28          	sub    rsp,0x28
    7ffff7fb664a:	4c 89 c3             	mov    rbx,r8
    7ffff7fb664d:	49 89 ce             	mov    r14,rcx
    7ffff7fb6650:	49 89 d5             	mov    r13,rdx
    7ffff7fb6653:	48 89 f5             	mov    rbp,rsi
    7ffff7fb6656:	49 89 ff             	mov    r15,rdi
    7ffff7fb6659:	4a 39 7c c1 f8       	cmp    QWORD PTR [rcx+r8*8-0x8],rdi
    7ffff7fb665e:	76 2e                	jbe    0x7ffff7fb668e
    7ffff7fb6660:	48 8b 54 24 68       	mov    rdx,QWORD PTR [rsp+0x68]
    7ffff7fb6665:	48 8b 74 24 60       	mov    rsi,QWORD PTR [rsp+0x60]
    7ffff7fb666a:	48 8b 4c 24 70       	mov    rcx,QWORD PTR [rsp+0x70]
    7ffff7fb666f:	4e 8b 44 ed f0       	mov    r8,QWORD PTR [rbp+r13*8-0x10]
    7ffff7fb6674:	49 89 e4             	mov    r12,rsp
    7ffff7fb6677:	4c 89 e7             	mov    rdi,r12
    7ffff7fb667a:	41 57                	push   r15
    7ffff7fb667c:	42 ff 74 ed f8       	push   QWORD PTR [rbp+r13*8-0x8]
    7ffff7fb6681:	e8 db 1e 00 00       	call   0x7ffff7fb8561
    7ffff7fb6686:	58                   	pop    rax
    7ffff7fb6687:	59                   	pop    rcx
    7ffff7fb6688:	4d 8b 24 24          	mov    r12,QWORD PTR [r12]
    7ffff7fb668c:	eb 04                	jmp    0x7ffff7fb6692
    7ffff7fb668e:	6a ff                	push   0xffffffffffffffff
    7ffff7fb6690:	41 5c                	pop    r12
    7ffff7fb6692:	49 29 dd             	sub    r13,rbx
    7ffff7fb6695:	4e 8d 2c ed 00 00 00 	lea    r13,[r13*8+0x0]
    7ffff7fb669c:	00 
    7ffff7fb669d:	49 01 ed             	add    r13,rbp
    7ffff7fb66a0:	4c 89 ef             	mov    rdi,r13
    7ffff7fb66a3:	48 89 de             	mov    rsi,rbx
    7ffff7fb66a6:	4c 89 e2             	mov    rdx,r12
    7ffff7fb66a9:	4c 89 f1             	mov    rcx,r14
    7ffff7fb66ac:	49 89 d8             	mov    r8,rbx
    7ffff7fb66af:	e8 f8 14 00 00       	call   0x7ffff7fb7bac
    7ffff7fb66b4:	4c 39 f8             	cmp    rax,r15
    7ffff7fb66b7:	76 14                	jbe    0x7ffff7fb66cd
    7ffff7fb66b9:	49 ff cc             	dec    r12
    7ffff7fb66bc:	4c 89 ef             	mov    rdi,r13
    7ffff7fb66bf:	48 89 de             	mov    rsi,rbx
    7ffff7fb66c2:	4c 89 f2             	mov    rdx,r14
    7ffff7fb66c5:	48 89 d9             	mov    rcx,rbx
    7ffff7fb66c8:	e8 11 f9 ff ff       	call   0x7ffff7fb5fde
    7ffff7fb66cd:	4c 89 e0             	mov    rax,r12
    7ffff7fb66d0:	48 83 c4 28          	add    rsp,0x28
    7ffff7fb66d4:	5b                   	pop    rbx
    7ffff7fb66d5:	41 5c                	pop    r12
    7ffff7fb66d7:	41 5d                	pop    r13
    7ffff7fb66d9:	41 5e                	pop    r14
    7ffff7fb66db:	41 5f                	pop    r15
    7ffff7fb66dd:	5d                   	pop    rbp
    7ffff7fb66de:	c3                   	ret
    7ffff7fb66df:	55                   	push   rbp
    7ffff7fb66e0:	41 57                	push   r15
    7ffff7fb66e2:	41 56                	push   r14
    7ffff7fb66e4:	41 55                	push   r13
    7ffff7fb66e6:	41 54                	push   r12
    7ffff7fb66e8:	53                   	push   rbx
    7ffff7fb66e9:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb66ed:	4c 89 cb             	mov    rbx,r9
    7ffff7fb66f0:	4d 89 c6             	mov    r14,r8
    7ffff7fb66f3:	49 89 cf             	mov    r15,rcx
    7ffff7fb66f6:	49 89 d4             	mov    r12,rdx
    7ffff7fb66f9:	49 89 f5             	mov    r13,rsi
    7ffff7fb66fc:	48 89 fd             	mov    rbp,rdi
    7ffff7fb66ff:	48 89 f0             	mov    rax,rsi
    7ffff7fb6702:	48 29 c8             	sub    rax,rcx
    7ffff7fb6705:	48 8d 3c c7          	lea    rdi,[rdi+rax*8]
    7ffff7fb6709:	48 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],rdi
    7ffff7fb670e:	48 89 ce             	mov    rsi,rcx
    7ffff7fb6711:	e8 75 fd ff ff       	call   0x7ffff7fb648b
    7ffff7fb6716:	88 44 24 0f          	mov    BYTE PTR [rsp+0xf],al
    7ffff7fb671a:	3c ff                	cmp    al,0xff
    7ffff7fb671c:	74 3f                	je     0x7ffff7fb675d
    7ffff7fb671e:	48 8b 7c 24 10       	mov    rdi,QWORD PTR [rsp+0x10]
    7ffff7fb6723:	4c 89 fe             	mov    rsi,r15
    7ffff7fb6726:	4c 89 e2             	mov    rdx,r12
    7ffff7fb6729:	4c 89 f9             	mov    rcx,r15
    7ffff7fb672c:	e8 44 f9 ff ff       	call   0x7ffff7fb6075
    7ffff7fb6731:	eb 2a                	jmp    0x7ffff7fb675d
    7ffff7fb6733:	4a 8b 7c ed 00       	mov    rdi,QWORD PTR [rbp+r13*8+0x0]
    7ffff7fb6738:	48 83 ec 08          	sub    rsp,0x8
    7ffff7fb673c:	48 89 ee             	mov    rsi,rbp
    7ffff7fb673f:	4c 89 ea             	mov    rdx,r13
    7ffff7fb6742:	4c 89 e1             	mov    rcx,r12
    7ffff7fb6745:	4d 89 f8             	mov    r8,r15
    7ffff7fb6748:	ff 74 24 58          	push   QWORD PTR [rsp+0x58]
    7ffff7fb674c:	53                   	push   rbx
    7ffff7fb674d:	41 56                	push   r14
    7ffff7fb674f:	e8 e8 fe ff ff       	call   0x7ffff7fb663c
    7ffff7fb6754:	48 83 c4 20          	add    rsp,0x20
    7ffff7fb6758:	4a 89 44 ed 00       	mov    QWORD PTR [rbp+r13*8+0x0],rax
    7ffff7fb675d:	49 ff cd             	dec    r13
    7ffff7fb6760:	49 8d 45 01          	lea    rax,[r13+0x1]
    7ffff7fb6764:	4c 39 f8             	cmp    rax,r15
    7ffff7fb6767:	77 ca                	ja     0x7ffff7fb6733
    7ffff7fb6769:	80 7c 24 0f ff       	cmp    BYTE PTR [rsp+0xf],0xff
    7ffff7fb676e:	0f 95 c0             	setne  al
    7ffff7fb6771:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb6775:	5b                   	pop    rbx
    7ffff7fb6776:	41 5c                	pop    r12
    7ffff7fb6778:	41 5d                	pop    r13
    7ffff7fb677a:	41 5e                	pop    r14
    7ffff7fb677c:	41 5f                	pop    r15
    7ffff7fb677e:	5d                   	pop    rbp
    7ffff7fb677f:	c3                   	ret
    7ffff7fb6780:	55                   	push   rbp
    7ffff7fb6781:	41 57                	push   r15
    7ffff7fb6783:	41 56                	push   r14
    7ffff7fb6785:	41 55                	push   r13
    7ffff7fb6787:	41 54                	push   r12
    7ffff7fb6789:	53                   	push   rbx
    7ffff7fb678a:	50                   	push   rax
    7ffff7fb678b:	4c 89 cb             	mov    rbx,r9
    7ffff7fb678e:	4d 89 c6             	mov    r14,r8
    7ffff7fb6791:	49 89 cf             	mov    r15,rcx
    7ffff7fb6794:	49 89 d4             	mov    r12,rdx
    7ffff7fb6797:	49 89 fd             	mov    r13,rdi
    7ffff7fb679a:	48 89 cd             	mov    rbp,rcx
    7ffff7fb679d:	48 d1 ed             	shr    rbp,1
    7ffff7fb67a0:	48 29 ee             	sub    rsi,rbp
    7ffff7fb67a3:	48 8d 3c ef          	lea    rdi,[rdi+rbp*8]
    7ffff7fb67a7:	ff 74 24 48          	push   QWORD PTR [rsp+0x48]
    7ffff7fb67ab:	ff 74 24 48          	push   QWORD PTR [rsp+0x48]
    7ffff7fb67af:	e8 3d 00 00 00       	call   0x7ffff7fb67f1
    7ffff7fb67b4:	59                   	pop    rcx
    7ffff7fb67b5:	5a                   	pop    rdx
    7ffff7fb67b6:	88 44 24 07          	mov    BYTE PTR [rsp+0x7],al
    7ffff7fb67ba:	4c 01 fd             	add    rbp,r15
    7ffff7fb67bd:	4c 89 ef             	mov    rdi,r13
    7ffff7fb67c0:	48 89 ee             	mov    rsi,rbp
    7ffff7fb67c3:	4c 89 e2             	mov    rdx,r12
    7ffff7fb67c6:	4c 89 f9             	mov    rcx,r15
    7ffff7fb67c9:	4d 89 f0             	mov    r8,r14
    7ffff7fb67cc:	49 89 d9             	mov    r9,rbx
    7ffff7fb67cf:	ff 74 24 48          	push   QWORD PTR [rsp+0x48]
    7ffff7fb67d3:	ff 74 24 48          	push   QWORD PTR [rsp+0x48]
    7ffff7fb67d7:	e8 15 00 00 00       	call   0x7ffff7fb67f1
    7ffff7fb67dc:	59                   	pop    rcx
    7ffff7fb67dd:	5a                   	pop    rdx
    7ffff7fb67de:	8a 44 24 07          	mov    al,BYTE PTR [rsp+0x7]
    7ffff7fb67e2:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb67e6:	5b                   	pop    rbx
    7ffff7fb67e7:	41 5c                	pop    r12
    7ffff7fb67e9:	41 5d                	pop    r13
    7ffff7fb67eb:	41 5e                	pop    r14
    7ffff7fb67ed:	41 5f                	pop    r15
    7ffff7fb67ef:	5d                   	pop    rbp
    7ffff7fb67f0:	c3                   	ret
    7ffff7fb67f1:	55                   	push   rbp
    7ffff7fb67f2:	41 57                	push   r15
    7ffff7fb67f4:	41 56                	push   r14
    7ffff7fb67f6:	41 55                	push   r13
    7ffff7fb67f8:	41 54                	push   r12
    7ffff7fb67fa:	53                   	push   rbx
    7ffff7fb67fb:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb67ff:	48 89 cb             	mov    rbx,rcx
    7ffff7fb6802:	49 89 d6             	mov    r14,rdx
    7ffff7fb6805:	49 89 ff             	mov    r15,rdi
    7ffff7fb6808:	48 89 f0             	mov    rax,rsi
    7ffff7fb680b:	48 29 c8             	sub    rax,rcx
    7ffff7fb680e:	48 83 f8 21          	cmp    rax,0x21
    7ffff7fb6812:	73 1c                	jae    0x7ffff7fb6830
    7ffff7fb6814:	4c 89 ff             	mov    rdi,r15
    7ffff7fb6817:	4c 89 f2             	mov    rdx,r14
    7ffff7fb681a:	48 89 d9             	mov    rcx,rbx
    7ffff7fb681d:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb6821:	5b                   	pop    rbx
    7ffff7fb6822:	41 5c                	pop    r12
    7ffff7fb6824:	41 5d                	pop    r13
    7ffff7fb6826:	41 5e                	pop    r14
    7ffff7fb6828:	41 5f                	pop    r15
    7ffff7fb682a:	5d                   	pop    rbp
    7ffff7fb682b:	e9 af fe ff ff       	jmp    0x7ffff7fb66df
    7ffff7fb6830:	4c 8b 54 24 58       	mov    r10,QWORD PTR [rsp+0x58]
    7ffff7fb6835:	4c 89 54 24 08       	mov    QWORD PTR [rsp+0x8],r10
    7ffff7fb683a:	48 89 dd             	mov    rbp,rbx
    7ffff7fb683d:	48 29 c5             	sub    rbp,rax
    7ffff7fb6840:	48 29 ee             	sub    rsi,rbp
    7ffff7fb6843:	49 8d 3c ef          	lea    rdi,[r15+rbp*8]
    7ffff7fb6847:	49 8d 14 ee          	lea    rdx,[r14+rbp*8]
    7ffff7fb684b:	48 89 c1             	mov    rcx,rax
    7ffff7fb684e:	49 89 c5             	mov    r13,rax
    7ffff7fb6851:	41 52                	push   r10
    7ffff7fb6853:	ff 74 24 58          	push   QWORD PTR [rsp+0x58]
    7ffff7fb6857:	e8 24 ff ff ff       	call   0x7ffff7fb6780
    7ffff7fb685c:	59                   	pop    rcx
    7ffff7fb685d:	5a                   	pop    rdx
    7ffff7fb685e:	4d 89 f1             	mov    r9,r14
    7ffff7fb6861:	44 0f b6 f0          	movzx  r14d,al
    7ffff7fb6865:	49 8d 0c df          	lea    rcx,[r15+rbx*8]
    7ffff7fb6869:	6a 01                	push   0x1
    7ffff7fb686b:	5a                   	pop    rdx
    7ffff7fb686c:	4c 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],r15
    7ffff7fb6871:	4c 89 ff             	mov    rdi,r15
    7ffff7fb6874:	48 89 de             	mov    rsi,rbx
    7ffff7fb6877:	49 89 cc             	mov    r12,rcx
    7ffff7fb687a:	4d 89 e8             	mov    r8,r13
    7ffff7fb687d:	4d 89 cf             	mov    r15,r9
    7ffff7fb6880:	ff 74 24 08          	push   QWORD PTR [rsp+0x8]
    7ffff7fb6884:	48 89 6c 24 10       	mov    QWORD PTR [rsp+0x10],rbp
    7ffff7fb6889:	55                   	push   rbp
    7ffff7fb688a:	e8 6f 00 00 00       	call   0x7ffff7fb68fe
    7ffff7fb688f:	59                   	pop    rcx
    7ffff7fb6890:	5a                   	pop    rdx
    7ffff7fb6891:	48 89 c5             	mov    rbp,rax
    7ffff7fb6894:	45 84 f6             	test   r14b,r14b
    7ffff7fb6897:	74 4b                	je     0x7ffff7fb68e4
    7ffff7fb6899:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb689e:	4a 8d 3c e8          	lea    rdi,[rax+r13*8]
    7ffff7fb68a2:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
    7ffff7fb68a7:	48 89 ce             	mov    rsi,rcx
    7ffff7fb68aa:	4c 89 fa             	mov    rdx,r15
    7ffff7fb68ad:	e8 c3 f7 ff ff       	call   0x7ffff7fb6075
    7ffff7fb68b2:	0f b6 c0             	movzx  eax,al
    7ffff7fb68b5:	48 29 c5             	sub    rbp,rax
    7ffff7fb68b8:	eb 2a                	jmp    0x7ffff7fb68e4
    7ffff7fb68ba:	48 8b 7c 24 10       	mov    rdi,QWORD PTR [rsp+0x10]
    7ffff7fb68bf:	48 89 de             	mov    rsi,rbx
    7ffff7fb68c2:	4c 89 fa             	mov    rdx,r15
    7ffff7fb68c5:	48 89 d9             	mov    rcx,rbx
    7ffff7fb68c8:	e8 11 f7 ff ff       	call   0x7ffff7fb5fde
    7ffff7fb68cd:	0f b6 c0             	movzx  eax,al
    7ffff7fb68d0:	48 01 c5             	add    rbp,rax
    7ffff7fb68d3:	4c 89 e7             	mov    rdi,r12
    7ffff7fb68d6:	4c 89 ee             	mov    rsi,r13
    7ffff7fb68d9:	e8 e0 f6 ff ff       	call   0x7ffff7fb5fbe
    7ffff7fb68de:	0f b6 c0             	movzx  eax,al
    7ffff7fb68e1:	49 29 c6             	sub    r14,rax
    7ffff7fb68e4:	48 85 ed             	test   rbp,rbp
    7ffff7fb68e7:	78 d1                	js     0x7ffff7fb68ba
    7ffff7fb68e9:	4d 85 f6             	test   r14,r14
    7ffff7fb68ec:	0f 95 c0             	setne  al
    7ffff7fb68ef:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb68f3:	5b                   	pop    rbx
    7ffff7fb68f4:	41 5c                	pop    r12
    7ffff7fb68f6:	41 5d                	pop    r13
    7ffff7fb68f8:	41 5e                	pop    r14
    7ffff7fb68fa:	41 5f                	pop    r15
    7ffff7fb68fc:	5d                   	pop    rbp
    7ffff7fb68fd:	c3                   	ret
    7ffff7fb68fe:	55                   	push   rbp
    7ffff7fb68ff:	41 57                	push   r15
    7ffff7fb6901:	41 56                	push   r14
    7ffff7fb6903:	41 55                	push   r13
    7ffff7fb6905:	41 54                	push   r12
    7ffff7fb6907:	53                   	push   rbx
    7ffff7fb6908:	48 83 ec 68          	sub    rsp,0x68
    7ffff7fb690c:	4d 89 c7             	mov    r15,r8
    7ffff7fb690f:	89 54 24 4c          	mov    DWORD PTR [rsp+0x4c],edx
    7ffff7fb6913:	48 89 f5             	mov    rbp,rsi
    7ffff7fb6916:	49 89 fd             	mov    r13,rdi
    7ffff7fb6919:	48 8b 94 24 a0 00 00 	mov    rdx,QWORD PTR [rsp+0xa0]
    7ffff7fb6920:	00 
    7ffff7fb6921:	48 c7 44 24 10 00 00 	mov    QWORD PTR [rsp+0x10],0x0
    7ffff7fb6928:	00 00 
    7ffff7fb692a:	49 89 d6             	mov    r14,rdx
    7ffff7fb692d:	31 db                	xor    ebx,ebx
    7ffff7fb692f:	48 89 c8             	mov    rax,rcx
    7ffff7fb6932:	4c 89 fa             	mov    rdx,r15
    7ffff7fb6935:	4c 39 f2             	cmp    rdx,r14
    7ffff7fb6938:	73 08                	jae    0x7ffff7fb6942
    7ffff7fb693a:	49 89 d4             	mov    r12,rdx
    7ffff7fb693d:	49 89 c2             	mov    r10,rax
    7ffff7fb6940:	eb 0c                	jmp    0x7ffff7fb694e
    7ffff7fb6942:	4d 89 f4             	mov    r12,r14
    7ffff7fb6945:	4d 89 ca             	mov    r10,r9
    7ffff7fb6948:	49 89 d6             	mov    r14,rdx
    7ffff7fb694b:	49 89 c1             	mov    r9,rax
    7ffff7fb694e:	0f b6 44 24 4c       	movzx  eax,BYTE PTR [rsp+0x4c]
    7ffff7fb6953:	89 44 24 0c          	mov    DWORD PTR [rsp+0xc],eax
    7ffff7fb6957:	49 83 fc 19          	cmp    r12,0x19
    7ffff7fb695b:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
    7ffff7fb6960:	4c 89 54 24 18       	mov    QWORD PTR [rsp+0x18],r10
    7ffff7fb6965:	0f 83 31 01 00 00    	jae    0x7ffff7fb6a9c
    7ffff7fb696b:	49 81 fe 01 04 00 00 	cmp    r14,0x401
    7ffff7fb6972:	0f 82 bd 01 00 00    	jb     0x7ffff7fb6b35
    7ffff7fb6978:	4c 89 e0             	mov    rax,r12
    7ffff7fb697b:	48 0d 00 04 00 00    	or     rax,0x400
    7ffff7fb6981:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
    7ffff7fb6986:	4c 29 e0             	sub    rax,r12
    7ffff7fb6989:	48 89 44 24 60       	mov    QWORD PTR [rsp+0x60],rax
    7ffff7fb698e:	4c 89 f0             	mov    rax,r14
    7ffff7fb6991:	48 25 00 fc ff ff    	and    rax,0xfffffffffffffc00
    7ffff7fb6997:	44 89 f1             	mov    ecx,r14d
    7ffff7fb699a:	81 e1 ff 03 00 00    	and    ecx,0x3ff
    7ffff7fb69a0:	48 89 4c 24 50       	mov    QWORD PTR [rsp+0x50],rcx
    7ffff7fb69a5:	48 29 c5             	sub    rbp,rax
    7ffff7fb69a8:	48 89 6c 24 30       	mov    QWORD PTR [rsp+0x30],rbp
    7ffff7fb69ad:	4c 89 64 24 38       	mov    QWORD PTR [rsp+0x38],r12
    7ffff7fb69b2:	4a 8d 04 e5 00 00 00 	lea    rax,[r12*8+0x0]
    7ffff7fb69b9:	00 
    7ffff7fb69ba:	48 89 44 24 58       	mov    QWORD PTR [rsp+0x58],rax
    7ffff7fb69bf:	31 d2                	xor    edx,edx
    7ffff7fb69c1:	49 81 fe ff 03 00 00 	cmp    r14,0x3ff
    7ffff7fb69c8:	76 67                	jbe    0x7ffff7fb6a31
    7ffff7fb69ca:	49 81 c6 00 fc ff ff 	add    r14,0xfffffffffffffc00
    7ffff7fb69d1:	41 bf 00 20 00 00    	mov    r15d,0x2000
    7ffff7fb69d7:	4f 8d 24 39          	lea    r12,[r9+r15*1]
    7ffff7fb69db:	48 8b 44 24 58       	mov    rax,QWORD PTR [rsp+0x58]
    7ffff7fb69e0:	4a 8d 3c 28          	lea    rdi,[rax+r13*1]
    7ffff7fb69e4:	48 8b 74 24 60       	mov    rsi,QWORD PTR [rsp+0x60]
    7ffff7fb69e9:	4c 89 f3             	mov    rbx,r14
    7ffff7fb69ec:	4d 89 ce             	mov    r14,r9
    7ffff7fb69ef:	e8 6d 02 00 00       	call   0x7ffff7fb6c61
    7ffff7fb69f4:	48 89 c5             	mov    rbp,rax
    7ffff7fb69f7:	48 83 ec 08          	sub    rsp,0x8
    7ffff7fb69fb:	41 b8 00 04 00 00    	mov    r8d,0x400
    7ffff7fb6a01:	4c 89 ef             	mov    rdi,r13
    7ffff7fb6a04:	48 8b 74 24 48       	mov    rsi,QWORD PTR [rsp+0x48]
    7ffff7fb6a09:	8b 54 24 14          	mov    edx,DWORD PTR [rsp+0x14]
    7ffff7fb6a0d:	4c 89 f1             	mov    rcx,r14
    7ffff7fb6a10:	49 89 de             	mov    r14,rbx
    7ffff7fb6a13:	4c 8b 4c 24 20       	mov    r9,QWORD PTR [rsp+0x20]
    7ffff7fb6a18:	ff 74 24 40          	push   QWORD PTR [rsp+0x40]
    7ffff7fb6a1c:	e8 84 02 00 00       	call   0x7ffff7fb6ca5
    7ffff7fb6a21:	59                   	pop    rcx
    7ffff7fb6a22:	5a                   	pop    rdx
    7ffff7fb6a23:	48 89 c2             	mov    rdx,rax
    7ffff7fb6a26:	48 01 ea             	add    rdx,rbp
    7ffff7fb6a29:	4d 01 fd             	add    r13,r15
    7ffff7fb6a2c:	4d 89 e1             	mov    r9,r12
    7ffff7fb6a2f:	eb 90                	jmp    0x7ffff7fb69c1
    7ffff7fb6a31:	4d 89 ce             	mov    r14,r9
    7ffff7fb6a34:	48 8b 6c 24 30       	mov    rbp,QWORD PTR [rsp+0x30]
    7ffff7fb6a39:	48 89 ee             	mov    rsi,rbp
    7ffff7fb6a3c:	4c 8b 7c 24 38       	mov    r15,QWORD PTR [rsp+0x38]
    7ffff7fb6a41:	4c 29 fe             	sub    rsi,r15
    7ffff7fb6a44:	4a 8d 3c fd 00 00 00 	lea    rdi,[r15*8+0x0]
    7ffff7fb6a4b:	00 
    7ffff7fb6a4c:	4c 01 ef             	add    rdi,r13
    7ffff7fb6a4f:	e8 0d 02 00 00       	call   0x7ffff7fb6c61
    7ffff7fb6a54:	48 89 c1             	mov    rcx,rax
    7ffff7fb6a57:	48 8b 54 24 50       	mov    rdx,QWORD PTR [rsp+0x50]
    7ffff7fb6a5c:	4c 39 fa             	cmp    rdx,r15
    7ffff7fb6a5f:	72 18                	jb     0x7ffff7fb6a79
    7ffff7fb6a61:	48 8b 5c 24 20       	mov    rbx,QWORD PTR [rsp+0x20]
    7ffff7fb6a66:	48 01 cb             	add    rbx,rcx
    7ffff7fb6a69:	4c 89 f0             	mov    rax,r14
    7ffff7fb6a6c:	4c 8b 4c 24 18       	mov    r9,QWORD PTR [rsp+0x18]
    7ffff7fb6a71:	4d 89 fe             	mov    r14,r15
    7ffff7fb6a74:	e9 bc fe ff ff       	jmp    0x7ffff7fb6935
    7ffff7fb6a79:	48 85 d2             	test   rdx,rdx
    7ffff7fb6a7c:	48 8b 5c 24 20       	mov    rbx,QWORD PTR [rsp+0x20]
    7ffff7fb6a81:	0f 84 d1 00 00 00    	je     0x7ffff7fb6b58
    7ffff7fb6a87:	4d 89 f1             	mov    r9,r14
    7ffff7fb6a8a:	48 01 d9             	add    rcx,rbx
    7ffff7fb6a8d:	48 01 4c 24 10       	add    QWORD PTR [rsp+0x10],rcx
    7ffff7fb6a92:	48 8b 4c 24 18       	mov    rcx,QWORD PTR [rsp+0x18]
    7ffff7fb6a97:	e9 8e fe ff ff       	jmp    0x7ffff7fb692a
    7ffff7fb6a9c:	48 89 6c 24 30       	mov    QWORD PTR [rsp+0x30],rbp
    7ffff7fb6aa1:	49 81 fc c0 00 00 00 	cmp    r12,0xc0
    7ffff7fb6aa8:	4c 89 4c 24 28       	mov    QWORD PTR [rsp+0x28],r9
    7ffff7fb6aad:	4b 8d 04 24          	lea    rax,[r12+r12*1]
    7ffff7fb6ab1:	0f 87 ab 00 00 00    	ja     0x7ffff7fb6b62
    7ffff7fb6ab7:	48 89 44 24 38       	mov    QWORD PTR [rsp+0x38],rax
    7ffff7fb6abc:	4a 8d 04 e5 00 00 00 	lea    rax,[r12*8+0x0]
    7ffff7fb6ac3:	00 
    7ffff7fb6ac4:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
    7ffff7fb6ac9:	31 d2                	xor    edx,edx
    7ffff7fb6acb:	4d 89 f7             	mov    r15,r14
    7ffff7fb6ace:	48 8b 5c 24 40       	mov    rbx,QWORD PTR [rsp+0x40]
    7ffff7fb6ad3:	4d 29 e7             	sub    r15,r12
    7ffff7fb6ad6:	0f 82 02 01 00 00    	jb     0x7ffff7fb6bde
    7ffff7fb6adc:	4e 8d 34 2b          	lea    r14,[rbx+r13*1]
    7ffff7fb6ae0:	4c 89 f7             	mov    rdi,r14
    7ffff7fb6ae3:	4c 89 e6             	mov    rsi,r12
    7ffff7fb6ae6:	e8 76 01 00 00       	call   0x7ffff7fb6c61
    7ffff7fb6aeb:	48 89 c5             	mov    rbp,rax
    7ffff7fb6aee:	4c 89 ef             	mov    rdi,r13
    7ffff7fb6af1:	48 8b 74 24 38       	mov    rsi,QWORD PTR [rsp+0x38]
    7ffff7fb6af6:	8b 54 24 0c          	mov    edx,DWORD PTR [rsp+0xc]
    7ffff7fb6afa:	4c 8b 6c 24 28       	mov    r13,QWORD PTR [rsp+0x28]
    7ffff7fb6aff:	4c 89 e9             	mov    rcx,r13
    7ffff7fb6b02:	4d 89 e0             	mov    r8,r12
    7ffff7fb6b05:	4c 8b 4c 24 18       	mov    r9,QWORD PTR [rsp+0x18]
    7ffff7fb6b0a:	ff b4 24 a8 00 00 00 	push   QWORD PTR [rsp+0xa8]
    7ffff7fb6b11:	41 54                	push   r12
    7ffff7fb6b13:	e8 fc 0a 00 00       	call   0x7ffff7fb7614
    7ffff7fb6b18:	59                   	pop    rcx
    7ffff7fb6b19:	5a                   	pop    rdx
    7ffff7fb6b1a:	48 89 c2             	mov    rdx,rax
    7ffff7fb6b1d:	48 01 ea             	add    rdx,rbp
    7ffff7fb6b20:	4c 29 64 24 30       	sub    QWORD PTR [rsp+0x30],r12
    7ffff7fb6b25:	49 01 dd             	add    r13,rbx
    7ffff7fb6b28:	4c 89 6c 24 28       	mov    QWORD PTR [rsp+0x28],r13
    7ffff7fb6b2d:	4d 89 f5             	mov    r13,r14
    7ffff7fb6b30:	4d 89 fe             	mov    r14,r15
    7ffff7fb6b33:	eb 9e                	jmp    0x7ffff7fb6ad3
    7ffff7fb6b35:	48 83 ec 08          	sub    rsp,0x8
    7ffff7fb6b39:	4c 89 ef             	mov    rdi,r13
    7ffff7fb6b3c:	48 89 ee             	mov    rsi,rbp
    7ffff7fb6b3f:	8b 54 24 14          	mov    edx,DWORD PTR [rsp+0x14]
    7ffff7fb6b43:	4c 89 c9             	mov    rcx,r9
    7ffff7fb6b46:	4d 89 f0             	mov    r8,r14
    7ffff7fb6b49:	4d 89 d1             	mov    r9,r10
    7ffff7fb6b4c:	41 54                	push   r12
    7ffff7fb6b4e:	e8 52 01 00 00       	call   0x7ffff7fb6ca5
    7ffff7fb6b53:	59                   	pop    rcx
    7ffff7fb6b54:	5a                   	pop    rdx
    7ffff7fb6b55:	48 89 c1             	mov    rcx,rax
    7ffff7fb6b58:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb6b5d:	e9 e7 00 00 00       	jmp    0x7ffff7fb6c49
    7ffff7fb6b62:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
    7ffff7fb6b67:	4a 8d 04 e5 00 00 00 	lea    rax,[r12*8+0x0]
    7ffff7fb6b6e:	00 
    7ffff7fb6b6f:	48 89 44 24 38       	mov    QWORD PTR [rsp+0x38],rax
    7ffff7fb6b74:	31 d2                	xor    edx,edx
    7ffff7fb6b76:	4d 89 f7             	mov    r15,r14
    7ffff7fb6b79:	48 8b 6c 24 38       	mov    rbp,QWORD PTR [rsp+0x38]
    7ffff7fb6b7e:	4d 29 e7             	sub    r15,r12
    7ffff7fb6b81:	72 5b                	jb     0x7ffff7fb6bde
    7ffff7fb6b83:	4d 89 ee             	mov    r14,r13
    7ffff7fb6b86:	49 01 ee             	add    r14,rbp
    7ffff7fb6b89:	4c 89 f7             	mov    rdi,r14
    7ffff7fb6b8c:	4c 89 e6             	mov    rsi,r12
    7ffff7fb6b8f:	e8 cd 00 00 00       	call   0x7ffff7fb6c61
    7ffff7fb6b94:	48 89 c3             	mov    rbx,rax
    7ffff7fb6b97:	4c 89 ef             	mov    rdi,r13
    7ffff7fb6b9a:	48 8b 74 24 40       	mov    rsi,QWORD PTR [rsp+0x40]
    7ffff7fb6b9f:	8b 54 24 0c          	mov    edx,DWORD PTR [rsp+0xc]
    7ffff7fb6ba3:	4c 8b 6c 24 28       	mov    r13,QWORD PTR [rsp+0x28]
    7ffff7fb6ba8:	4c 89 e9             	mov    rcx,r13
    7ffff7fb6bab:	4d 89 e0             	mov    r8,r12
    7ffff7fb6bae:	4c 8b 4c 24 18       	mov    r9,QWORD PTR [rsp+0x18]
    7ffff7fb6bb3:	ff b4 24 a8 00 00 00 	push   QWORD PTR [rsp+0xa8]
    7ffff7fb6bba:	41 54                	push   r12
    7ffff7fb6bbc:	e8 ab 01 00 00       	call   0x7ffff7fb6d6c
    7ffff7fb6bc1:	59                   	pop    rcx
    7ffff7fb6bc2:	5a                   	pop    rdx
    7ffff7fb6bc3:	48 89 c2             	mov    rdx,rax
    7ffff7fb6bc6:	48 01 da             	add    rdx,rbx
    7ffff7fb6bc9:	4c 29 64 24 30       	sub    QWORD PTR [rsp+0x30],r12
    7ffff7fb6bce:	49 01 ed             	add    r13,rbp
    7ffff7fb6bd1:	4c 89 6c 24 28       	mov    QWORD PTR [rsp+0x28],r13
    7ffff7fb6bd6:	4d 89 f5             	mov    r13,r14
    7ffff7fb6bd9:	4d 89 fe             	mov    r14,r15
    7ffff7fb6bdc:	eb a0                	jmp    0x7ffff7fb6b7e
    7ffff7fb6bde:	48 8b 5c 24 30       	mov    rbx,QWORD PTR [rsp+0x30]
    7ffff7fb6be3:	48 89 de             	mov    rsi,rbx
    7ffff7fb6be6:	4c 29 e6             	sub    rsi,r12
    7ffff7fb6be9:	4a 8d 3c e5 00 00 00 	lea    rdi,[r12*8+0x0]
    7ffff7fb6bf0:	00 
    7ffff7fb6bf1:	4c 01 ef             	add    rdi,r13
    7ffff7fb6bf4:	e8 68 00 00 00       	call   0x7ffff7fb6c61
    7ffff7fb6bf9:	48 89 c1             	mov    rcx,rax
    7ffff7fb6bfc:	4d 85 f6             	test   r14,r14
    7ffff7fb6bff:	74 3e                	je     0x7ffff7fb6c3f
    7ffff7fb6c01:	4c 89 ef             	mov    rdi,r13
    7ffff7fb6c04:	48 89 de             	mov    rsi,rbx
    7ffff7fb6c07:	8b 54 24 0c          	mov    edx,DWORD PTR [rsp+0xc]
    7ffff7fb6c0b:	48 89 cb             	mov    rbx,rcx
    7ffff7fb6c0e:	48 8b 4c 24 18       	mov    rcx,QWORD PTR [rsp+0x18]
    7ffff7fb6c13:	4d 89 e0             	mov    r8,r12
    7ffff7fb6c16:	4c 8b 4c 24 28       	mov    r9,QWORD PTR [rsp+0x28]
    7ffff7fb6c1b:	ff b4 24 a8 00 00 00 	push   QWORD PTR [rsp+0xa8]
    7ffff7fb6c22:	41 56                	push   r14
    7ffff7fb6c24:	e8 d5 fc ff ff       	call   0x7ffff7fb68fe
    7ffff7fb6c29:	48 89 d9             	mov    rcx,rbx
    7ffff7fb6c2c:	48 83 c4 10          	add    rsp,0x10
    7ffff7fb6c30:	48 03 4c 24 20       	add    rcx,QWORD PTR [rsp+0x20]
    7ffff7fb6c35:	48 01 c1             	add    rcx,rax
    7ffff7fb6c38:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb6c3d:	eb 0d                	jmp    0x7ffff7fb6c4c
    7ffff7fb6c3f:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb6c44:	48 8b 5c 24 20       	mov    rbx,QWORD PTR [rsp+0x20]
    7ffff7fb6c49:	48 01 d9             	add    rcx,rbx
    7ffff7fb6c4c:	48 01 c1             	add    rcx,rax
    7ffff7fb6c4f:	48 89 c8             	mov    rax,rcx
    7ffff7fb6c52:	48 83 c4 68          	add    rsp,0x68
    7ffff7fb6c56:	5b                   	pop    rbx
    7ffff7fb6c57:	41 5c                	pop    r12
    7ffff7fb6c59:	41 5d                	pop    r13
    7ffff7fb6c5b:	41 5e                	pop    r14
    7ffff7fb6c5d:	41 5f                	pop    r15
    7ffff7fb6c5f:	5d                   	pop    rbp
    7ffff7fb6c60:	c3                   	ret
    7ffff7fb6c61:	50                   	push   rax
    7ffff7fb6c62:	48 85 d2             	test   rdx,rdx
    7ffff7fb6c65:	74 3a                	je     0x7ffff7fb6ca1
    7ffff7fb6c67:	48 89 d0             	mov    rax,rdx
    7ffff7fb6c6a:	48 85 f6             	test   rsi,rsi
    7ffff7fb6c6d:	74 34                	je     0x7ffff7fb6ca3
    7ffff7fb6c6f:	48 89 c2             	mov    rdx,rax
    7ffff7fb6c72:	48 f7 da             	neg    rdx
    7ffff7fb6c75:	48 0f 48 d0          	cmovs  rdx,rax
    7ffff7fb6c79:	48 85 c0             	test   rax,rax
    7ffff7fb6c7c:	78 0a                	js     0x7ffff7fb6c88
    7ffff7fb6c7e:	e8 6c 0f 00 00       	call   0x7ffff7fb7bef
    7ffff7fb6c83:	0f b6 c0             	movzx  eax,al
    7ffff7fb6c86:	eb 1b                	jmp    0x7ffff7fb6ca3
    7ffff7fb6c88:	48 29 17             	sub    QWORD PTR [rdi],rdx
    7ffff7fb6c8b:	73 14                	jae    0x7ffff7fb6ca1
    7ffff7fb6c8d:	48 ff ce             	dec    rsi
    7ffff7fb6c90:	48 83 c7 08          	add    rdi,0x8
    7ffff7fb6c94:	e8 25 f3 ff ff       	call   0x7ffff7fb5fbe
    7ffff7fb6c99:	0f b6 c0             	movzx  eax,al
    7ffff7fb6c9c:	48 f7 d8             	neg    rax
    7ffff7fb6c9f:	eb 02                	jmp    0x7ffff7fb6ca3
    7ffff7fb6ca1:	31 c0                	xor    eax,eax
    7ffff7fb6ca3:	59                   	pop    rcx
    7ffff7fb6ca4:	c3                   	ret
    7ffff7fb6ca5:	55                   	push   rbp
    7ffff7fb6ca6:	41 57                	push   r15
    7ffff7fb6ca8:	41 56                	push   r14
    7ffff7fb6caa:	41 55                	push   r13
    7ffff7fb6cac:	41 54                	push   r12
    7ffff7fb6cae:	53                   	push   rbx
    7ffff7fb6caf:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb6cb3:	4c 89 4c 24 10       	mov    QWORD PTR [rsp+0x10],r9
    7ffff7fb6cb8:	4d 89 c7             	mov    r15,r8
    7ffff7fb6cbb:	48 89 4c 24 08       	mov    QWORD PTR [rsp+0x8],rcx
    7ffff7fb6cc0:	49 89 fc             	mov    r12,rdi
    7ffff7fb6cc3:	48 8b 6c 24 50       	mov    rbp,QWORD PTR [rsp+0x50]
    7ffff7fb6cc8:	48 c1 e5 03          	shl    rbp,0x3
    7ffff7fb6ccc:	31 db                	xor    ebx,ebx
    7ffff7fb6cce:	4d 89 c6             	mov    r14,r8
    7ffff7fb6cd1:	31 c0                	xor    eax,eax
    7ffff7fb6cd3:	85 d2                	test   edx,edx
    7ffff7fb6cd5:	74 3b                	je     0x7ffff7fb6d12
    7ffff7fb6cd7:	44 0f b6 e8          	movzx  r13d,al
    7ffff7fb6cdb:	48 39 dd             	cmp    rbp,rbx
    7ffff7fb6cde:	74 6d                	je     0x7ffff7fb6d4d
    7ffff7fb6ce0:	49 8d 3c 1c          	lea    rdi,[r12+rbx*1]
    7ffff7fb6ce4:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb6ce9:	48 8b 14 18          	mov    rdx,QWORD PTR [rax+rbx*1]
    7ffff7fb6ced:	4c 89 fe             	mov    rsi,r15
    7ffff7fb6cf0:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
    7ffff7fb6cf5:	4d 89 f8             	mov    r8,r15
    7ffff7fb6cf8:	e8 af 0e 00 00       	call   0x7ffff7fb7bac
    7ffff7fb6cfd:	41 0f ba e5 00       	bt     r13d,0x0
    7ffff7fb6d02:	4b 19 04 f4          	sbb    QWORD PTR [r12+r14*8],rax
    7ffff7fb6d06:	0f 92 c0             	setb   al
    7ffff7fb6d09:	48 83 c3 08          	add    rbx,0x8
    7ffff7fb6d0d:	49 ff c6             	inc    r14
    7ffff7fb6d10:	eb c5                	jmp    0x7ffff7fb6cd7
    7ffff7fb6d12:	44 0f b6 e8          	movzx  r13d,al
    7ffff7fb6d16:	48 39 dd             	cmp    rbp,rbx
    7ffff7fb6d19:	74 3b                	je     0x7ffff7fb6d56
    7ffff7fb6d1b:	49 8d 3c 1c          	lea    rdi,[r12+rbx*1]
    7ffff7fb6d1f:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb6d24:	48 8b 14 18          	mov    rdx,QWORD PTR [rax+rbx*1]
    7ffff7fb6d28:	4c 89 fe             	mov    rsi,r15
    7ffff7fb6d2b:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
    7ffff7fb6d30:	4d 89 f8             	mov    r8,r15
    7ffff7fb6d33:	e8 02 0e 00 00       	call   0x7ffff7fb7b3a
    7ffff7fb6d38:	41 0f ba e5 00       	bt     r13d,0x0
    7ffff7fb6d3d:	4b 11 04 f4          	adc    QWORD PTR [r12+r14*8],rax
    7ffff7fb6d41:	0f 92 c0             	setb   al
    7ffff7fb6d44:	48 83 c3 08          	add    rbx,0x8
    7ffff7fb6d48:	49 ff c6             	inc    r14
    7ffff7fb6d4b:	eb c5                	jmp    0x7ffff7fb6d12
    7ffff7fb6d4d:	41 83 e5 01          	and    r13d,0x1
    7ffff7fb6d51:	49 f7 dd             	neg    r13
    7ffff7fb6d54:	eb 04                	jmp    0x7ffff7fb6d5a
    7ffff7fb6d56:	41 83 e5 01          	and    r13d,0x1
    7ffff7fb6d5a:	4c 89 e8             	mov    rax,r13
    7ffff7fb6d5d:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb6d61:	5b                   	pop    rbx
    7ffff7fb6d62:	41 5c                	pop    r12
    7ffff7fb6d64:	41 5d                	pop    r13
    7ffff7fb6d66:	41 5e                	pop    r14
    7ffff7fb6d68:	41 5f                	pop    r15
    7ffff7fb6d6a:	5d                   	pop    rbp
    7ffff7fb6d6b:	c3                   	ret
    7ffff7fb6d6c:	55                   	push   rbp
    7ffff7fb6d6d:	41 57                	push   r15
    7ffff7fb6d6f:	41 56                	push   r14
    7ffff7fb6d71:	41 55                	push   r13
    7ffff7fb6d73:	41 54                	push   r12
    7ffff7fb6d75:	53                   	push   rbx
    7ffff7fb6d76:	48 81 ec 58 01 00 00 	sub    rsp,0x158
    7ffff7fb6d7d:	89 54 24 30          	mov    DWORD PTR [rsp+0x30],edx
    7ffff7fb6d81:	49 8d 40 02          	lea    rax,[r8+0x2]
    7ffff7fb6d85:	6a 03                	push   0x3
    7ffff7fb6d87:	41 5a                	pop    r10
    7ffff7fb6d89:	31 d2                	xor    edx,edx
    7ffff7fb6d8b:	49 f7 f2             	div    r10
    7ffff7fb6d8e:	49 89 c7             	mov    r15,rax
    7ffff7fb6d91:	4d 89 cc             	mov    r12,r9
    7ffff7fb6d94:	49 89 ce             	mov    r14,rcx
    7ffff7fb6d97:	48 89 b4 24 c0 00 00 	mov    QWORD PTR [rsp+0xc0],rsi
    7ffff7fb6d9e:	00 
    7ffff7fb6d9f:	48 89 7c 24 58       	mov    QWORD PTR [rsp+0x58],rdi
    7ffff7fb6da4:	48 8b 84 24 98 01 00 	mov    rax,QWORD PTR [rsp+0x198]
    7ffff7fb6dab:	00 
    7ffff7fb6dac:	48 8b 94 24 90 01 00 	mov    rdx,QWORD PTR [rsp+0x190]
    7ffff7fb6db3:	00 
    7ffff7fb6db4:	4b 8d 2c 3f          	lea    rbp,[r15+r15*1]
    7ffff7fb6db8:	4c 89 c6             	mov    rsi,r8
    7ffff7fb6dbb:	48 29 ee             	sub    rsi,rbp
    7ffff7fb6dbe:	48 89 74 24 10       	mov    QWORD PTR [rsp+0x10],rsi
    7ffff7fb6dc3:	4a 8d 34 f9          	lea    rsi,[rcx+r15*8]
    7ffff7fb6dc7:	48 89 4c 24 70       	mov    QWORD PTR [rsp+0x70],rcx
    7ffff7fb6dcc:	48 89 74 24 50       	mov    QWORD PTR [rsp+0x50],rsi
    7ffff7fb6dd1:	4d 29 f8             	sub    r8,r15
    7ffff7fb6dd4:	4a 8d 0c fe          	lea    rcx,[rsi+r15*8]
    7ffff7fb6dd8:	48 89 4c 24 40       	mov    QWORD PTR [rsp+0x40],rcx
    7ffff7fb6ddd:	4d 29 f8             	sub    r8,r15
    7ffff7fb6de0:	4c 89 44 24 38       	mov    QWORD PTR [rsp+0x38],r8
    7ffff7fb6de5:	4c 29 fa             	sub    rdx,r15
    7ffff7fb6de8:	4c 29 fa             	sub    rdx,r15
    7ffff7fb6deb:	48 89 54 24 68       	mov    QWORD PTR [rsp+0x68],rdx
    7ffff7fb6df0:	48 8b 30             	mov    rsi,QWORD PTR [rax]
    7ffff7fb6df3:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
    7ffff7fb6df7:	4b 8d 04 f9          	lea    rax,[r9+r15*8]
    7ffff7fb6dfb:	4c 89 4c 24 78       	mov    QWORD PTR [rsp+0x78],r9
    7ffff7fb6e00:	48 89 84 24 98 00 00 	mov    QWORD PTR [rsp+0x98],rax
    7ffff7fb6e07:	00 
    7ffff7fb6e08:	4a 8d 04 f8          	lea    rax,[rax+r15*8]
    7ffff7fb6e0c:	48 89 44 24 48       	mov    QWORD PTR [rsp+0x48],rax
    7ffff7fb6e11:	4b 8d 4c 3f 02       	lea    rcx,[r15+r15*1+0x2]
    7ffff7fb6e16:	48 89 8c 24 a8 00 00 	mov    QWORD PTR [rsp+0xa8],rcx
    7ffff7fb6e1d:	00 
    7ffff7fb6e1e:	48 8d 9c 24 18 01 00 	lea    rbx,[rsp+0x118]
    7ffff7fb6e25:	00 
    7ffff7fb6e26:	48 89 df             	mov    rdi,rbx
    7ffff7fb6e29:	e8 ce 0a 00 00       	call   0x7ffff7fb78fc
    7ffff7fb6e2e:	4c 8b 2b             	mov    r13,QWORD PTR [rbx]
    7ffff7fb6e31:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
    7ffff7fb6e35:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
    7ffff7fb6e3a:	48 8b 4b 10          	mov    rcx,QWORD PTR [rbx+0x10]
    7ffff7fb6e3e:	48 89 0c 24          	mov    QWORD PTR [rsp],rcx
    7ffff7fb6e42:	48 8b 53 18          	mov    rdx,QWORD PTR [rbx+0x18]
    7ffff7fb6e46:	48 89 54 24 08       	mov    QWORD PTR [rsp+0x8],rdx
    7ffff7fb6e4b:	48 8d 84 24 48 01 00 	lea    rax,[rsp+0x148]
    7ffff7fb6e52:	00 
    7ffff7fb6e53:	48 89 08             	mov    QWORD PTR [rax],rcx
    7ffff7fb6e56:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
    7ffff7fb6e5a:	4c 89 ef             	mov    rdi,r13
    7ffff7fb6e5d:	48 89 ee             	mov    rsi,rbp
    7ffff7fb6e60:	31 d2                	xor    edx,edx
    7ffff7fb6e62:	4c 89 f1             	mov    rcx,r14
    7ffff7fb6e65:	4d 89 f8             	mov    r8,r15
    7ffff7fb6e68:	4d 89 e1             	mov    r9,r12
    7ffff7fb6e6b:	50                   	push   rax
    7ffff7fb6e6c:	41 57                	push   r15
    7ffff7fb6e6e:	e8 de 0a 00 00       	call   0x7ffff7fb7951
    7ffff7fb6e73:	59                   	pop    rcx
    7ffff7fb6e74:	5a                   	pop    rdx
    7ffff7fb6e75:	48 8b 5c 24 58       	mov    rbx,QWORD PTR [rsp+0x58]
    7ffff7fb6e7a:	48 89 df             	mov    rdi,rbx
    7ffff7fb6e7d:	48 89 ee             	mov    rsi,rbp
    7ffff7fb6e80:	44 8b 74 24 30       	mov    r14d,DWORD PTR [rsp+0x30]
    7ffff7fb6e85:	44 89 f2             	mov    edx,r14d
    7ffff7fb6e88:	4c 89 e9             	mov    rcx,r13
    7ffff7fb6e8b:	49 89 e8             	mov    r8,rbp
    7ffff7fb6e8e:	e8 f9 0a 00 00       	call   0x7ffff7fb798c
    7ffff7fb6e93:	48 89 84 24 f0 00 00 	mov    QWORD PTR [rsp+0xf0],rax
    7ffff7fb6e9a:	00 
    7ffff7fb6e9b:	4a 8d 04 bd 00 00 00 	lea    rax,[r15*4+0x0]
    7ffff7fb6ea2:	00 
    7ffff7fb6ea3:	48 89 84 24 88 00 00 	mov    QWORD PTR [rsp+0x88],rax
    7ffff7fb6eaa:	00 
    7ffff7fb6eab:	4a 8d 04 bd 02 00 00 	lea    rax,[r15*4+0x2]
    7ffff7fb6eb2:	00 
    7ffff7fb6eb3:	48 89 84 24 f8 00 00 	mov    QWORD PTR [rsp+0xf8],rax
    7ffff7fb6eba:	00 
    7ffff7fb6ebb:	48 29 e8             	sub    rax,rbp
    7ffff7fb6ebe:	48 89 c6             	mov    rsi,rax
    7ffff7fb6ec1:	48 89 84 24 b0 00 00 	mov    QWORD PTR [rsp+0xb0],rax
    7ffff7fb6ec8:	00 
    7ffff7fb6ec9:	4d 89 fc             	mov    r12,r15
    7ffff7fb6ecc:	49 c1 e4 04          	shl    r12,0x4
    7ffff7fb6ed0:	4a 8d 3c 23          	lea    rdi,[rbx+r12*1]
    7ffff7fb6ed4:	48 89 bc 24 b8 00 00 	mov    QWORD PTR [rsp+0xb8],rdi
    7ffff7fb6edb:	00 
    7ffff7fb6edc:	44 89 f0             	mov    eax,r14d
    7ffff7fb6edf:	34 01                	xor    al,0x1
    7ffff7fb6ee1:	0f b6 d0             	movzx  edx,al
    7ffff7fb6ee4:	89 54 24 24          	mov    DWORD PTR [rsp+0x24],edx
    7ffff7fb6ee8:	4c 89 e9             	mov    rcx,r13
    7ffff7fb6eeb:	49 89 e8             	mov    r8,rbp
    7ffff7fb6eee:	e8 c1 0a 00 00       	call   0x7ffff7fb79b4
    7ffff7fb6ef3:	48 89 84 24 e8 00 00 	mov    QWORD PTR [rsp+0xe8],rax
    7ffff7fb6efa:	00 
    7ffff7fb6efb:	4c 89 ef             	mov    rdi,r13
    7ffff7fb6efe:	48 89 ac 24 00 01 00 	mov    QWORD PTR [rsp+0x100],rbp
    7ffff7fb6f05:	00 
    7ffff7fb6f06:	48 89 ee             	mov    rsi,rbp
    7ffff7fb6f09:	6a 03                	push   0x3
    7ffff7fb6f0b:	5a                   	pop    rdx
    7ffff7fb6f0c:	e8 7d 0b 00 00       	call   0x7ffff7fb7a8e
    7ffff7fb6f11:	4b 89 44 25 00       	mov    QWORD PTR [r13+r12*1+0x0],rax
    7ffff7fb6f16:	4b 83 64 25 08 00    	and    QWORD PTR [r13+r12*1+0x8],0x0
    7ffff7fb6f1c:	4d 8d 67 01          	lea    r12,[r15+0x1]
    7ffff7fb6f20:	48 8d ac 24 18 01 00 	lea    rbp,[rsp+0x118]
    7ffff7fb6f27:	00 
    7ffff7fb6f28:	48 89 ef             	mov    rdi,rbp
    7ffff7fb6f2b:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
    7ffff7fb6f2f:	48 8b 54 24 08       	mov    rdx,QWORD PTR [rsp+0x8]
    7ffff7fb6f34:	4c 89 e1             	mov    rcx,r12
    7ffff7fb6f37:	4c 89 a4 24 80 00 00 	mov    QWORD PTR [rsp+0x80],r12
    7ffff7fb6f3e:	00 
    7ffff7fb6f3f:	4c 8b 44 24 70       	mov    r8,QWORD PTR [rsp+0x70]
    7ffff7fb6f44:	4d 89 f9             	mov    r9,r15
    7ffff7fb6f47:	e8 71 0b 00 00       	call   0x7ffff7fb7abd
    7ffff7fb6f4c:	48 8b 5d 00          	mov    rbx,QWORD PTR [rbp+0x0]
    7ffff7fb6f50:	48 8b 45 08          	mov    rax,QWORD PTR [rbp+0x8]
    7ffff7fb6f54:	48 89 44 24 08       	mov    QWORD PTR [rsp+0x8],rax
    7ffff7fb6f59:	48 8b 75 10          	mov    rsi,QWORD PTR [rbp+0x10]
    7ffff7fb6f5d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
    7ffff7fb6f61:	4c 8d b4 24 18 01 00 	lea    r14,[rsp+0x118]
    7ffff7fb6f68:	00 
    7ffff7fb6f69:	4c 89 f7             	mov    rdi,r14
    7ffff7fb6f6c:	4c 89 e1             	mov    rcx,r12
    7ffff7fb6f6f:	4c 8b 44 24 78       	mov    r8,QWORD PTR [rsp+0x78]
    7ffff7fb6f74:	4d 89 f9             	mov    r9,r15
    7ffff7fb6f77:	e8 41 0b 00 00       	call   0x7ffff7fb7abd
    7ffff7fb6f7c:	4d 8b 26             	mov    r12,QWORD PTR [r14]
    7ffff7fb6f7f:	49 8b 6e 08          	mov    rbp,QWORD PTR [r14+0x8]
    7ffff7fb6f83:	48 89 ac 24 a0 00 00 	mov    QWORD PTR [rsp+0xa0],rbp
    7ffff7fb6f8a:	00 
    7ffff7fb6f8b:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
    7ffff7fb6f8f:	48 89 04 24          	mov    QWORD PTR [rsp],rax
    7ffff7fb6f93:	49 8b 4e 18          	mov    rcx,QWORD PTR [r14+0x18]
    7ffff7fb6f97:	48 89 4c 24 60       	mov    QWORD PTR [rsp+0x60],rcx
    7ffff7fb6f9c:	48 8d 94 24 38 01 00 	lea    rdx,[rsp+0x138]
    7ffff7fb6fa3:	00 
    7ffff7fb6fa4:	48 89 02             	mov    QWORD PTR [rdx],rax
    7ffff7fb6fa7:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
    7ffff7fb6fab:	6a 02                	push   0x2
    7ffff7fb6fad:	5a                   	pop    rdx
    7ffff7fb6fae:	49 89 de             	mov    r14,rbx
    7ffff7fb6fb1:	48 89 df             	mov    rdi,rbx
    7ffff7fb6fb4:	4c 89 fe             	mov    rsi,r15
    7ffff7fb6fb7:	48 8b 4c 24 50       	mov    rcx,QWORD PTR [rsp+0x50]
    7ffff7fb6fbc:	4d 89 f8             	mov    r8,r15
    7ffff7fb6fbf:	e8 76 0b 00 00       	call   0x7ffff7fb7b3a
    7ffff7fb6fc4:	4a 89 04 fb          	mov    QWORD PTR [rbx+r15*8],rax
    7ffff7fb6fc8:	48 89 df             	mov    rdi,rbx
    7ffff7fb6fcb:	4c 89 fe             	mov    rsi,r15
    7ffff7fb6fce:	48 8b 54 24 40       	mov    rdx,QWORD PTR [rsp+0x40]
    7ffff7fb6fd3:	48 8b 4c 24 38       	mov    rcx,QWORD PTR [rsp+0x38]
    7ffff7fb6fd8:	e8 93 0b 00 00       	call   0x7ffff7fb7b70
    7ffff7fb6fdd:	4a 01 04 fb          	add    QWORD PTR [rbx+r15*8],rax
    7ffff7fb6fe1:	48 89 5c 24 28       	mov    QWORD PTR [rsp+0x28],rbx
    7ffff7fb6fe6:	4c 89 e3             	mov    rbx,r12
    7ffff7fb6fe9:	4c 89 a4 24 90 00 00 	mov    QWORD PTR [rsp+0x90],r12
    7ffff7fb6ff0:	00 
    7ffff7fb6ff1:	4c 89 e7             	mov    rdi,r12
    7ffff7fb6ff4:	4c 89 fe             	mov    rsi,r15
    7ffff7fb6ff7:	6a 02                	push   0x2
    7ffff7fb6ff9:	5a                   	pop    rdx
    7ffff7fb6ffa:	48 8b 8c 24 98 00 00 	mov    rcx,QWORD PTR [rsp+0x98]
    7ffff7fb7001:	00 
    7ffff7fb7002:	4d 89 f8             	mov    r8,r15
    7ffff7fb7005:	e8 30 0b 00 00       	call   0x7ffff7fb7b3a
    7ffff7fb700a:	4b 89 04 fc          	mov    QWORD PTR [r12+r15*8],rax
    7ffff7fb700e:	4c 89 e7             	mov    rdi,r12
    7ffff7fb7011:	4c 89 fe             	mov    rsi,r15
    7ffff7fb7014:	48 8b 54 24 48       	mov    rdx,QWORD PTR [rsp+0x48]
    7ffff7fb7019:	4c 8b 64 24 68       	mov    r12,QWORD PTR [rsp+0x68]
    7ffff7fb701e:	4c 89 e1             	mov    rcx,r12
    7ffff7fb7021:	e8 4a 0b 00 00       	call   0x7ffff7fb7b70
    7ffff7fb7026:	4a 01 04 fb          	add    QWORD PTR [rbx+r15*8],rax
    7ffff7fb702a:	4c 89 ef             	mov    rdi,r13
    7ffff7fb702d:	48 8b 74 24 18       	mov    rsi,QWORD PTR [rsp+0x18]
    7ffff7fb7032:	31 d2                	xor    edx,edx
    7ffff7fb7034:	4c 89 f1             	mov    rcx,r14
    7ffff7fb7037:	4c 8b 44 24 08       	mov    r8,QWORD PTR [rsp+0x8]
    7ffff7fb703c:	49 89 d9             	mov    r9,rbx
    7ffff7fb703f:	48 8d 84 24 38 01 00 	lea    rax,[rsp+0x138]
    7ffff7fb7046:	00 
    7ffff7fb7047:	50                   	push   rax
    7ffff7fb7048:	55                   	push   rbp
    7ffff7fb7049:	e8 03 09 00 00       	call   0x7ffff7fb7951
    7ffff7fb704e:	59                   	pop    rcx
    7ffff7fb704f:	5a                   	pop    rdx
    7ffff7fb7050:	48 8d ac 24 18 01 00 	lea    rbp,[rsp+0x118]
    7ffff7fb7057:	00 
    7ffff7fb7058:	48 89 ef             	mov    rdi,rbp
    7ffff7fb705b:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
    7ffff7fb705f:	48 8b 54 24 60       	mov    rdx,QWORD PTR [rsp+0x60]
    7ffff7fb7064:	48 8b 9c 24 a8 00 00 	mov    rbx,QWORD PTR [rsp+0xa8]
    7ffff7fb706b:	00 
    7ffff7fb706c:	48 89 d9             	mov    rcx,rbx
    7ffff7fb706f:	e8 88 08 00 00       	call   0x7ffff7fb78fc
    7ffff7fb7074:	4c 8b 75 00          	mov    r14,QWORD PTR [rbp+0x0]
    7ffff7fb7078:	c5 f8 10 45 10       	vmovups xmm0,XMMWORD PTR [rbp+0x10]
    7ffff7fb707d:	48 8d 84 24 08 01 00 	lea    rax,[rsp+0x108]
    7ffff7fb7084:	00 
    7ffff7fb7085:	c5 f8 11 00          	vmovups XMMWORD PTR [rax],xmm0
    7ffff7fb7089:	49 89 c2             	mov    r10,rax
    7ffff7fb708c:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb7091:	48 8d 2c 00          	lea    rbp,[rax+rax*1]
    7ffff7fb7095:	4c 89 f7             	mov    rdi,r14
    7ffff7fb7098:	48 89 ee             	mov    rsi,rbp
    7ffff7fb709b:	31 d2                	xor    edx,edx
    7ffff7fb709d:	48 8b 4c 24 40       	mov    rcx,QWORD PTR [rsp+0x40]
    7ffff7fb70a2:	4c 8b 44 24 38       	mov    r8,QWORD PTR [rsp+0x38]
    7ffff7fb70a7:	4c 8b 4c 24 48       	mov    r9,QWORD PTR [rsp+0x48]
    7ffff7fb70ac:	41 52                	push   r10
    7ffff7fb70ae:	41 54                	push   r12
    7ffff7fb70b0:	e8 9c 08 00 00       	call   0x7ffff7fb7951
    7ffff7fb70b5:	59                   	pop    rcx
    7ffff7fb70b6:	5a                   	pop    rdx
    7ffff7fb70b7:	48 8b bc 24 b8 00 00 	mov    rdi,QWORD PTR [rsp+0xb8]
    7ffff7fb70be:	00 
    7ffff7fb70bf:	48 8b b4 24 b0 00 00 	mov    rsi,QWORD PTR [rsp+0xb0]
    7ffff7fb70c6:	00 
    7ffff7fb70c7:	8b 54 24 24          	mov    edx,DWORD PTR [rsp+0x24]
    7ffff7fb70cb:	4c 89 f1             	mov    rcx,r14
    7ffff7fb70ce:	49 89 e8             	mov    r8,rbp
    7ffff7fb70d1:	e8 de 08 00 00       	call   0x7ffff7fb79b4
    7ffff7fb70d6:	48 89 84 24 e0 00 00 	mov    QWORD PTR [rsp+0xe0],rax
    7ffff7fb70dd:	00 
    7ffff7fb70de:	48 8b b4 24 c0 00 00 	mov    rsi,QWORD PTR [rsp+0xc0]
    7ffff7fb70e5:	00 
    7ffff7fb70e6:	48 2b b4 24 88 00 00 	sub    rsi,QWORD PTR [rsp+0x88]
    7ffff7fb70ed:	00 
    7ffff7fb70ee:	4c 89 ff             	mov    rdi,r15
    7ffff7fb70f1:	48 c1 e7 05          	shl    rdi,0x5
    7ffff7fb70f5:	48 03 7c 24 58       	add    rdi,QWORD PTR [rsp+0x58]
    7ffff7fb70fa:	8b 54 24 30          	mov    edx,DWORD PTR [rsp+0x30]
    7ffff7fb70fe:	4c 89 f1             	mov    rcx,r14
    7ffff7fb7101:	49 89 e8             	mov    r8,rbp
    7ffff7fb7104:	e8 83 08 00 00       	call   0x7ffff7fb798c
    7ffff7fb7109:	48 89 84 24 88 00 00 	mov    QWORD PTR [rsp+0x88],rax
    7ffff7fb7110:	00 
    7ffff7fb7111:	6a 0c                	push   0xc
    7ffff7fb7113:	5a                   	pop    rdx
    7ffff7fb7114:	4c 89 f7             	mov    rdi,r14
    7ffff7fb7117:	48 89 ee             	mov    rsi,rbp
    7ffff7fb711a:	e8 6f 09 00 00       	call   0x7ffff7fb7a8e
    7ffff7fb711f:	48 8b 54 24 10       	mov    rdx,QWORD PTR [rsp+0x10]
    7ffff7fb7124:	48 8d 0c 55 01 00 00 	lea    rcx,[rdx*2+0x1]
    7ffff7fb712b:	00 
    7ffff7fb712c:	48 c1 e2 04          	shl    rdx,0x4
    7ffff7fb7130:	49 89 04 16          	mov    QWORD PTR [r14+rdx*1],rax
    7ffff7fb7134:	4c 89 ef             	mov    rdi,r13
    7ffff7fb7137:	48 8b 74 24 18       	mov    rsi,QWORD PTR [rsp+0x18]
    7ffff7fb713c:	4c 89 f2             	mov    rdx,r14
    7ffff7fb713f:	e8 fb ee ff ff       	call   0x7ffff7fb603f
    7ffff7fb7144:	4c 8d b4 24 18 01 00 	lea    r14,[rsp+0x118]
    7ffff7fb714b:	00 
    7ffff7fb714c:	4c 89 f7             	mov    rdi,r14
    7ffff7fb714f:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
    7ffff7fb7153:	48 8b 54 24 60       	mov    rdx,QWORD PTR [rsp+0x60]
    7ffff7fb7158:	48 89 d9             	mov    rcx,rbx
    7ffff7fb715b:	e8 9c 07 00 00       	call   0x7ffff7fb78fc
    7ffff7fb7160:	49 8b 06             	mov    rax,QWORD PTR [r14]
    7ffff7fb7163:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
    7ffff7fb7168:	49 8b 46 08          	mov    rax,QWORD PTR [r14+0x8]
    7ffff7fb716c:	48 89 04 24          	mov    QWORD PTR [rsp],rax
    7ffff7fb7170:	49 8b 76 10          	mov    rsi,QWORD PTR [r14+0x10]
    7ffff7fb7174:	48 89 b4 24 d8 00 00 	mov    QWORD PTR [rsp+0xd8],rsi
    7ffff7fb717b:	00 
    7ffff7fb717c:	49 8b 56 18          	mov    rdx,QWORD PTR [r14+0x18]
    7ffff7fb7180:	48 89 54 24 60       	mov    QWORD PTR [rsp+0x60],rdx
    7ffff7fb7185:	48 8d ac 24 18 01 00 	lea    rbp,[rsp+0x118]
    7ffff7fb718c:	00 
    7ffff7fb718d:	48 89 ef             	mov    rdi,rbp
    7ffff7fb7190:	4c 8b a4 24 80 00 00 	mov    r12,QWORD PTR [rsp+0x80]
    7ffff7fb7197:	00 
    7ffff7fb7198:	4c 89 e1             	mov    rcx,r12
    7ffff7fb719b:	4c 8b 44 24 70       	mov    r8,QWORD PTR [rsp+0x70]
    7ffff7fb71a0:	4d 89 f9             	mov    r9,r15
    7ffff7fb71a3:	e8 15 09 00 00       	call   0x7ffff7fb7abd
    7ffff7fb71a8:	48 8b 5d 00          	mov    rbx,QWORD PTR [rbp+0x0]
    7ffff7fb71ac:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
    7ffff7fb71b0:	48 89 84 24 c8 00 00 	mov    QWORD PTR [rsp+0xc8],rax
    7ffff7fb71b7:	00 
    7ffff7fb71b8:	48 8b 6d 18          	mov    rbp,QWORD PTR [rbp+0x18]
    7ffff7fb71bc:	48 89 df             	mov    rdi,rbx
    7ffff7fb71bf:	4c 89 fe             	mov    rsi,r15
    7ffff7fb71c2:	48 8b 54 24 40       	mov    rdx,QWORD PTR [rsp+0x40]
    7ffff7fb71c7:	48 8b 4c 24 38       	mov    rcx,QWORD PTR [rsp+0x38]
    7ffff7fb71cc:	e8 38 ee ff ff       	call   0x7ffff7fb6009
    7ffff7fb71d1:	0f b6 c0             	movzx  eax,al
    7ffff7fb71d4:	48 89 de             	mov    rsi,rbx
    7ffff7fb71d7:	48 89 5c 24 70       	mov    QWORD PTR [rsp+0x70],rbx
    7ffff7fb71dc:	4a 89 04 fb          	mov    QWORD PTR [rbx+r15*8],rax
    7ffff7fb71e0:	48 8b 44 24 08       	mov    rax,QWORD PTR [rsp+0x8]
    7ffff7fb71e5:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
    7ffff7fb71ec:	00 
    7ffff7fb71ed:	48 89 94 24 d0 00 00 	mov    QWORD PTR [rsp+0xd0],rdx
    7ffff7fb71f4:	00 
    7ffff7fb71f5:	4c 8b 35 6c 19 00 00 	mov    r14,QWORD PTR [rip+0x196c]        # 0x7ffff7fb8b68
    7ffff7fb71fc:	48 8b 5c 24 28       	mov    rbx,QWORD PTR [rsp+0x28]
    7ffff7fb7201:	48 89 df             	mov    rdi,rbx
    7ffff7fb7204:	41 ff d6             	call   r14
    7ffff7fb7207:	48 89 df             	mov    rdi,rbx
    7ffff7fb720a:	4c 89 fe             	mov    rsi,r15
    7ffff7fb720d:	48 8b 54 24 50       	mov    rdx,QWORD PTR [rsp+0x50]
    7ffff7fb7212:	4c 89 f9             	mov    rcx,r15
    7ffff7fb7215:	e8 c4 ed ff ff       	call   0x7ffff7fb5fde
    7ffff7fb721a:	0f b6 c0             	movzx  eax,al
    7ffff7fb721d:	4a 01 04 fb          	add    QWORD PTR [rbx+r15*8],rax
    7ffff7fb7221:	48 8d 9c 24 18 01 00 	lea    rbx,[rsp+0x118]
    7ffff7fb7228:	00 
    7ffff7fb7229:	48 89 df             	mov    rdi,rbx
    7ffff7fb722c:	48 8b b4 24 c8 00 00 	mov    rsi,QWORD PTR [rsp+0xc8]
    7ffff7fb7233:	00 
    7ffff7fb7234:	48 89 ea             	mov    rdx,rbp
    7ffff7fb7237:	4c 89 e1             	mov    rcx,r12
    7ffff7fb723a:	4c 8b 44 24 78       	mov    r8,QWORD PTR [rsp+0x78]
    7ffff7fb723f:	4d 89 f9             	mov    r9,r15
    7ffff7fb7242:	e8 76 08 00 00       	call   0x7ffff7fb7abd
    7ffff7fb7247:	4c 8b 23             	mov    r12,QWORD PTR [rbx]
    7ffff7fb724a:	c5 f8 10 43 10       	vmovups xmm0,XMMWORD PTR [rbx+0x10]
    7ffff7fb724f:	48 8d 84 24 08 01 00 	lea    rax,[rsp+0x108]
    7ffff7fb7256:	00 
    7ffff7fb7257:	c5 f8 11 00          	vmovups XMMWORD PTR [rax],xmm0
    7ffff7fb725b:	4c 89 e7             	mov    rdi,r12
    7ffff7fb725e:	4c 89 fe             	mov    rsi,r15
    7ffff7fb7261:	48 8b 54 24 48       	mov    rdx,QWORD PTR [rsp+0x48]
    7ffff7fb7266:	48 8b 4c 24 68       	mov    rcx,QWORD PTR [rsp+0x68]
    7ffff7fb726b:	e8 99 ed ff ff       	call   0x7ffff7fb6009
    7ffff7fb7270:	0f b6 c0             	movzx  eax,al
    7ffff7fb7273:	4c 89 e6             	mov    rsi,r12
    7ffff7fb7276:	4c 89 a4 24 80 00 00 	mov    QWORD PTR [rsp+0x80],r12
    7ffff7fb727d:	00 
    7ffff7fb727e:	4b 89 04 fc          	mov    QWORD PTR [r12+r15*8],rax
    7ffff7fb7282:	4c 8b a4 24 a0 00 00 	mov    r12,QWORD PTR [rsp+0xa0]
    7ffff7fb7289:	00 
    7ffff7fb728a:	4a 8d 14 e5 00 00 00 	lea    rdx,[r12*8+0x0]
    7ffff7fb7291:	00 
    7ffff7fb7292:	48 89 54 24 68       	mov    QWORD PTR [rsp+0x68],rdx
    7ffff7fb7297:	48 8b 9c 24 90 00 00 	mov    rbx,QWORD PTR [rsp+0x90]
    7ffff7fb729e:	00 
    7ffff7fb729f:	48 89 df             	mov    rdi,rbx
    7ffff7fb72a2:	41 ff d6             	call   r14
    7ffff7fb72a5:	48 89 df             	mov    rdi,rbx
    7ffff7fb72a8:	4c 89 fe             	mov    rsi,r15
    7ffff7fb72ab:	48 8b 94 24 98 00 00 	mov    rdx,QWORD PTR [rsp+0x98]
    7ffff7fb72b2:	00 
    7ffff7fb72b3:	4c 89 f9             	mov    rcx,r15
    7ffff7fb72b6:	e8 23 ed ff ff       	call   0x7ffff7fb5fde
    7ffff7fb72bb:	0f b6 c0             	movzx  eax,al
    7ffff7fb72be:	49 89 d9             	mov    r9,rbx
    7ffff7fb72c1:	4a 01 04 fb          	add    QWORD PTR [rbx+r15*8],rax
    7ffff7fb72c5:	4c 8b 74 24 10       	mov    r14,QWORD PTR [rsp+0x10]
    7ffff7fb72ca:	4c 89 f7             	mov    rdi,r14
    7ffff7fb72cd:	48 8b 2c 24          	mov    rbp,QWORD PTR [rsp]
    7ffff7fb72d1:	48 89 ee             	mov    rsi,rbp
    7ffff7fb72d4:	31 d2                	xor    edx,edx
    7ffff7fb72d6:	48 8b 4c 24 28       	mov    rcx,QWORD PTR [rsp+0x28]
    7ffff7fb72db:	48 8b 5c 24 08       	mov    rbx,QWORD PTR [rsp+0x8]
    7ffff7fb72e0:	49 89 d8             	mov    r8,rbx
    7ffff7fb72e3:	48 8d 84 24 08 01 00 	lea    rax,[rsp+0x108]
    7ffff7fb72ea:	00 
    7ffff7fb72eb:	50                   	push   rax
    7ffff7fb72ec:	41 54                	push   r12
    7ffff7fb72ee:	e8 5e 06 00 00       	call   0x7ffff7fb7951
    7ffff7fb72f3:	59                   	pop    rcx
    7ffff7fb72f4:	5a                   	pop    rdx
    7ffff7fb72f5:	4b 8d 04 7f          	lea    rax,[r15+r15*2]
    7ffff7fb72f9:	48 83 c0 02          	add    rax,0x2
    7ffff7fb72fd:	48 89 44 24 48       	mov    QWORD PTR [rsp+0x48],rax
    7ffff7fb7302:	48 89 c6             	mov    rsi,rax
    7ffff7fb7305:	4c 29 fe             	sub    rsi,r15
    7ffff7fb7308:	48 8b 44 24 58       	mov    rax,QWORD PTR [rsp+0x58]
    7ffff7fb730d:	4a 8d 3c f8          	lea    rdi,[rax+r15*8]
    7ffff7fb7311:	48 89 7c 24 78       	mov    QWORD PTR [rsp+0x78],rdi
    7ffff7fb7316:	48 89 74 24 38       	mov    QWORD PTR [rsp+0x38],rsi
    7ffff7fb731b:	8b 54 24 30          	mov    edx,DWORD PTR [rsp+0x30]
    7ffff7fb731f:	4c 89 f1             	mov    rcx,r14
    7ffff7fb7322:	49 89 e8             	mov    r8,rbp
    7ffff7fb7325:	e8 8a 06 00 00       	call   0x7ffff7fb79b4
    7ffff7fb732a:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
    7ffff7fb732f:	4c 8b 74 24 28       	mov    r14,QWORD PTR [rsp+0x28]
    7ffff7fb7334:	4c 89 f7             	mov    rdi,r14
    7ffff7fb7337:	48 8b 74 24 70       	mov    rsi,QWORD PTR [rsp+0x70]
    7ffff7fb733c:	48 8b 94 24 d0 00 00 	mov    rdx,QWORD PTR [rsp+0xd0]
    7ffff7fb7343:	00 
    7ffff7fb7344:	48 8b 2d 1d 18 00 00 	mov    rbp,QWORD PTR [rip+0x181d]        # 0x7ffff7fb8b68
    7ffff7fb734b:	ff d5                	call   rbp
    7ffff7fb734d:	4c 89 f7             	mov    rdi,r14
    7ffff7fb7350:	48 89 de             	mov    rsi,rbx
    7ffff7fb7353:	48 8b 54 24 50       	mov    rdx,QWORD PTR [rsp+0x50]
    7ffff7fb7358:	4c 89 f9             	mov    rcx,r15
    7ffff7fb735b:	e8 6f ed ff ff       	call   0x7ffff7fb60cf
    7ffff7fb7360:	89 c3                	mov    ebx,eax
    7ffff7fb7362:	4c 8b b4 24 90 00 00 	mov    r14,QWORD PTR [rsp+0x90]
    7ffff7fb7369:	00 
    7ffff7fb736a:	4c 89 f7             	mov    rdi,r14
    7ffff7fb736d:	48 8b b4 24 80 00 00 	mov    rsi,QWORD PTR [rsp+0x80]
    7ffff7fb7374:	00 
    7ffff7fb7375:	48 8b 54 24 68       	mov    rdx,QWORD PTR [rsp+0x68]
    7ffff7fb737a:	ff d5                	call   rbp
    7ffff7fb737c:	4c 89 f7             	mov    rdi,r14
    7ffff7fb737f:	4c 89 e6             	mov    rsi,r12
    7ffff7fb7382:	48 8b 94 24 98 00 00 	mov    rdx,QWORD PTR [rsp+0x98]
    7ffff7fb7389:	00 
    7ffff7fb738a:	4c 89 f9             	mov    rcx,r15
    7ffff7fb738d:	e8 3d ed ff ff       	call   0x7ffff7fb60cf
    7ffff7fb7392:	41 89 c4             	mov    r12d,eax
    7ffff7fb7395:	41 30 dc             	xor    r12b,bl
    7ffff7fb7398:	48 8d 9c 24 18 01 00 	lea    rbx,[rsp+0x118]
    7ffff7fb739f:	00 
    7ffff7fb73a0:	48 89 df             	mov    rdi,rbx
    7ffff7fb73a3:	48 8b b4 24 d8 00 00 	mov    rsi,QWORD PTR [rsp+0xd8]
    7ffff7fb73aa:	00 
    7ffff7fb73ab:	48 8b 54 24 60       	mov    rdx,QWORD PTR [rsp+0x60]
    7ffff7fb73b0:	48 8b 8c 24 a8 00 00 	mov    rcx,QWORD PTR [rsp+0xa8]
    7ffff7fb73b7:	00 
    7ffff7fb73b8:	e8 3f 05 00 00       	call   0x7ffff7fb78fc
    7ffff7fb73bd:	48 8b 2b             	mov    rbp,QWORD PTR [rbx]
    7ffff7fb73c0:	4c 8b 73 08          	mov    r14,QWORD PTR [rbx+0x8]
    7ffff7fb73c4:	c5 f8 10 43 10       	vmovups xmm0,XMMWORD PTR [rbx+0x10]
    7ffff7fb73c9:	48 8d 84 24 08 01 00 	lea    rax,[rsp+0x108]
    7ffff7fb73d0:	00 
    7ffff7fb73d1:	c5 f8 11 00          	vmovups XMMWORD PTR [rax],xmm0
    7ffff7fb73d5:	48 89 ef             	mov    rdi,rbp
    7ffff7fb73d8:	4c 89 f6             	mov    rsi,r14
    7ffff7fb73db:	31 d2                	xor    edx,edx
    7ffff7fb73dd:	48 8b 4c 24 28       	mov    rcx,QWORD PTR [rsp+0x28]
    7ffff7fb73e2:	4c 8b 44 24 08       	mov    r8,QWORD PTR [rsp+0x8]
    7ffff7fb73e7:	4c 8b 8c 24 90 00 00 	mov    r9,QWORD PTR [rsp+0x90]
    7ffff7fb73ee:	00 
    7ffff7fb73ef:	50                   	push   rax
    7ffff7fb73f0:	ff b4 24 a8 00 00 00 	push   QWORD PTR [rsp+0xa8]
    7ffff7fb73f7:	e8 55 05 00 00       	call   0x7ffff7fb7951
    7ffff7fb73fc:	59                   	pop    rcx
    7ffff7fb73fd:	5a                   	pop    rdx
    7ffff7fb73fe:	41 0f b6 dc          	movzx  ebx,r12b
    7ffff7fb7402:	48 8b 7c 24 10       	mov    rdi,QWORD PTR [rsp+0x10]
    7ffff7fb7407:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
    7ffff7fb740b:	89 da                	mov    edx,ebx
    7ffff7fb740d:	48 89 e9             	mov    rcx,rbp
    7ffff7fb7410:	4d 89 f0             	mov    r8,r14
    7ffff7fb7413:	e8 74 05 00 00       	call   0x7ffff7fb798c
    7ffff7fb7418:	6a 02                	push   0x2
    7ffff7fb741a:	5a                   	pop    rdx
    7ffff7fb741b:	4c 89 ef             	mov    rdi,r13
    7ffff7fb741e:	84 db                	test   bl,bl
    7ffff7fb7420:	74 15                	je     0x7ffff7fb7437
    7ffff7fb7422:	48 8b 5c 24 18       	mov    rbx,QWORD PTR [rsp+0x18]
    7ffff7fb7427:	48 89 de             	mov    rsi,rbx
    7ffff7fb742a:	48 89 e9             	mov    rcx,rbp
    7ffff7fb742d:	4d 89 f0             	mov    r8,r14
    7ffff7fb7430:	e8 77 07 00 00       	call   0x7ffff7fb7bac
    7ffff7fb7435:	eb 13                	jmp    0x7ffff7fb744a
    7ffff7fb7437:	48 8b 5c 24 18       	mov    rbx,QWORD PTR [rsp+0x18]
    7ffff7fb743c:	48 89 de             	mov    rsi,rbx
    7ffff7fb743f:	48 89 e9             	mov    rcx,rbp
    7ffff7fb7442:	4d 89 f0             	mov    r8,r14
    7ffff7fb7445:	e8 f0 06 00 00       	call   0x7ffff7fb7b3a
    7ffff7fb744a:	4b 8d 04 7f          	lea    rax,[r15+r15*2]
    7ffff7fb744e:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
    7ffff7fb7453:	6a 3d                	push   0x3d
    7ffff7fb7455:	5a                   	pop    rdx
    7ffff7fb7456:	4c 89 ef             	mov    rdi,r13
    7ffff7fb7459:	48 89 de             	mov    rsi,rbx
    7ffff7fb745c:	e8 7c f1 ff ff       	call   0x7ffff7fb65dd
    7ffff7fb7461:	48 89 c1             	mov    rcx,rax
    7ffff7fb7464:	48 8d 2c dd 00 00 00 	lea    rbp,[rbx*8+0x0]
    7ffff7fb746b:	00 
    7ffff7fb746c:	48 bb 00 00 00 00 00 	movabs rbx,0xc000000000000000
    7ffff7fb7473:	00 00 c0 
    7ffff7fb7476:	49 be 55 55 55 55 55 	movabs r14,0x5555555555555555
    7ffff7fb747d:	55 55 55 
    7ffff7fb7480:	48 85 ed             	test   rbp,rbp
    7ffff7fb7483:	74 1e                	je     0x7ffff7fb74a3
    7ffff7fb7485:	49 8b 54 2d f8       	mov    rdx,QWORD PTR [r13+rbp*1-0x8]
    7ffff7fb748a:	48 89 df             	mov    rdi,rbx
    7ffff7fb748d:	4c 89 f6             	mov    rsi,r14
    7ffff7fb7490:	e8 4d f0 ff ff       	call   0x7ffff7fb64e2
    7ffff7fb7495:	48 89 d1             	mov    rcx,rdx
    7ffff7fb7498:	49 89 44 2d f8       	mov    QWORD PTR [r13+rbp*1-0x8],rax
    7ffff7fb749d:	48 83 c5 f8          	add    rbp,0xfffffffffffffff8
    7ffff7fb74a1:	eb dd                	jmp    0x7ffff7fb7480
    7ffff7fb74a3:	6a 01                	push   0x1
    7ffff7fb74a5:	5a                   	pop    rdx
    7ffff7fb74a6:	48 8b 7c 24 10       	mov    rdi,QWORD PTR [rsp+0x10]
    7ffff7fb74ab:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
    7ffff7fb74af:	e8 4f ef ff ff       	call   0x7ffff7fb6403
    7ffff7fb74b4:	48 8b 7c 24 78       	mov    rdi,QWORD PTR [rsp+0x78]
    7ffff7fb74b9:	48 8b 74 24 38       	mov    rsi,QWORD PTR [rsp+0x38]
    7ffff7fb74be:	8b 54 24 24          	mov    edx,DWORD PTR [rsp+0x24]
    7ffff7fb74c2:	4c 89 e9             	mov    rcx,r13
    7ffff7fb74c5:	4c 8b 64 24 18       	mov    r12,QWORD PTR [rsp+0x18]
    7ffff7fb74ca:	4d 89 e0             	mov    r8,r12
    7ffff7fb74cd:	e8 ba 04 00 00       	call   0x7ffff7fb798c
    7ffff7fb74d2:	48 8b 5c 24 40       	mov    rbx,QWORD PTR [rsp+0x40]
    7ffff7fb74d7:	48 01 c3             	add    rbx,rax
    7ffff7fb74da:	4b 8d 04 bf          	lea    rax,[r15+r15*4]
    7ffff7fb74de:	48 89 44 24 08       	mov    QWORD PTR [rsp+0x8],rax
    7ffff7fb74e3:	4f 8d 34 bf          	lea    r14,[r15+r15*4]
    7ffff7fb74e7:	49 83 c6 02          	add    r14,0x2
    7ffff7fb74eb:	4c 89 74 24 50       	mov    QWORD PTR [rsp+0x50],r14
    7ffff7fb74f0:	48 8b 4c 24 28       	mov    rcx,QWORD PTR [rsp+0x28]
    7ffff7fb74f5:	49 29 ce             	sub    r14,rcx
    7ffff7fb74f8:	48 8b 44 24 58       	mov    rax,QWORD PTR [rsp+0x58]
    7ffff7fb74fd:	4c 8d 3c c8          	lea    r15,[rax+rcx*8]
    7ffff7fb7501:	0f b6 6c 24 30       	movzx  ebp,BYTE PTR [rsp+0x30]
    7ffff7fb7506:	4c 89 ff             	mov    rdi,r15
    7ffff7fb7509:	4c 89 f6             	mov    rsi,r14
    7ffff7fb750c:	89 ea                	mov    edx,ebp
    7ffff7fb750e:	4c 89 e9             	mov    rcx,r13
    7ffff7fb7511:	4d 89 e0             	mov    r8,r12
    7ffff7fb7514:	e8 73 04 00 00       	call   0x7ffff7fb798c
    7ffff7fb7519:	48 89 44 24 30       	mov    QWORD PTR [rsp+0x30],rax
    7ffff7fb751e:	4c 8b a4 24 b8 00 00 	mov    r12,QWORD PTR [rsp+0xb8]
    7ffff7fb7525:	00 
    7ffff7fb7526:	4c 89 e7             	mov    rdi,r12
    7ffff7fb7529:	48 8b b4 24 b0 00 00 	mov    rsi,QWORD PTR [rsp+0xb0]
    7ffff7fb7530:	00 
    7ffff7fb7531:	89 ea                	mov    edx,ebp
    7ffff7fb7533:	4c 8b 6c 24 10       	mov    r13,QWORD PTR [rsp+0x10]
    7ffff7fb7538:	4c 89 e9             	mov    rcx,r13
    7ffff7fb753b:	48 8b 2c 24          	mov    rbp,QWORD PTR [rsp]
    7ffff7fb753f:	49 89 e8             	mov    r8,rbp
    7ffff7fb7542:	e8 45 04 00 00       	call   0x7ffff7fb798c
    7ffff7fb7547:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
    7ffff7fb754c:	4c 89 ff             	mov    rdi,r15
    7ffff7fb754f:	4c 89 f6             	mov    rsi,r14
    7ffff7fb7552:	8b 54 24 24          	mov    edx,DWORD PTR [rsp+0x24]
    7ffff7fb7556:	4c 89 e9             	mov    rcx,r13
    7ffff7fb7559:	49 89 e8             	mov    r8,rbp
    7ffff7fb755c:	e8 2b 04 00 00       	call   0x7ffff7fb798c
    7ffff7fb7561:	49 89 c6             	mov    r14,rax
    7ffff7fb7564:	4c 8b 6c 24 48       	mov    r13,QWORD PTR [rsp+0x48]
    7ffff7fb7569:	4c 89 ee             	mov    rsi,r13
    7ffff7fb756c:	48 2b b4 24 00 01 00 	sub    rsi,QWORD PTR [rsp+0x100]
    7ffff7fb7573:	00 
    7ffff7fb7574:	4c 89 e7             	mov    rdi,r12
    7ffff7fb7577:	48 8b 94 24 f0 00 00 	mov    rdx,QWORD PTR [rsp+0xf0]
    7ffff7fb757e:	00 
    7ffff7fb757f:	e8 dd f6 ff ff       	call   0x7ffff7fb6c61
    7ffff7fb7584:	48 01 c3             	add    rbx,rax
    7ffff7fb7587:	4c 8b a4 24 f8 00 00 	mov    r12,QWORD PTR [rsp+0xf8]
    7ffff7fb758e:	00 
    7ffff7fb758f:	4c 89 e6             	mov    rsi,r12
    7ffff7fb7592:	4c 29 ee             	sub    rsi,r13
    7ffff7fb7595:	4c 8b 7c 24 58       	mov    r15,QWORD PTR [rsp+0x58]
    7ffff7fb759a:	4b 8d 3c ef          	lea    rdi,[r15+r13*8]
    7ffff7fb759e:	48 89 da             	mov    rdx,rbx
    7ffff7fb75a1:	e8 bb f6 ff ff       	call   0x7ffff7fb6c61
    7ffff7fb75a6:	48 8b 94 24 e0 00 00 	mov    rdx,QWORD PTR [rsp+0xe0]
    7ffff7fb75ad:	00 
    7ffff7fb75ae:	48 03 94 24 e8 00 00 	add    rdx,QWORD PTR [rsp+0xe8]
    7ffff7fb75b5:	00 
    7ffff7fb75b6:	48 03 54 24 18       	add    rdx,QWORD PTR [rsp+0x18]
    7ffff7fb75bb:	48 01 c2             	add    rdx,rax
    7ffff7fb75be:	48 8b 5c 24 50       	mov    rbx,QWORD PTR [rsp+0x50]
    7ffff7fb75c3:	48 89 de             	mov    rsi,rbx
    7ffff7fb75c6:	4c 29 e6             	sub    rsi,r12
    7ffff7fb75c9:	4b 8d 3c e7          	lea    rdi,[r15+r12*8]
    7ffff7fb75cd:	e8 8f f6 ff ff       	call   0x7ffff7fb6c61
    7ffff7fb75d2:	4c 03 74 24 30       	add    r14,QWORD PTR [rsp+0x30]
    7ffff7fb75d7:	49 01 c6             	add    r14,rax
    7ffff7fb75da:	48 8b b4 24 c0 00 00 	mov    rsi,QWORD PTR [rsp+0xc0]
    7ffff7fb75e1:	00 
    7ffff7fb75e2:	48 29 de             	sub    rsi,rbx
    7ffff7fb75e5:	48 8b 44 24 08       	mov    rax,QWORD PTR [rsp+0x8]
    7ffff7fb75ea:	49 8d 3c c7          	lea    rdi,[r15+rax*8]
    7ffff7fb75ee:	48 83 c7 10          	add    rdi,0x10
    7ffff7fb75f2:	4c 89 f2             	mov    rdx,r14
    7ffff7fb75f5:	e8 67 f6 ff ff       	call   0x7ffff7fb6c61
    7ffff7fb75fa:	48 03 84 24 88 00 00 	add    rax,QWORD PTR [rsp+0x88]
    7ffff7fb7601:	00 
    7ffff7fb7602:	48 81 c4 58 01 00 00 	add    rsp,0x158
    7ffff7fb7609:	5b                   	pop    rbx
    7ffff7fb760a:	41 5c                	pop    r12
    7ffff7fb760c:	41 5d                	pop    r13
    7ffff7fb760e:	41 5e                	pop    r14
    7ffff7fb7610:	41 5f                	pop    r15
    7ffff7fb7612:	5d                   	pop    rbp
    7ffff7fb7613:	c3                   	ret
    7ffff7fb7614:	55                   	push   rbp
    7ffff7fb7615:	41 57                	push   r15
    7ffff7fb7617:	41 56                	push   r14
    7ffff7fb7619:	41 55                	push   r13
    7ffff7fb761b:	41 54                	push   r12
    7ffff7fb761d:	53                   	push   rbx
    7ffff7fb761e:	48 81 ec b8 00 00 00 	sub    rsp,0xb8
    7ffff7fb7625:	4d 89 ce             	mov    r14,r9
    7ffff7fb7628:	48 89 4c 24 18       	mov    QWORD PTR [rsp+0x18],rcx
    7ffff7fb762d:	89 54 24 04          	mov    DWORD PTR [rsp+0x4],edx
    7ffff7fb7631:	48 89 74 24 50       	mov    QWORD PTR [rsp+0x50],rsi
    7ffff7fb7636:	48 89 7c 24 20       	mov    QWORD PTR [rsp+0x20],rdi
    7ffff7fb763b:	48 8b 84 24 f8 00 00 	mov    rax,QWORD PTR [rsp+0xf8]
    7ffff7fb7642:	00 
    7ffff7fb7643:	48 8b b4 24 f0 00 00 	mov    rsi,QWORD PTR [rsp+0xf0]
    7ffff7fb764a:	00 
    7ffff7fb764b:	49 8d 58 01          	lea    rbx,[r8+0x1]
    7ffff7fb764f:	49 89 df             	mov    r15,rbx
    7ffff7fb7652:	49 d1 ef             	shr    r15,1
    7ffff7fb7655:	4a 8d 14 f9          	lea    rdx,[rcx+r15*8]
    7ffff7fb7659:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
    7ffff7fb765e:	4d 29 f8             	sub    r8,r15
    7ffff7fb7661:	4c 89 44 24 28       	mov    QWORD PTR [rsp+0x28],r8
    7ffff7fb7666:	4b 8d 14 f9          	lea    rdx,[r9+r15*8]
    7ffff7fb766a:	48 89 54 24 48       	mov    QWORD PTR [rsp+0x48],rdx
    7ffff7fb766f:	4c 89 4c 24 68       	mov    QWORD PTR [rsp+0x68],r9
    7ffff7fb7674:	4c 29 fe             	sub    rsi,r15
    7ffff7fb7677:	48 89 74 24 40       	mov    QWORD PTR [rsp+0x40],rsi
    7ffff7fb767c:	48 83 e3 fe          	and    rbx,0xfffffffffffffffe
    7ffff7fb7680:	48 8b 30             	mov    rsi,QWORD PTR [rax]
    7ffff7fb7683:	48 89 74 24 10       	mov    QWORD PTR [rsp+0x10],rsi
    7ffff7fb7688:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
    7ffff7fb768c:	48 89 54 24 08       	mov    QWORD PTR [rsp+0x8],rdx
    7ffff7fb7691:	4c 8d ac 24 98 00 00 	lea    r13,[rsp+0x98]
    7ffff7fb7698:	00 
    7ffff7fb7699:	4c 89 ef             	mov    rdi,r13
    7ffff7fb769c:	48 89 d9             	mov    rcx,rbx
    7ffff7fb769f:	e8 58 02 00 00       	call   0x7ffff7fb78fc
    7ffff7fb76a4:	4d 8b 65 00          	mov    r12,QWORD PTR [r13+0x0]
    7ffff7fb76a8:	49 8b 6d 08          	mov    rbp,QWORD PTR [r13+0x8]
    7ffff7fb76ac:	c4 c1 78 10 45 10    	vmovups xmm0,XMMWORD PTR [r13+0x10]
    7ffff7fb76b2:	48 8d 84 24 88 00 00 	lea    rax,[rsp+0x88]
    7ffff7fb76b9:	00 
    7ffff7fb76ba:	c5 f8 11 00          	vmovups XMMWORD PTR [rax],xmm0
    7ffff7fb76be:	4c 89 e7             	mov    rdi,r12
    7ffff7fb76c1:	48 89 ee             	mov    rsi,rbp
    7ffff7fb76c4:	31 d2                	xor    edx,edx
    7ffff7fb76c6:	48 8b 4c 24 18       	mov    rcx,QWORD PTR [rsp+0x18]
    7ffff7fb76cb:	4d 89 f8             	mov    r8,r15
    7ffff7fb76ce:	4d 89 f1             	mov    r9,r14
    7ffff7fb76d1:	50                   	push   rax
    7ffff7fb76d2:	41 57                	push   r15
    7ffff7fb76d4:	e8 78 02 00 00       	call   0x7ffff7fb7951
    7ffff7fb76d9:	59                   	pop    rcx
    7ffff7fb76da:	5a                   	pop    rdx
    7ffff7fb76db:	4c 8b 74 24 20       	mov    r14,QWORD PTR [rsp+0x20]
    7ffff7fb76e0:	4c 89 f7             	mov    rdi,r14
    7ffff7fb76e3:	48 89 de             	mov    rsi,rbx
    7ffff7fb76e6:	44 8b 6c 24 04       	mov    r13d,DWORD PTR [rsp+0x4]
    7ffff7fb76eb:	44 89 ea             	mov    edx,r13d
    7ffff7fb76ee:	4c 89 e1             	mov    rcx,r12
    7ffff7fb76f1:	49 89 e8             	mov    r8,rbp
    7ffff7fb76f4:	e8 93 02 00 00       	call   0x7ffff7fb798c
    7ffff7fb76f9:	48 89 84 24 80 00 00 	mov    QWORD PTR [rsp+0x80],rax
    7ffff7fb7700:	00 
    7ffff7fb7701:	4b 8d 04 7f          	lea    rax,[r15+r15*2]
    7ffff7fb7705:	48 89 44 24 70       	mov    QWORD PTR [rsp+0x70],rax
    7ffff7fb770a:	4b 8d 3c fe          	lea    rdi,[r14+r15*8]
    7ffff7fb770e:	48 89 7c 24 30       	mov    QWORD PTR [rsp+0x30],rdi
    7ffff7fb7713:	48 89 de             	mov    rsi,rbx
    7ffff7fb7716:	44 89 ea             	mov    edx,r13d
    7ffff7fb7719:	4c 89 e1             	mov    rcx,r12
    7ffff7fb771c:	49 89 e8             	mov    r8,rbp
    7ffff7fb771f:	e8 68 02 00 00       	call   0x7ffff7fb798c
    7ffff7fb7724:	48 89 44 24 78       	mov    QWORD PTR [rsp+0x78],rax
    7ffff7fb7729:	4c 8b 74 24 28       	mov    r14,QWORD PTR [rsp+0x28]
    7ffff7fb772e:	4b 8d 0c 36          	lea    rcx,[r14+r14*1]
    7ffff7fb7732:	4c 8d ac 24 98 00 00 	lea    r13,[rsp+0x98]
    7ffff7fb7739:	00 
    7ffff7fb773a:	4c 89 ef             	mov    rdi,r13
    7ffff7fb773d:	48 8b 74 24 10       	mov    rsi,QWORD PTR [rsp+0x10]
    7ffff7fb7742:	48 8b 54 24 08       	mov    rdx,QWORD PTR [rsp+0x8]
    7ffff7fb7747:	e8 b0 01 00 00       	call   0x7ffff7fb78fc
    7ffff7fb774c:	4d 8b 65 00          	mov    r12,QWORD PTR [r13+0x0]
    7ffff7fb7750:	49 8b 6d 08          	mov    rbp,QWORD PTR [r13+0x8]
    7ffff7fb7754:	c4 c1 78 10 45 10    	vmovups xmm0,XMMWORD PTR [r13+0x10]
    7ffff7fb775a:	48 8d 84 24 88 00 00 	lea    rax,[rsp+0x88]
    7ffff7fb7761:	00 
    7ffff7fb7762:	c5 f8 11 00          	vmovups XMMWORD PTR [rax],xmm0
    7ffff7fb7766:	4c 89 e7             	mov    rdi,r12
    7ffff7fb7769:	48 89 ee             	mov    rsi,rbp
    7ffff7fb776c:	31 d2                	xor    edx,edx
    7ffff7fb776e:	48 8b 4c 24 38       	mov    rcx,QWORD PTR [rsp+0x38]
    7ffff7fb7773:	4d 89 f0             	mov    r8,r14
    7ffff7fb7776:	4c 8b 4c 24 48       	mov    r9,QWORD PTR [rsp+0x48]
    7ffff7fb777b:	50                   	push   rax
    7ffff7fb777c:	ff 74 24 48          	push   QWORD PTR [rsp+0x48]
    7ffff7fb7780:	e8 cc 01 00 00       	call   0x7ffff7fb7951
    7ffff7fb7785:	59                   	pop    rcx
    7ffff7fb7786:	5a                   	pop    rdx
    7ffff7fb7787:	48 8b 74 24 50       	mov    rsi,QWORD PTR [rsp+0x50]
    7ffff7fb778c:	48 29 de             	sub    rsi,rbx
    7ffff7fb778f:	48 8b 44 24 20       	mov    rax,QWORD PTR [rsp+0x20]
    7ffff7fb7794:	48 8d 3c d8          	lea    rdi,[rax+rbx*8]
    7ffff7fb7798:	48 89 7c 24 58       	mov    QWORD PTR [rsp+0x58],rdi
    7ffff7fb779d:	44 8b 74 24 04       	mov    r14d,DWORD PTR [rsp+0x4]
    7ffff7fb77a2:	44 89 f2             	mov    edx,r14d
    7ffff7fb77a5:	4c 89 e1             	mov    rcx,r12
    7ffff7fb77a8:	49 89 e8             	mov    r8,rbp
    7ffff7fb77ab:	e8 dc 01 00 00       	call   0x7ffff7fb798c
    7ffff7fb77b0:	48 89 44 24 60       	mov    QWORD PTR [rsp+0x60],rax
    7ffff7fb77b5:	48 8b 7c 24 30       	mov    rdi,QWORD PTR [rsp+0x30]
    7ffff7fb77ba:	48 89 de             	mov    rsi,rbx
    7ffff7fb77bd:	44 89 f2             	mov    edx,r14d
    7ffff7fb77c0:	4c 89 e1             	mov    rcx,r12
    7ffff7fb77c3:	49 89 e8             	mov    r8,rbp
    7ffff7fb77c6:	e8 e9 01 00 00       	call   0x7ffff7fb79b4
    7ffff7fb77cb:	49 89 c4             	mov    r12,rax
    7ffff7fb77ce:	4c 8d ac 24 98 00 00 	lea    r13,[rsp+0x98]
    7ffff7fb77d5:	00 
    7ffff7fb77d6:	4c 89 ef             	mov    rdi,r13
    7ffff7fb77d9:	48 8b 74 24 10       	mov    rsi,QWORD PTR [rsp+0x10]
    7ffff7fb77de:	48 8b 54 24 08       	mov    rdx,QWORD PTR [rsp+0x8]
    7ffff7fb77e3:	48 8b 4c 24 18       	mov    rcx,QWORD PTR [rsp+0x18]
    7ffff7fb77e8:	4d 89 f8             	mov    r8,r15
    7ffff7fb77eb:	e8 ec 01 00 00       	call   0x7ffff7fb79dc
    7ffff7fb77f0:	49 8b 7d 00          	mov    rdi,QWORD PTR [r13+0x0]
    7ffff7fb77f4:	48 89 7c 24 18       	mov    QWORD PTR [rsp+0x18],rdi
    7ffff7fb77f9:	49 8b 75 08          	mov    rsi,QWORD PTR [r13+0x8]
    7ffff7fb77fd:	48 89 74 24 10       	mov    QWORD PTR [rsp+0x10],rsi
    7ffff7fb7802:	49 8b 6d 10          	mov    rbp,QWORD PTR [r13+0x10]
    7ffff7fb7806:	49 8b 45 18          	mov    rax,QWORD PTR [r13+0x18]
    7ffff7fb780a:	48 89 44 24 08       	mov    QWORD PTR [rsp+0x8],rax
    7ffff7fb780f:	48 8b 54 24 38       	mov    rdx,QWORD PTR [rsp+0x38]
    7ffff7fb7814:	48 8b 4c 24 28       	mov    rcx,QWORD PTR [rsp+0x28]
    7ffff7fb7819:	e8 b1 e8 ff ff       	call   0x7ffff7fb60cf
    7ffff7fb781e:	41 89 c6             	mov    r14d,eax
    7ffff7fb7821:	4c 8d ac 24 98 00 00 	lea    r13,[rsp+0x98]
    7ffff7fb7828:	00 
    7ffff7fb7829:	4c 89 ef             	mov    rdi,r13
    7ffff7fb782c:	48 89 ee             	mov    rsi,rbp
    7ffff7fb782f:	48 8b 54 24 08       	mov    rdx,QWORD PTR [rsp+0x8]
    7ffff7fb7834:	48 8b 4c 24 68       	mov    rcx,QWORD PTR [rsp+0x68]
    7ffff7fb7839:	4d 89 f8             	mov    r8,r15
    7ffff7fb783c:	e8 9b 01 00 00       	call   0x7ffff7fb79dc
    7ffff7fb7841:	4d 8b 7d 00          	mov    r15,QWORD PTR [r13+0x0]
    7ffff7fb7845:	49 8b 6d 08          	mov    rbp,QWORD PTR [r13+0x8]
    7ffff7fb7849:	c4 c1 78 10 45 10    	vmovups xmm0,XMMWORD PTR [r13+0x10]
    7ffff7fb784f:	4c 8d ac 24 88 00 00 	lea    r13,[rsp+0x88]
    7ffff7fb7856:	00 
    7ffff7fb7857:	c4 c1 78 11 45 00    	vmovups XMMWORD PTR [r13+0x0],xmm0
    7ffff7fb785d:	4c 89 ff             	mov    rdi,r15
    7ffff7fb7860:	48 89 ee             	mov    rsi,rbp
    7ffff7fb7863:	48 8b 54 24 48       	mov    rdx,QWORD PTR [rsp+0x48]
    7ffff7fb7868:	48 8b 4c 24 40       	mov    rcx,QWORD PTR [rsp+0x40]
    7ffff7fb786d:	e8 5d e8 ff ff       	call   0x7ffff7fb60cf
    7ffff7fb7872:	44 32 74 24 04       	xor    r14b,BYTE PTR [rsp+0x4]
    7ffff7fb7877:	41 30 c6             	xor    r14b,al
    7ffff7fb787a:	41 80 f6 01          	xor    r14b,0x1
    7ffff7fb787e:	41 0f b6 d6          	movzx  edx,r14b
    7ffff7fb7882:	48 8b 7c 24 30       	mov    rdi,QWORD PTR [rsp+0x30]
    7ffff7fb7887:	48 89 de             	mov    rsi,rbx
    7ffff7fb788a:	48 8b 4c 24 18       	mov    rcx,QWORD PTR [rsp+0x18]
    7ffff7fb788f:	4c 8b 44 24 10       	mov    r8,QWORD PTR [rsp+0x10]
    7ffff7fb7894:	4d 89 f9             	mov    r9,r15
    7ffff7fb7897:	41 55                	push   r13
    7ffff7fb7899:	55                   	push   rbp
    7ffff7fb789a:	e8 b2 00 00 00       	call   0x7ffff7fb7951
    7ffff7fb789f:	59                   	pop    rcx
    7ffff7fb78a0:	5a                   	pop    rdx
    7ffff7fb78a1:	49 89 c6             	mov    r14,rax
    7ffff7fb78a4:	4c 8b 7c 24 70       	mov    r15,QWORD PTR [rsp+0x70]
    7ffff7fb78a9:	4c 89 fe             	mov    rsi,r15
    7ffff7fb78ac:	48 29 de             	sub    rsi,rbx
    7ffff7fb78af:	48 8b 7c 24 58       	mov    rdi,QWORD PTR [rsp+0x58]
    7ffff7fb78b4:	48 8b 94 24 80 00 00 	mov    rdx,QWORD PTR [rsp+0x80]
    7ffff7fb78bb:	00 
    7ffff7fb78bc:	e8 a0 f3 ff ff       	call   0x7ffff7fb6c61
    7ffff7fb78c1:	4c 03 64 24 78       	add    r12,QWORD PTR [rsp+0x78]
    7ffff7fb78c6:	49 01 c4             	add    r12,rax
    7ffff7fb78c9:	4d 01 f4             	add    r12,r14
    7ffff7fb78cc:	48 8b 74 24 50       	mov    rsi,QWORD PTR [rsp+0x50]
    7ffff7fb78d1:	4c 29 fe             	sub    rsi,r15
    7ffff7fb78d4:	48 8b 4c 24 20       	mov    rcx,QWORD PTR [rsp+0x20]
    7ffff7fb78d9:	4a 8d 3c f9          	lea    rdi,[rcx+r15*8]
    7ffff7fb78dd:	4c 89 e2             	mov    rdx,r12
    7ffff7fb78e0:	e8 7c f3 ff ff       	call   0x7ffff7fb6c61
    7ffff7fb78e5:	48 03 44 24 60       	add    rax,QWORD PTR [rsp+0x60]
    7ffff7fb78ea:	48 81 c4 b8 00 00 00 	add    rsp,0xb8
    7ffff7fb78f1:	5b                   	pop    rbx
    7ffff7fb78f2:	41 5c                	pop    r12
    7ffff7fb78f4:	41 5d                	pop    r13
    7ffff7fb78f6:	41 5e                	pop    r14
    7ffff7fb78f8:	41 5f                	pop    r15
    7ffff7fb78fa:	5d                   	pop    rbp
    7ffff7fb78fb:	c3                   	ret
    7ffff7fb78fc:	41 57                	push   r15
    7ffff7fb78fe:	41 56                	push   r14
    7ffff7fb7900:	41 54                	push   r12
    7ffff7fb7902:	53                   	push   rbx
    7ffff7fb7903:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb7907:	49 89 ce             	mov    r14,rcx
    7ffff7fb790a:	48 89 d3             	mov    rbx,rdx
    7ffff7fb790d:	49 89 ff             	mov    r15,rdi
    7ffff7fb7910:	49 89 e4             	mov    r12,rsp
    7ffff7fb7913:	4c 89 e7             	mov    rdi,r12
    7ffff7fb7916:	e8 2c 01 00 00       	call   0x7ffff7fb7a47
    7ffff7fb791b:	49 8b 4c 24 08       	mov    rcx,QWORD PTR [r12+0x8]
    7ffff7fb7920:	49 8b 44 24 10       	mov    rax,QWORD PTR [r12+0x10]
    7ffff7fb7925:	31 d2                	xor    edx,edx
    7ffff7fb7927:	49 39 d6             	cmp    r14,rdx
    7ffff7fb792a:	74 0a                	je     0x7ffff7fb7936
    7ffff7fb792c:	48 83 24 d1 00       	and    QWORD PTR [rcx+rdx*8],0x0
    7ffff7fb7931:	48 ff c2             	inc    rdx
    7ffff7fb7934:	eb f1                	jmp    0x7ffff7fb7927
    7ffff7fb7936:	49 89 0f             	mov    QWORD PTR [r15],rcx
    7ffff7fb7939:	4d 89 77 08          	mov    QWORD PTR [r15+0x8],r14
    7ffff7fb793d:	49 89 47 10          	mov    QWORD PTR [r15+0x10],rax
    7ffff7fb7941:	49 89 5f 18          	mov    QWORD PTR [r15+0x18],rbx
    7ffff7fb7945:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb7949:	5b                   	pop    rbx
    7ffff7fb794a:	41 5c                	pop    r12
    7ffff7fb794c:	41 5e                	pop    r14
    7ffff7fb794e:	41 5f                	pop    r15
    7ffff7fb7950:	c3                   	ret
    7ffff7fb7951:	50                   	push   rax
    7ffff7fb7952:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb7957:	49 83 f8 19          	cmp    r8,0x19
    7ffff7fb795b:	73 0f                	jae    0x7ffff7fb796c
    7ffff7fb795d:	48 83 ec 08          	sub    rsp,0x8
    7ffff7fb7961:	0f b6 d2             	movzx  edx,dl
    7ffff7fb7964:	50                   	push   rax
    7ffff7fb7965:	e8 3b f3 ff ff       	call   0x7ffff7fb6ca5
    7ffff7fb796a:	eb 16                	jmp    0x7ffff7fb7982
    7ffff7fb796c:	0f b6 d2             	movzx  edx,dl
    7ffff7fb796f:	49 81 f8 c1 00 00 00 	cmp    r8,0xc1
    7ffff7fb7976:	73 0e                	jae    0x7ffff7fb7986
    7ffff7fb7978:	ff 74 24 18          	push   QWORD PTR [rsp+0x18]
    7ffff7fb797c:	50                   	push   rax
    7ffff7fb797d:	e8 92 fc ff ff       	call   0x7ffff7fb7614
    7ffff7fb7982:	59                   	pop    rcx
    7ffff7fb7983:	5a                   	pop    rdx
    7ffff7fb7984:	59                   	pop    rcx
    7ffff7fb7985:	c3                   	ret
    7ffff7fb7986:	58                   	pop    rax
    7ffff7fb7987:	e9 e0 f3 ff ff       	jmp    0x7ffff7fb6d6c
    7ffff7fb798c:	50                   	push   rax
    7ffff7fb798d:	85 d2                	test   edx,edx
    7ffff7fb798f:	74 13                	je     0x7ffff7fb79a4
    7ffff7fb7991:	48 89 ca             	mov    rdx,rcx
    7ffff7fb7994:	4c 89 c1             	mov    rcx,r8
    7ffff7fb7997:	e8 d9 e6 ff ff       	call   0x7ffff7fb6075
    7ffff7fb799c:	0f b6 c0             	movzx  eax,al
    7ffff7fb799f:	48 f7 d8             	neg    rax
    7ffff7fb79a2:	eb 0e                	jmp    0x7ffff7fb79b2
    7ffff7fb79a4:	48 89 ca             	mov    rdx,rcx
    7ffff7fb79a7:	4c 89 c1             	mov    rcx,r8
    7ffff7fb79aa:	e8 2f e6 ff ff       	call   0x7ffff7fb5fde
    7ffff7fb79af:	0f b6 c0             	movzx  eax,al
    7ffff7fb79b2:	59                   	pop    rcx
    7ffff7fb79b3:	c3                   	ret
    7ffff7fb79b4:	50                   	push   rax
    7ffff7fb79b5:	85 d2                	test   edx,edx
    7ffff7fb79b7:	74 13                	je     0x7ffff7fb79cc
    7ffff7fb79b9:	48 89 ca             	mov    rdx,rcx
    7ffff7fb79bc:	4c 89 c1             	mov    rcx,r8
    7ffff7fb79bf:	e8 7b e6 ff ff       	call   0x7ffff7fb603f
    7ffff7fb79c4:	0f b6 c0             	movzx  eax,al
    7ffff7fb79c7:	48 f7 d8             	neg    rax
    7ffff7fb79ca:	eb 0e                	jmp    0x7ffff7fb79da
    7ffff7fb79cc:	48 89 ca             	mov    rdx,rcx
    7ffff7fb79cf:	4c 89 c1             	mov    rcx,r8
    7ffff7fb79d2:	e8 32 e6 ff ff       	call   0x7ffff7fb6009
    7ffff7fb79d7:	0f b6 c0             	movzx  eax,al
    7ffff7fb79da:	59                   	pop    rcx
    7ffff7fb79db:	c3                   	ret
    7ffff7fb79dc:	41 57                	push   r15
    7ffff7fb79de:	41 56                	push   r14
    7ffff7fb79e0:	41 55                	push   r13
    7ffff7fb79e2:	41 54                	push   r12
    7ffff7fb79e4:	53                   	push   rbx
    7ffff7fb79e5:	48 83 ec 20          	sub    rsp,0x20
    7ffff7fb79e9:	4d 89 c6             	mov    r14,r8
    7ffff7fb79ec:	49 89 cc             	mov    r12,rcx
    7ffff7fb79ef:	48 89 d3             	mov    rbx,rdx
    7ffff7fb79f2:	49 89 ff             	mov    r15,rdi
    7ffff7fb79f5:	4c 8d 6c 24 08       	lea    r13,[rsp+0x8]
    7ffff7fb79fa:	4c 89 ef             	mov    rdi,r13
    7ffff7fb79fd:	4c 89 c1             	mov    rcx,r8
    7ffff7fb7a00:	e8 42 00 00 00       	call   0x7ffff7fb7a47
    7ffff7fb7a05:	49 8b 4d 08          	mov    rcx,QWORD PTR [r13+0x8]
    7ffff7fb7a09:	49 8b 45 10          	mov    rax,QWORD PTR [r13+0x10]
    7ffff7fb7a0d:	4a 8d 14 f5 00 00 00 	lea    rdx,[r14*8+0x0]
    7ffff7fb7a14:	00 
    7ffff7fb7a15:	31 f6                	xor    esi,esi
    7ffff7fb7a17:	48 39 f2             	cmp    rdx,rsi
    7ffff7fb7a1a:	74 0e                	je     0x7ffff7fb7a2a
    7ffff7fb7a1c:	49 8b 3c 34          	mov    rdi,QWORD PTR [r12+rsi*1]
    7ffff7fb7a20:	48 89 3c 31          	mov    QWORD PTR [rcx+rsi*1],rdi
    7ffff7fb7a24:	48 83 c6 08          	add    rsi,0x8
    7ffff7fb7a28:	eb ed                	jmp    0x7ffff7fb7a17
    7ffff7fb7a2a:	49 89 0f             	mov    QWORD PTR [r15],rcx
    7ffff7fb7a2d:	4d 89 77 08          	mov    QWORD PTR [r15+0x8],r14
    7ffff7fb7a31:	49 89 47 10          	mov    QWORD PTR [r15+0x10],rax
    7ffff7fb7a35:	49 89 5f 18          	mov    QWORD PTR [r15+0x18],rbx
    7ffff7fb7a39:	48 83 c4 20          	add    rsp,0x20
    7ffff7fb7a3d:	5b                   	pop    rbx
    7ffff7fb7a3e:	41 5c                	pop    r12
    7ffff7fb7a40:	41 5d                	pop    r13
    7ffff7fb7a42:	41 5e                	pop    r14
    7ffff7fb7a44:	41 5f                	pop    r15
    7ffff7fb7a46:	c3                   	ret
    7ffff7fb7a47:	89 f0                	mov    eax,esi
    7ffff7fb7a49:	f7 d8                	neg    eax
    7ffff7fb7a4b:	83 e0 07             	and    eax,0x7
    7ffff7fb7a4e:	48 01 f0             	add    rax,rsi
    7ffff7fb7a51:	40 0f 92 c6          	setb   sil
    7ffff7fb7a55:	49 89 c8             	mov    r8,rcx
    7ffff7fb7a58:	49 c1 e8 3d          	shr    r8,0x3d
    7ffff7fb7a5c:	41 0f 95 c0          	setne  r8b
    7ffff7fb7a60:	41 08 f0             	or     r8b,sil
    7ffff7fb7a63:	75 16                	jne    0x7ffff7fb7a7b
    7ffff7fb7a65:	48 c1 e1 03          	shl    rcx,0x3
    7ffff7fb7a69:	48 01 c1             	add    rcx,rax
    7ffff7fb7a6c:	40 0f 92 c6          	setb   sil
    7ffff7fb7a70:	48 39 d1             	cmp    rcx,rdx
    7ffff7fb7a73:	0f 97 c2             	seta   dl
    7ffff7fb7a76:	40 08 f2             	or     dl,sil
    7ffff7fb7a79:	74 04                	je     0x7ffff7fb7a7f
    7ffff7fb7a7b:	31 c0                	xor    eax,eax
    7ffff7fb7a7d:	eb 0b                	jmp    0x7ffff7fb7a8a
    7ffff7fb7a7f:	48 89 47 08          	mov    QWORD PTR [rdi+0x8],rax
    7ffff7fb7a83:	48 89 4f 10          	mov    QWORD PTR [rdi+0x10],rcx
    7ffff7fb7a87:	6a 01                	push   0x1
    7ffff7fb7a89:	58                   	pop    rax
    7ffff7fb7a8a:	48 89 07             	mov    QWORD PTR [rdi],rax
    7ffff7fb7a8d:	c3                   	ret
    7ffff7fb7a8e:	48 85 d2             	test   rdx,rdx
    7ffff7fb7a91:	74 27                	je     0x7ffff7fb7aba
    7ffff7fb7a93:	48 c1 e6 03          	shl    rsi,0x3
    7ffff7fb7a97:	31 c9                	xor    ecx,ecx
    7ffff7fb7a99:	31 c0                	xor    eax,eax
    7ffff7fb7a9b:	48 39 ce             	cmp    rsi,rcx
    7ffff7fb7a9e:	74 1c                	je     0x7ffff7fb7abc
    7ffff7fb7aa0:	c4 62 b3 f6 04 0f    	mulx   r8,r9,QWORD PTR [rdi+rcx*1]
    7ffff7fb7aa6:	49 01 c1             	add    r9,rax
    7ffff7fb7aa9:	49 83 d0 00          	adc    r8,0x0
    7ffff7fb7aad:	4c 89 0c 0f          	mov    QWORD PTR [rdi+rcx*1],r9
    7ffff7fb7ab1:	48 83 c1 08          	add    rcx,0x8
    7ffff7fb7ab5:	4c 89 c0             	mov    rax,r8
    7ffff7fb7ab8:	eb e1                	jmp    0x7ffff7fb7a9b
    7ffff7fb7aba:	31 c0                	xor    eax,eax
    7ffff7fb7abc:	c3                   	ret
    7ffff7fb7abd:	55                   	push   rbp
    7ffff7fb7abe:	41 57                	push   r15
    7ffff7fb7ac0:	41 56                	push   r14
    7ffff7fb7ac2:	41 55                	push   r13
    7ffff7fb7ac4:	41 54                	push   r12
    7ffff7fb7ac6:	53                   	push   rbx
    7ffff7fb7ac7:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb7acb:	4d 89 cf             	mov    r15,r9
    7ffff7fb7ace:	4d 89 c5             	mov    r13,r8
    7ffff7fb7ad1:	49 89 ce             	mov    r14,rcx
    7ffff7fb7ad4:	48 89 d3             	mov    rbx,rdx
    7ffff7fb7ad7:	49 89 fc             	mov    r12,rdi
    7ffff7fb7ada:	48 89 e5             	mov    rbp,rsp
    7ffff7fb7add:	48 89 ef             	mov    rdi,rbp
    7ffff7fb7ae0:	e8 62 ff ff ff       	call   0x7ffff7fb7a47
    7ffff7fb7ae5:	48 8b 4d 08          	mov    rcx,QWORD PTR [rbp+0x8]
    7ffff7fb7ae9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
    7ffff7fb7aed:	4a 8d 14 fd 00 00 00 	lea    rdx,[r15*8+0x0]
    7ffff7fb7af4:	00 
    7ffff7fb7af5:	31 f6                	xor    esi,esi
    7ffff7fb7af7:	48 39 f2             	cmp    rdx,rsi
    7ffff7fb7afa:	74 17                	je     0x7ffff7fb7b13
    7ffff7fb7afc:	49 8b 7c 35 00       	mov    rdi,QWORD PTR [r13+rsi*1+0x0]
    7ffff7fb7b01:	48 89 3c 31          	mov    QWORD PTR [rcx+rsi*1],rdi
    7ffff7fb7b05:	48 83 c6 08          	add    rsi,0x8
    7ffff7fb7b09:	eb ec                	jmp    0x7ffff7fb7af7
    7ffff7fb7b0b:	4a 83 24 f9 00       	and    QWORD PTR [rcx+r15*8],0x0
    7ffff7fb7b10:	49 ff c7             	inc    r15
    7ffff7fb7b13:	4d 39 fe             	cmp    r14,r15
    7ffff7fb7b16:	75 f3                	jne    0x7ffff7fb7b0b
    7ffff7fb7b18:	49 89 0c 24          	mov    QWORD PTR [r12],rcx
    7ffff7fb7b1c:	4d 89 74 24 08       	mov    QWORD PTR [r12+0x8],r14
    7ffff7fb7b21:	49 89 44 24 10       	mov    QWORD PTR [r12+0x10],rax
    7ffff7fb7b26:	49 89 5c 24 18       	mov    QWORD PTR [r12+0x18],rbx
    7ffff7fb7b2b:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb7b2f:	5b                   	pop    rbx
    7ffff7fb7b30:	41 5c                	pop    r12
    7ffff7fb7b32:	41 5d                	pop    r13
    7ffff7fb7b34:	41 5e                	pop    r14
    7ffff7fb7b36:	41 5f                	pop    r15
    7ffff7fb7b38:	5d                   	pop    rbp
    7ffff7fb7b39:	c3                   	ret
    7ffff7fb7b3a:	48 85 d2             	test   rdx,rdx
    7ffff7fb7b3d:	74 2e                	je     0x7ffff7fb7b6d
    7ffff7fb7b3f:	45 31 c0             	xor    r8d,r8d
    7ffff7fb7b42:	31 c0                	xor    eax,eax
    7ffff7fb7b44:	4c 39 c6             	cmp    rsi,r8
    7ffff7fb7b47:	74 26                	je     0x7ffff7fb7b6f
    7ffff7fb7b49:	c4 22 ab f6 0c c1    	mulx   r9,r10,QWORD PTR [rcx+r8*8]
    7ffff7fb7b4f:	45 31 db             	xor    r11d,r11d
    7ffff7fb7b52:	4a 03 04 c7          	add    rax,QWORD PTR [rdi+r8*8]
    7ffff7fb7b56:	41 0f 92 c3          	setb   r11b
    7ffff7fb7b5a:	4c 01 d0             	add    rax,r10
    7ffff7fb7b5d:	4a 89 04 c7          	mov    QWORD PTR [rdi+r8*8],rax
    7ffff7fb7b61:	4d 8d 40 01          	lea    r8,[r8+0x1]
    7ffff7fb7b65:	4d 11 cb             	adc    r11,r9
    7ffff7fb7b68:	4c 89 d8             	mov    rax,r11
    7ffff7fb7b6b:	eb d7                	jmp    0x7ffff7fb7b44
    7ffff7fb7b6d:	31 c0                	xor    eax,eax
    7ffff7fb7b6f:	c3                   	ret
    7ffff7fb7b70:	41 57                	push   r15
    7ffff7fb7b72:	41 56                	push   r14
    7ffff7fb7b74:	53                   	push   rbx
    7ffff7fb7b75:	49 89 ce             	mov    r14,rcx
    7ffff7fb7b78:	48 89 d1             	mov    rcx,rdx
    7ffff7fb7b7b:	48 89 f3             	mov    rbx,rsi
    7ffff7fb7b7e:	49 89 ff             	mov    r15,rdi
    7ffff7fb7b81:	6a 04                	push   0x4
    7ffff7fb7b83:	5a                   	pop    rdx
    7ffff7fb7b84:	4c 89 f6             	mov    rsi,r14
    7ffff7fb7b87:	4d 89 f0             	mov    r8,r14
    7ffff7fb7b8a:	e8 ab ff ff ff       	call   0x7ffff7fb7b3a
    7ffff7fb7b8f:	4c 29 f3             	sub    rbx,r14
    7ffff7fb7b92:	76 12                	jbe    0x7ffff7fb7ba6
    7ffff7fb7b94:	4b 8d 3c f7          	lea    rdi,[r15+r14*8]
    7ffff7fb7b98:	48 89 de             	mov    rsi,rbx
    7ffff7fb7b9b:	48 89 c2             	mov    rdx,rax
    7ffff7fb7b9e:	e8 4c 00 00 00       	call   0x7ffff7fb7bef
    7ffff7fb7ba3:	0f b6 c0             	movzx  eax,al
    7ffff7fb7ba6:	5b                   	pop    rbx
    7ffff7fb7ba7:	41 5e                	pop    r14
    7ffff7fb7ba9:	41 5f                	pop    r15
    7ffff7fb7bab:	c3                   	ret
    7ffff7fb7bac:	48 85 d2             	test   rdx,rdx
    7ffff7fb7baf:	74 3b                	je     0x7ffff7fb7bec
    7ffff7fb7bb1:	6a ff                	push   0xffffffffffffffff
    7ffff7fb7bb3:	58                   	pop    rax
    7ffff7fb7bb4:	45 31 c0             	xor    r8d,r8d
    7ffff7fb7bb7:	4c 39 c6             	cmp    rsi,r8
    7ffff7fb7bba:	74 2c                	je     0x7ffff7fb7be8
    7ffff7fb7bbc:	c4 22 ab f6 0c c1    	mulx   r9,r10,QWORD PTR [rcx+r8*8]
    7ffff7fb7bc2:	45 31 db             	xor    r11d,r11d
    7ffff7fb7bc5:	4a 03 04 c7          	add    rax,QWORD PTR [rdi+r8*8]
    7ffff7fb7bc9:	41 0f 92 c3          	setb   r11b
    7ffff7fb7bcd:	4c 29 d0             	sub    rax,r10
    7ffff7fb7bd0:	4d 19 cb             	sbb    r11,r9
    7ffff7fb7bd3:	48 83 c0 01          	add    rax,0x1
    7ffff7fb7bd7:	4a 89 04 c7          	mov    QWORD PTR [rdi+r8*8],rax
    7ffff7fb7bdb:	4d 8d 40 01          	lea    r8,[r8+0x1]
    7ffff7fb7bdf:	49 83 d3 fe          	adc    r11,0xfffffffffffffffe
    7ffff7fb7be3:	4c 89 d8             	mov    rax,r11
    7ffff7fb7be6:	eb cf                	jmp    0x7ffff7fb7bb7
    7ffff7fb7be8:	48 f7 d0             	not    rax
    7ffff7fb7beb:	c3                   	ret
    7ffff7fb7bec:	31 c0                	xor    eax,eax
    7ffff7fb7bee:	c3                   	ret
    7ffff7fb7bef:	48 01 17             	add    QWORD PTR [rdi],rdx
    7ffff7fb7bf2:	73 0c                	jae    0x7ffff7fb7c00
    7ffff7fb7bf4:	48 ff ce             	dec    rsi
    7ffff7fb7bf7:	48 83 c7 08          	add    rdi,0x8
    7ffff7fb7bfb:	e9 9f e3 ff ff       	jmp    0x7ffff7fb5f9f
    7ffff7fb7c00:	31 c0                	xor    eax,eax
    7ffff7fb7c02:	c3                   	ret


    # ------------------------BIG INT 곱셈기------------------------------


    7ffff7fb7c03:	48 89 f0             	mov    rax,rsi
    7ffff7fb7c06:	48 f7 de             	neg    rsi
    7ffff7fb7c09:	48 0f 48 f0          	cmovs  rsi,rax
    7ffff7fb7c0d:	48 83 fe 02          	cmp    rsi,0x2
    7ffff7fb7c11:	0f 87 5e e7 ff ff    	ja     0x7ffff7fb6375
    7ffff7fb7c17:	c3                   	ret
    7ffff7fb7c18:	41 57                	push   r15
    7ffff7fb7c1a:	41 56                	push   r14
    7ffff7fb7c1c:	53                   	push   rbx
    7ffff7fb7c1d:	48 89 d3             	mov    rbx,rdx
    7ffff7fb7c20:	49 89 f7             	mov    r15,rsi
    7ffff7fb7c23:	49 89 fe             	mov    r14,rdi
    7ffff7fb7c26:	48 85 d2             	test   rdx,rdx
    7ffff7fb7c29:	74 0d                	je     0x7ffff7fb7c38
    7ffff7fb7c2b:	4c 89 ff             	mov    rdi,r15
    7ffff7fb7c2e:	48 89 de             	mov    rsi,rbx
    7ffff7fb7c31:	e8 55 e3 ff ff       	call   0x7ffff7fb5f8b
    7ffff7fb7c36:	eb 03                	jmp    0x7ffff7fb7c3b
    7ffff7fb7c38:	4c 89 f8             	mov    rax,r15
    7ffff7fb7c3b:	4d 89 3e             	mov    QWORD PTR [r14],r15
    7ffff7fb7c3e:	49 89 5e 08          	mov    QWORD PTR [r14+0x8],rbx
    7ffff7fb7c42:	49 89 46 10          	mov    QWORD PTR [r14+0x10],rax
    7ffff7fb7c46:	5b                   	pop    rbx
    7ffff7fb7c47:	41 5e                	pop    r14
    7ffff7fb7c49:	41 5f                	pop    r15
    7ffff7fb7c4b:	c3                   	ret
    7ffff7fb7c4c:	48 8b 77 08          	mov    rsi,QWORD PTR [rdi+0x8]
    7ffff7fb7c50:	48 85 f6             	test   rsi,rsi
    7ffff7fb7c53:	74 0c                	je     0x7ffff7fb7c61
    7ffff7fb7c55:	48 8b 17             	mov    rdx,QWORD PTR [rdi]
    7ffff7fb7c58:	48 8b 7f 10          	mov    rdi,QWORD PTR [rdi+0x10]
    7ffff7fb7c5c:	e9 ad b6 ff ff       	jmp    0x7ffff7fb330e
    7ffff7fb7c61:	c3                   	ret
    7ffff7fb7c62:	53                   	push   rbx
    7ffff7fb7c63:	48 89 d0             	mov    rax,rdx
    7ffff7fb7c66:	48 89 ca             	mov    rdx,rcx
    7ffff7fb7c69:	c4 62 ab f6 ce       	mulx   r9,r10,rsi ; mulx
    7ffff7fb7c6e:	4c 89 c2             	mov    rdx,r8
    7ffff7fb7c71:	c4 62 cb f6 de       	mulx   r11,rsi,rsi ; mulx
    7ffff7fb7c76:	48 03 74 24 18       	add    rsi,QWORD PTR [rsp+0x18]
    7ffff7fb7c7b:	49 83 d3 00          	adc    r11,0x0
    7ffff7fb7c7f:	48 89 ca             	mov    rdx,rcx
    7ffff7fb7c82:	c4 e2 e3 f6 c8       	mulx   rcx,rbx,rax ;mulx
    7ffff7fb7c87:	4c 03 54 24 10       	add    r10,QWORD PTR [rsp+0x10]
    7ffff7fb7c8c:	4c 11 cb             	adc    rbx,r9
    7ffff7fb7c8f:	4c 89 c2             	mov    rdx,r8
    7ffff7fb7c92:	c4 e2 fb f6 d0       	mulx   rdx,rax,rax ; mulx
    7ffff7fb7c97:	48 11 c8             	adc    rax,rcx
    7ffff7fb7c9a:	48 83 d2 00          	adc    rdx,0x0
    7ffff7fb7c9e:	48 01 f3             	add    rbx,rsi
    7ffff7fb7ca1:	49 83 d3 00          	adc    r11,0x0
    7ffff7fb7ca5:	49 01 c3             	add    r11,rax
    7ffff7fb7ca8:	48 83 d2 00          	adc    rdx,0x0
    7ffff7fb7cac:	4c 89 17             	mov    QWORD PTR [rdi],r10
    7ffff7fb7caf:	48 89 5f 08          	mov    QWORD PTR [rdi+0x8],rbx
    7ffff7fb7cb3:	4c 89 5f 10          	mov    QWORD PTR [rdi+0x10],r11
    7ffff7fb7cb7:	48 89 57 18          	mov    QWORD PTR [rdi+0x18],rdx
    7ffff7fb7cbb:	5b                   	pop    rbx
    7ffff7fb7cbc:	c3                   	ret
    7ffff7fb7cbd:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
    7ffff7fb7cc1:	48 89 c1             	mov    rcx,rax
    7ffff7fb7cc4:	48 f7 d9             	neg    rcx
    7ffff7fb7cc7:	48 0f 48 c8          	cmovs  rcx,rax
    7ffff7fb7ccb:	48 83 f9 01          	cmp    rcx,0x1
    7ffff7fb7ccf:	74 0f                	je     0x7ffff7fb7ce0
    7ffff7fb7cd1:	48 83 f9 02          	cmp    rcx,0x2
    7ffff7fb7cd5:	74 19                	je     0x7ffff7fb7cf0
    7ffff7fb7cd7:	48 8b 4e 08          	mov    rcx,QWORD PTR [rsi+0x8]
    7ffff7fb7cdb:	48 8b 36             	mov    rsi,QWORD PTR [rsi]
    7ffff7fb7cde:	eb 10                	jmp    0x7ffff7fb7cf0
    7ffff7fb7ce0:	31 c9                	xor    ecx,ecx
    7ffff7fb7ce2:	48 83 3e 00          	cmp    QWORD PTR [rsi],0x0
    7ffff7fb7ce6:	0f 95 c1             	setne  cl
    7ffff7fb7ce9:	6a 08                	push   0x8
    7ffff7fb7ceb:	5a                   	pop    rdx
    7ffff7fb7cec:	48 0f 44 f2          	cmove  rsi,rdx
    7ffff7fb7cf0:	48 85 c0             	test   rax,rax
    7ffff7fb7cf3:	0f 9e 07             	setle  BYTE PTR [rdi]
    7ffff7fb7cf6:	48 89 77 08          	mov    QWORD PTR [rdi+0x8],rsi
    7ffff7fb7cfa:	48 89 4f 10          	mov    QWORD PTR [rdi+0x10],rcx
    7ffff7fb7cfe:	c3                   	ret
    7ffff7fb7cff:	55                   	push   rbp
    7ffff7fb7d00:	41 57                	push   r15
    7ffff7fb7d02:	41 56                	push   r14
    7ffff7fb7d04:	41 55                	push   r13
    7ffff7fb7d06:	41 54                	push   r12
    7ffff7fb7d08:	53                   	push   rbx
    7ffff7fb7d09:	48 81 ec 98 00 00 00 	sub    rsp,0x98
    7ffff7fb7d10:	48 89 d3             	mov    rbx,rdx
    7ffff7fb7d13:	48 89 7c 24 58       	mov    QWORD PTR [rsp+0x58],rdi
    7ffff7fb7d18:	4c 8b 76 08          	mov    r14,QWORD PTR [rsi+0x8]
    7ffff7fb7d1c:	4c 8b 6a 08          	mov    r13,QWORD PTR [rdx+0x8]
    7ffff7fb7d20:	49 83 fd 21          	cmp    r13,0x21
    7ffff7fb7d24:	0f 92 c1             	setb   cl
    7ffff7fb7d27:	4c 89 f0             	mov    rax,r14
    7ffff7fb7d2a:	4c 29 e8             	sub    rax,r13
    7ffff7fb7d2d:	48 83 f8 21          	cmp    rax,0x21
    7ffff7fb7d31:	0f 92 c2             	setb   dl
    7ffff7fb7d34:	08 ca                	or     dl,cl
    7ffff7fb7d36:	88 54 24 10          	mov    BYTE PTR [rsp+0x10],dl
    7ffff7fb7d3a:	48 89 74 24 08       	mov    QWORD PTR [rsp+0x8],rsi
    7ffff7fb7d3f:	74 07                	je     0x7ffff7fb7d48
    7ffff7fb7d41:	6a 01                	push   0x1
    7ffff7fb7d43:	5e                   	pop    rsi
    7ffff7fb7d44:	31 d2                	xor    edx,edx
    7ffff7fb7d46:	eb 15                	jmp    0x7ffff7fb7d5d
    7ffff7fb7d48:	4c 89 ef             	mov    rdi,r13
    7ffff7fb7d4b:	48 d1 ef             	shr    rdi,1
    7ffff7fb7d4e:	48 39 c7             	cmp    rdi,rax
    7ffff7fb7d51:	48 0f 43 f8          	cmovae rdi,rax
    7ffff7fb7d55:	e8 42 e8 ff ff       	call   0x7ffff7fb659c
    7ffff7fb7d5a:	48 89 c6             	mov    rsi,rax
    7ffff7fb7d5d:	48 8d bc 24 80 00 00 	lea    rdi,[rsp+0x80]
    7ffff7fb7d64:	00 
    7ffff7fb7d65:	e8 ae fe ff ff       	call   0x7ffff7fb7c18
    7ffff7fb7d6a:	48 89 5c 24 50       	mov    QWORD PTR [rsp+0x50],rbx
    7ffff7fb7d6f:	48 8b 2b             	mov    rbp,QWORD PTR [rbx]
    7ffff7fb7d72:	f3 4a 0f bd 5c ed f8 	lzcnt  rbx,QWORD PTR [rbp+r13*8-0x8]
    7ffff7fb7d79:	48 89 ef             	mov    rdi,rbp
    7ffff7fb7d7c:	4c 89 ee             	mov    rsi,r13
    7ffff7fb7d7f:	89 da                	mov    edx,ebx
    7ffff7fb7d81:	e8 57 e8 ff ff       	call   0x7ffff7fb65dd
    7ffff7fb7d86:	4a 8b 74 ed f0       	mov    rsi,QWORD PTR [rbp+r13*8-0x10]
    7ffff7fb7d8b:	4a 8b 54 ed f8       	mov    rdx,QWORD PTR [rbp+r13*8-0x8]
    7ffff7fb7d90:	4c 8d 7c 24 60       	lea    r15,[rsp+0x60]
    7ffff7fb7d95:	4c 89 ff             	mov    rdi,r15
    7ffff7fb7d98:	e8 8a e7 ff ff       	call   0x7ffff7fb6527
    7ffff7fb7d9d:	49 8b 07             	mov    rax,QWORD PTR [r15]
    7ffff7fb7da0:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
    7ffff7fb7da5:	49 8b 47 08          	mov    rax,QWORD PTR [r15+0x8]
    7ffff7fb7da9:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
    7ffff7fb7dae:	4d 8b 67 10          	mov    r12,QWORD PTR [r15+0x10]
    7ffff7fb7db2:	48 8b 44 24 08       	mov    rax,QWORD PTR [rsp+0x8]
    7ffff7fb7db7:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    7ffff7fb7dba:	48 8d 8c 24 80 00 00 	lea    rcx,[rsp+0x80]
    7ffff7fb7dc1:	00 
    7ffff7fb7dc2:	48 8b 41 10          	mov    rax,QWORD PTR [rcx+0x10]
    7ffff7fb7dc6:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
    7ffff7fb7dca:	48 01 c1             	add    rcx,rax
    7ffff7fb7dcd:	49 89 07             	mov    QWORD PTR [r15],rax
    7ffff7fb7dd0:	49 89 4f 08          	mov    QWORD PTR [r15+0x8],rcx
    7ffff7fb7dd4:	49 89 d7             	mov    r15,rdx
    7ffff7fb7dd7:	48 89 d7             	mov    rdi,rdx
    7ffff7fb7dda:	4c 89 f6             	mov    rsi,r14
    7ffff7fb7ddd:	48 89 5c 24 48       	mov    QWORD PTR [rsp+0x48],rbx
    7ffff7fb7de2:	89 da                	mov    edx,ebx
    7ffff7fb7de4:	e8 f4 e7 ff ff       	call   0x7ffff7fb65dd
    7ffff7fb7de9:	48 85 c0             	test   rax,rax
    7ffff7fb7dec:	48 89 6c 24 18       	mov    QWORD PTR [rsp+0x18],rbp
    7ffff7fb7df1:	74 34                	je     0x7ffff7fb7e27
    7ffff7fb7df3:	48 83 ec 08          	sub    rsp,0x8
    7ffff7fb7df7:	48 89 c7             	mov    rdi,rax
    7ffff7fb7dfa:	4c 89 fe             	mov    rsi,r15
    7ffff7fb7dfd:	4c 89 f2             	mov    rdx,r14
    7ffff7fb7e00:	48 89 e9             	mov    rcx,rbp
    7ffff7fb7e03:	4d 89 e8             	mov    r8,r13
    7ffff7fb7e06:	41 54                	push   r12
    7ffff7fb7e08:	48 8b 6c 24 38       	mov    rbp,QWORD PTR [rsp+0x38]
    7ffff7fb7e0d:	55                   	push   rbp
    7ffff7fb7e0e:	48 8b 5c 24 38       	mov    rbx,QWORD PTR [rsp+0x38]
    7ffff7fb7e13:	53                   	push   rbx
    7ffff7fb7e14:	e8 23 e8 ff ff       	call   0x7ffff7fb663c
    7ffff7fb7e19:	48 83 c4 20          	add    rsp,0x20
    7ffff7fb7e1d:	48 89 44 24 30       	mov    QWORD PTR [rsp+0x30],rax
    7ffff7fb7e22:	49 89 d8             	mov    r8,rbx
    7ffff7fb7e25:	eb 13                	jmp    0x7ffff7fb7e3a
    7ffff7fb7e27:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
    7ffff7fb7e2e:	00 00 
    7ffff7fb7e30:	48 8b 6c 24 28       	mov    rbp,QWORD PTR [rsp+0x28]
    7ffff7fb7e35:	4c 8b 44 24 20       	mov    r8,QWORD PTR [rsp+0x20]
    7ffff7fb7e3a:	80 7c 24 10 00       	cmp    BYTE PTR [rsp+0x10],0x0
    7ffff7fb7e3f:	74 26                	je     0x7ffff7fb7e67
    7ffff7fb7e41:	48 83 ec 08          	sub    rsp,0x8
    7ffff7fb7e45:	4c 89 ff             	mov    rdi,r15
    7ffff7fb7e48:	4c 89 f6             	mov    rsi,r14
    7ffff7fb7e4b:	4c 8b 74 24 20       	mov    r14,QWORD PTR [rsp+0x20]
    7ffff7fb7e50:	4c 89 f2             	mov    rdx,r14
    7ffff7fb7e53:	4c 89 e9             	mov    rcx,r13
    7ffff7fb7e56:	49 89 e9             	mov    r9,rbp
    7ffff7fb7e59:	41 54                	push   r12
    7ffff7fb7e5b:	e8 7f e8 ff ff       	call   0x7ffff7fb66df
    7ffff7fb7e60:	59                   	pop    rcx
    7ffff7fb7e61:	5a                   	pop    rdx
    7ffff7fb7e62:	e9 b6 00 00 00       	jmp    0x7ffff7fb7f1d
    7ffff7fb7e67:	4c 89 64 24 38       	mov    QWORD PTR [rsp+0x38],r12
    7ffff7fb7e6c:	4c 89 e9             	mov    rcx,r13
    7ffff7fb7e6f:	4a 8d 2c 6d 00 00 00 	lea    rbp,[r13*2+0x0]
    7ffff7fb7e76:	00 
    7ffff7fb7e77:	4e 8d 2c f5 00 00 00 	lea    r13,[r14*8+0x0]
    7ffff7fb7e7e:	00 
    7ffff7fb7e7f:	48 89 c8             	mov    rax,rcx
    7ffff7fb7e82:	48 c1 e0 04          	shl    rax,0x4
    7ffff7fb7e86:	49 29 c5             	sub    r13,rax
    7ffff7fb7e89:	4c 89 7c 24 40       	mov    QWORD PTR [rsp+0x40],r15
    7ffff7fb7e8e:	4d 01 fd             	add    r13,r15
    7ffff7fb7e91:	48 89 4c 24 10       	mov    QWORD PTR [rsp+0x10],rcx
    7ffff7fb7e96:	4c 8d 24 cd 00 00 00 	lea    r12,[rcx*8+0x0]
    7ffff7fb7e9d:	00 
    7ffff7fb7e9e:	49 f7 dc             	neg    r12
    7ffff7fb7ea1:	45 31 ff             	xor    r15d,r15d
    7ffff7fb7ea4:	48 8b 5c 24 10       	mov    rbx,QWORD PTR [rsp+0x10]
    7ffff7fb7ea9:	49 39 ee             	cmp    r14,rbp
    7ffff7fb7eac:	72 34                	jb     0x7ffff7fb7ee2
    7ffff7fb7eae:	4c 89 ef             	mov    rdi,r13
    7ffff7fb7eb1:	48 89 ee             	mov    rsi,rbp
    7ffff7fb7eb4:	48 8b 54 24 18       	mov    rdx,QWORD PTR [rsp+0x18]
    7ffff7fb7eb9:	48 89 d9             	mov    rcx,rbx
    7ffff7fb7ebc:	4c 8b 44 24 20       	mov    r8,QWORD PTR [rsp+0x20]
    7ffff7fb7ec1:	4c 8b 4c 24 28       	mov    r9,QWORD PTR [rsp+0x28]
    7ffff7fb7ec6:	48 8d 44 24 60       	lea    rax,[rsp+0x60]
    7ffff7fb7ecb:	50                   	push   rax
    7ffff7fb7ecc:	ff 74 24 40          	push   QWORD PTR [rsp+0x40]
    7ffff7fb7ed0:	e8 ab e8 ff ff       	call   0x7ffff7fb6780
    7ffff7fb7ed5:	59                   	pop    rcx
    7ffff7fb7ed6:	5a                   	pop    rdx
    7ffff7fb7ed7:	41 08 c7             	or     r15b,al
    7ffff7fb7eda:	49 29 de             	sub    r14,rbx
    7ffff7fb7edd:	4d 01 e5             	add    r13,r12
    7ffff7fb7ee0:	eb c7                	jmp    0x7ffff7fb7ea9
    7ffff7fb7ee2:	4c 8b 6c 24 10       	mov    r13,QWORD PTR [rsp+0x10]
    7ffff7fb7ee7:	4d 39 ee             	cmp    r14,r13
    7ffff7fb7eea:	76 3b                	jbe    0x7ffff7fb7f27
    7ffff7fb7eec:	48 8b 7c 24 40       	mov    rdi,QWORD PTR [rsp+0x40]
    7ffff7fb7ef1:	4c 89 f6             	mov    rsi,r14
    7ffff7fb7ef4:	4c 8b 74 24 18       	mov    r14,QWORD PTR [rsp+0x18]
    7ffff7fb7ef9:	4c 89 f2             	mov    rdx,r14
    7ffff7fb7efc:	4c 89 e9             	mov    rcx,r13
    7ffff7fb7eff:	4c 8b 44 24 20       	mov    r8,QWORD PTR [rsp+0x20]
    7ffff7fb7f04:	4c 8b 4c 24 28       	mov    r9,QWORD PTR [rsp+0x28]
    7ffff7fb7f09:	48 8d 44 24 60       	lea    rax,[rsp+0x60]
    7ffff7fb7f0e:	50                   	push   rax
    7ffff7fb7f0f:	ff 74 24 40          	push   QWORD PTR [rsp+0x40]
    7ffff7fb7f13:	e8 d9 e8 ff ff       	call   0x7ffff7fb67f1
    7ffff7fb7f18:	59                   	pop    rcx
    7ffff7fb7f19:	5a                   	pop    rdx
    7ffff7fb7f1a:	44 08 f8             	or     al,r15b
    7ffff7fb7f1d:	41 89 c7             	mov    r15d,eax
    7ffff7fb7f20:	4c 8b 64 24 08       	mov    r12,QWORD PTR [rsp+0x8]
    7ffff7fb7f25:	eb 0a                	jmp    0x7ffff7fb7f31
    7ffff7fb7f27:	4c 8b 64 24 08       	mov    r12,QWORD PTR [rsp+0x8]
    7ffff7fb7f2c:	4c 8b 74 24 18       	mov    r14,QWORD PTR [rsp+0x18]
    7ffff7fb7f31:	41 0f b6 c7          	movzx  eax,r15b
    7ffff7fb7f35:	83 e0 01             	and    eax,0x1
    7ffff7fb7f38:	48 8b 74 24 30       	mov    rsi,QWORD PTR [rsp+0x30]
    7ffff7fb7f3d:	48 01 c6             	add    rsi,rax
    7ffff7fb7f40:	4c 89 e7             	mov    rdi,r12
    7ffff7fb7f43:	e8 8a e3 ff ff       	call   0x7ffff7fb62d2
    7ffff7fb7f48:	48 8d bc 24 80 00 00 	lea    rdi,[rsp+0x80]
    7ffff7fb7f4f:	00 
    7ffff7fb7f50:	e8 f7 fc ff ff       	call   0x7ffff7fb7c4c
    7ffff7fb7f55:	49 8b 1c 24          	mov    rbx,QWORD PTR [r12]
    7ffff7fb7f59:	4a 8d 14 ed 00 00 00 	lea    rdx,[r13*8+0x0]
    7ffff7fb7f60:	00 
    7ffff7fb7f61:	4c 89 f7             	mov    rdi,r14
    7ffff7fb7f64:	48 89 de             	mov    rsi,rbx
    7ffff7fb7f67:	ff 15 fb 0b 00 00    	call   QWORD PTR [rip+0xbfb]        # 0x7ffff7fb8b68
    7ffff7fb7f6d:	4c 89 f7             	mov    rdi,r14
    7ffff7fb7f70:	4c 89 ee             	mov    rsi,r13
    7ffff7fb7f73:	48 8b 54 24 48       	mov    rdx,QWORD PTR [rsp+0x48]
    7ffff7fb7f78:	e8 86 e4 ff ff       	call   0x7ffff7fb6403
    7ffff7fb7f7d:	48 8b 4c 24 50       	mov    rcx,QWORD PTR [rsp+0x50]
    7ffff7fb7f82:	48 8b 41 10          	mov    rax,QWORD PTR [rcx+0x10]
    7ffff7fb7f86:	48 8d 74 24 60       	lea    rsi,[rsp+0x60]
    7ffff7fb7f8b:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb7f8f:	c5 f8 10 01          	vmovups xmm0,XMMWORD PTR [rcx]
    7ffff7fb7f93:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb7f97:	48 8b 7c 24 58       	mov    rdi,QWORD PTR [rsp+0x58]
    7ffff7fb7f9c:	e8 53 e2 ff ff       	call   0x7ffff7fb61f4
    7ffff7fb7fa1:	49 8b 74 24 10       	mov    rsi,QWORD PTR [r12+0x10]
    7ffff7fb7fa6:	48 89 df             	mov    rdi,rbx
    7ffff7fb7fa9:	48 81 c4 98 00 00 00 	add    rsp,0x98
    7ffff7fb7fb0:	5b                   	pop    rbx
    7ffff7fb7fb1:	41 5c                	pop    r12
    7ffff7fb7fb3:	41 5d                	pop    r13
    7ffff7fb7fb5:	41 5e                	pop    r14
    7ffff7fb7fb7:	41 5f                	pop    r15
    7ffff7fb7fb9:	5d                   	pop    rbp
    7ffff7fb7fba:	e9 b1 e3 ff ff       	jmp    0x7ffff7fb6370
    7ffff7fb7fbf:	4c 8b 46 10          	mov    r8,QWORD PTR [rsi+0x10]
    7ffff7fb7fc3:	4c 89 c0             	mov    rax,r8
    7ffff7fb7fc6:	48 f7 d8             	neg    rax
    7ffff7fb7fc9:	4c 89 c1             	mov    rcx,r8
    7ffff7fb7fcc:	48 0f 49 c8          	cmovns rcx,rax
    7ffff7fb7fd0:	48 83 f1 01          	xor    rcx,0x1
    7ffff7fb7fd4:	48 0b 0e             	or     rcx,QWORD PTR [rsi]
    7ffff7fb7fd7:	0f 95 c1             	setne  cl
    7ffff7fb7fda:	4d 85 c0             	test   r8,r8
    7ffff7fb7fdd:	41 0f 9e c0          	setle  r8b
    7ffff7fb7fe1:	41 38 d0             	cmp    r8b,dl
    7ffff7fb7fe4:	74 08                	je     0x7ffff7fb7fee
    7ffff7fb7fe6:	84 c9                	test   cl,cl
    7ffff7fb7fe8:	74 04                	je     0x7ffff7fb7fee
    7ffff7fb7fea:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb7fee:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
    7ffff7fb7ff2:	48 89 47 10          	mov    QWORD PTR [rdi+0x10],rax
    7ffff7fb7ff6:	c5 f8 10 06          	vmovups xmm0,XMMWORD PTR [rsi]
    7ffff7fb7ffa:	c5 f8 11 07          	vmovups XMMWORD PTR [rdi],xmm0
    7ffff7fb7ffe:	c3                   	ret
    7ffff7fb7fff:	55                   	push   rbp
    7ffff7fb8000:	41 57                	push   r15
    7ffff7fb8002:	41 56                	push   r14
    7ffff7fb8004:	41 55                	push   r13
    7ffff7fb8006:	41 54                	push   r12
    7ffff7fb8008:	53                   	push   rbx
    7ffff7fb8009:	48 83 ec 58          	sub    rsp,0x58
    7ffff7fb800d:	49 89 f6             	mov    r14,rsi
    7ffff7fb8010:	48 89 fb             	mov    rbx,rdi
    7ffff7fb8013:	48 89 d0             	mov    rax,rdx
    7ffff7fb8016:	48 09 c8             	or     rax,rcx
    7ffff7fb8019:	74 65                	je     0x7ffff7fb8080
    7ffff7fb801b:	49 89 cc             	mov    r12,rcx
    7ffff7fb801e:	49 89 d7             	mov    r15,rdx
    7ffff7fb8021:	48 89 d0             	mov    rax,rdx
    7ffff7fb8024:	48 83 f0 01          	xor    rax,0x1
    7ffff7fb8028:	48 09 c8             	or     rax,rcx
    7ffff7fb802b:	0f 84 94 01 00 00    	je     0x7ffff7fb81c5
    7ffff7fb8031:	4d 85 e4             	test   r12,r12
    7ffff7fb8034:	75 74                	jne    0x7ffff7fb80aa
    7ffff7fb8036:	4c 89 f8             	mov    rax,r15
    7ffff7fb8039:	48 83 c0 ff          	add    rax,0xffffffffffffffff
    7ffff7fb803d:	4c 89 e1             	mov    rcx,r12
    7ffff7fb8040:	48 83 d1 ff          	adc    rcx,0xffffffffffffffff
    7ffff7fb8044:	4c 89 e2             	mov    rdx,r12
    7ffff7fb8047:	48 31 ca             	xor    rdx,rcx
    7ffff7fb804a:	4c 89 fe             	mov    rsi,r15
    7ffff7fb804d:	48 31 c6             	xor    rsi,rax
    7ffff7fb8050:	48 39 f0             	cmp    rax,rsi
    7ffff7fb8053:	48 19 d1             	sbb    rcx,rdx
    7ffff7fb8056:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
    7ffff7fb8059:	49 8b 76 08          	mov    rsi,QWORD PTR [r14+0x8]
    7ffff7fb805d:	0f 83 4f 01 00 00    	jae    0x7ffff7fb81b2
    7ffff7fb8063:	f3 49 0f bc c7       	tzcnt  rax,r15
    7ffff7fb8068:	f3 49 0f bc d4       	tzcnt  rdx,r12
    7ffff7fb806d:	83 c2 40             	add    edx,0x40
    7ffff7fb8070:	4d 85 ff             	test   r15,r15
    7ffff7fb8073:	0f 45 d0             	cmovne edx,eax
    7ffff7fb8076:	e8 62 e5 ff ff       	call   0x7ffff7fb65dd
    7ffff7fb807b:	e9 3a 01 00 00       	jmp    0x7ffff7fb81ba
    7ffff7fb8080:	c5 f8 57 c0          	vxorps xmm0,xmm0,xmm0
    7ffff7fb8084:	c5 f8 11 03          	vmovups XMMWORD PTR [rbx],xmm0
    7ffff7fb8088:	48 c7 43 10 01 00 00 	mov    QWORD PTR [rbx+0x10],0x1
    7ffff7fb808f:	00 
    7ffff7fb8090:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
    7ffff7fb8093:	49 8b 76 10          	mov    rsi,QWORD PTR [r14+0x10]
    7ffff7fb8097:	48 83 c4 58          	add    rsp,0x58
    7ffff7fb809b:	5b                   	pop    rbx
    7ffff7fb809c:	41 5c                	pop    r12
    7ffff7fb809e:	41 5d                	pop    r13
    7ffff7fb80a0:	41 5e                	pop    r14
    7ffff7fb80a2:	41 5f                	pop    r15
    7ffff7fb80a4:	5d                   	pop    rbp
    7ffff7fb80a5:	e9 c6 e2 ff ff       	jmp    0x7ffff7fb6370
    7ffff7fb80aa:	48 89 5c 24 28       	mov    QWORD PTR [rsp+0x28],rbx
    7ffff7fb80af:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
    7ffff7fb80b2:	4c 89 74 24 08       	mov    QWORD PTR [rsp+0x8],r14
    7ffff7fb80b7:	49 8b 6e 08          	mov    rbp,QWORD PTR [r14+0x8]
    7ffff7fb80bb:	48 89 6c 24 20       	mov    QWORD PTR [rsp+0x20],rbp
    7ffff7fb80c0:	48 83 e5 fe          	and    rbp,0xfffffffffffffffe
    7ffff7fb80c4:	48 89 4c 24 18       	mov    QWORD PTR [rsp+0x18],rcx
    7ffff7fb80c9:	4c 8d 71 08          	lea    r14,[rcx+0x8]
    7ffff7fb80cd:	48 89 6c 24 10       	mov    QWORD PTR [rsp+0x10],rbp
    7ffff7fb80d2:	48 f7 dd             	neg    rbp
    7ffff7fb80d5:	45 31 ed             	xor    r13d,r13d
    7ffff7fb80d8:	31 db                	xor    ebx,ebx
    7ffff7fb80da:	48 85 ed             	test   rbp,rbp
    7ffff7fb80dd:	74 3c                	je     0x7ffff7fb811b
    7ffff7fb80df:	49 8b 76 f8          	mov    rsi,QWORD PTR [r14-0x8]
    7ffff7fb80e3:	49 8b 16             	mov    rdx,QWORD PTR [r14]
    7ffff7fb80e6:	48 8d 7c 24 30       	lea    rdi,[rsp+0x30]
    7ffff7fb80eb:	4c 89 f9             	mov    rcx,r15
    7ffff7fb80ee:	4d 89 e0             	mov    r8,r12
    7ffff7fb80f1:	53                   	push   rbx
    7ffff7fb80f2:	41 55                	push   r13
    7ffff7fb80f4:	e8 69 fb ff ff       	call   0x7ffff7fb7c62
    7ffff7fb80f9:	58                   	pop    rax
    7ffff7fb80fa:	59                   	pop    rcx
    7ffff7fb80fb:	c5 f8 28 44 24 30    	vmovaps xmm0,XMMWORD PTR [rsp+0x30]
    7ffff7fb8101:	48 8b 5c 24 48       	mov    rbx,QWORD PTR [rsp+0x48]
    7ffff7fb8106:	4c 8b 6c 24 40       	mov    r13,QWORD PTR [rsp+0x40]
    7ffff7fb810b:	c4 c1 78 11 46 f8    	vmovups XMMWORD PTR [r14-0x8],xmm0
    7ffff7fb8111:	49 83 c6 10          	add    r14,0x10
    7ffff7fb8115:	48 83 c5 02          	add    rbp,0x2
    7ffff7fb8119:	eb bf                	jmp    0x7ffff7fb80da
    7ffff7fb811b:	48 8b 74 24 20       	mov    rsi,QWORD PTR [rsp+0x20]
    7ffff7fb8120:	40 f6 c6 01          	test   sil,0x1
    7ffff7fb8124:	74 39                	je     0x7ffff7fb815f
    7ffff7fb8126:	4c 8b 44 24 18       	mov    r8,QWORD PTR [rsp+0x18]
    7ffff7fb812b:	4c 8b 4c 24 10       	mov    r9,QWORD PTR [rsp+0x10]
    7ffff7fb8130:	4b 8b 04 c8          	mov    rax,QWORD PTR [r8+r9*8]
    7ffff7fb8134:	4c 89 fa             	mov    rdx,r15
    7ffff7fb8137:	c4 e2 c3 f6 c8       	mulx   rcx,rdi,rax
    7ffff7fb813c:	4c 89 e2             	mov    rdx,r12
    7ffff7fb813f:	c4 e2 fb f6 d0       	mulx   rdx,rax,rax
    7ffff7fb8144:	48 01 d8             	add    rax,rbx
    7ffff7fb8147:	48 83 d2 00          	adc    rdx,0x0
    7ffff7fb814b:	4c 01 ef             	add    rdi,r13
    7ffff7fb814e:	48 11 c8             	adc    rax,rcx
    7ffff7fb8151:	48 83 d2 00          	adc    rdx,0x0
    7ffff7fb8155:	4b 89 3c c8          	mov    QWORD PTR [r8+r9*8],rdi
    7ffff7fb8159:	49 89 c5             	mov    r13,rax
    7ffff7fb815c:	48 89 d3             	mov    rbx,rdx
    7ffff7fb815f:	4c 8b 74 24 08       	mov    r14,QWORD PTR [rsp+0x8]
    7ffff7fb8164:	4c 89 e8             	mov    rax,r13
    7ffff7fb8167:	48 09 d8             	or     rax,rbx
    7ffff7fb816a:	74 24                	je     0x7ffff7fb8190
    7ffff7fb816c:	48 83 c6 02          	add    rsi,0x2
    7ffff7fb8170:	4c 89 f7             	mov    rdi,r14
    7ffff7fb8173:	e8 8f e1 ff ff       	call   0x7ffff7fb6307
    7ffff7fb8178:	49 8b 06             	mov    rax,QWORD PTR [r14]
    7ffff7fb817b:	49 8b 4e 08          	mov    rcx,QWORD PTR [r14+0x8]
    7ffff7fb817f:	4c 89 2c c8          	mov    QWORD PTR [rax+rcx*8],r13
    7ffff7fb8183:	48 89 5c c8 08       	mov    QWORD PTR [rax+rcx*8+0x8],rbx
    7ffff7fb8188:	48 83 c1 02          	add    rcx,0x2
    7ffff7fb818c:	49 89 4e 08          	mov    QWORD PTR [r14+0x8],rcx
    7ffff7fb8190:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
    7ffff7fb8194:	48 8d 74 24 30       	lea    rsi,[rsp+0x30]
    7ffff7fb8199:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb819d:	49 8b 06             	mov    rax,QWORD PTR [r14]
    7ffff7fb81a0:	48 89 06             	mov    QWORD PTR [rsi],rax
    7ffff7fb81a3:	49 8b 46 08          	mov    rax,QWORD PTR [r14+0x8]
    7ffff7fb81a7:	48 89 46 08          	mov    QWORD PTR [rsi+0x8],rax
    7ffff7fb81ab:	48 8b 7c 24 28       	mov    rdi,QWORD PTR [rsp+0x28]
    7ffff7fb81b0:	eb 2c                	jmp    0x7ffff7fb81de
    7ffff7fb81b2:	4c 89 fa             	mov    rdx,r15
    7ffff7fb81b5:	e8 d4 f8 ff ff       	call   0x7ffff7fb7a8e
    7ffff7fb81ba:	4c 89 f7             	mov    rdi,r14
    7ffff7fb81bd:	48 89 c6             	mov    rsi,rax
    7ffff7fb81c0:	e8 0d e1 ff ff       	call   0x7ffff7fb62d2
    7ffff7fb81c5:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
    7ffff7fb81c9:	48 8d 74 24 30       	lea    rsi,[rsp+0x30]
    7ffff7fb81ce:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb81d2:	c4 c1 78 10 06       	vmovups xmm0,XMMWORD PTR [r14]
    7ffff7fb81d7:	c5 f8 29 06          	vmovaps XMMWORD PTR [rsi],xmm0
    7ffff7fb81db:	48 89 df             	mov    rdi,rbx
    7ffff7fb81de:	e8 11 e0 ff ff       	call   0x7ffff7fb61f4
    7ffff7fb81e3:	48 83 c4 58          	add    rsp,0x58
    7ffff7fb81e7:	5b                   	pop    rbx
    7ffff7fb81e8:	41 5c                	pop    r12
    7ffff7fb81ea:	41 5d                	pop    r13
    7ffff7fb81ec:	41 5e                	pop    r14
    7ffff7fb81ee:	41 5f                	pop    r15
    7ffff7fb81f0:	5d                   	pop    rbp
    7ffff7fb81f1:	c3                   	ret
    7ffff7fb81f2:	41 56                	push   r14
    7ffff7fb81f4:	53                   	push   rbx
    7ffff7fb81f5:	50                   	push   rax
    7ffff7fb81f6:	83 64 24 04 00       	and    DWORD PTR [rsp+0x4],0x0
    7ffff7fb81fb:	88 54 24 04          	mov    BYTE PTR [rsp+0x4],dl
    7ffff7fb81ff:	48 85 f6             	test   rsi,rsi
    7ffff7fb8202:	74 29                	je     0x7ffff7fb822d
    7ffff7fb8204:	48 89 f3             	mov    rbx,rsi
    7ffff7fb8207:	49 89 fe             	mov    r14,rdi
    7ffff7fb820a:	48 8d 7c 24 04       	lea    rdi,[rsp+0x4]
    7ffff7fb820f:	6a 01                	push   0x1
    7ffff7fb8211:	5a                   	pop    rdx
    7ffff7fb8212:	4c 89 f6             	mov    rsi,r14
    7ffff7fb8215:	ff 15 85 09 00 00    	call   QWORD PTR [rip+0x985]        # 0x7ffff7fb8ba0
    7ffff7fb821b:	89 c1                	mov    ecx,eax
    7ffff7fb821d:	48 ff cb             	dec    rbx
    7ffff7fb8220:	49 ff c6             	inc    r14
    7ffff7fb8223:	31 c0                	xor    eax,eax
    7ffff7fb8225:	85 c9                	test   ecx,ecx
    7ffff7fb8227:	49 0f 44 c6          	cmove  rax,r14
    7ffff7fb822b:	eb 02                	jmp    0x7ffff7fb822f
    7ffff7fb822d:	31 c0                	xor    eax,eax
    7ffff7fb822f:	48 89 da             	mov    rdx,rbx
    7ffff7fb8232:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb8236:	5b                   	pop    rbx
    7ffff7fb8237:	41 5e                	pop    r14
    7ffff7fb8239:	c3                   	ret
    7ffff7fb823a:	8d 47 d0             	lea    eax,[rdi-0x30]
    7ffff7fb823d:	3c 0a                	cmp    al,0xa
    7ffff7fb823f:	73 05                	jae    0x7ffff7fb8246
    7ffff7fb8241:	0f b6 d0             	movzx  edx,al
    7ffff7fb8244:	eb 1f                	jmp    0x7ffff7fb8265
    7ffff7fb8246:	8d 47 9f             	lea    eax,[rdi-0x61]
    7ffff7fb8249:	3c 1a                	cmp    al,0x1a
    7ffff7fb824b:	73 09                	jae    0x7ffff7fb8256
    7ffff7fb824d:	40 0f b6 d7          	movzx  edx,dil
    7ffff7fb8251:	83 c2 a9             	add    edx,0xffffffa9
    7ffff7fb8254:	eb 0f                	jmp    0x7ffff7fb8265
    7ffff7fb8256:	8d 47 bf             	lea    eax,[rdi-0x41]
    7ffff7fb8259:	3c 1a                	cmp    al,0x1a
    7ffff7fb825b:	73 11                	jae    0x7ffff7fb826e
    7ffff7fb825d:	40 80 c7 c9          	add    dil,0xc9
    7ffff7fb8261:	40 0f b6 d7          	movzx  edx,dil
    7ffff7fb8265:	31 c0                	xor    eax,eax
    7ffff7fb8267:	83 fa 10             	cmp    edx,0x10
    7ffff7fb826a:	0f 92 c0             	setb   al
    7ffff7fb826d:	c3                   	ret
    7ffff7fb826e:	31 c0                	xor    eax,eax
    7ffff7fb8270:	c3                   	ret
    7ffff7fb8271:	55                   	push   rbp
    7ffff7fb8272:	41 57                	push   r15
    7ffff7fb8274:	41 56                	push   r14
    7ffff7fb8276:	41 55                	push   r13
    7ffff7fb8278:	41 54                	push   r12
    7ffff7fb827a:	53                   	push   rbx
    7ffff7fb827b:	48 83 ec 68          	sub    rsp,0x68
    7ffff7fb827f:	49 89 d5             	mov    r13,rdx
    7ffff7fb8282:	48 89 f5             	mov    rbp,rsi
    7ffff7fb8285:	48 89 fb             	mov    rbx,rdi
    7ffff7fb8288:	6a 2d                	push   0x2d
    7ffff7fb828a:	5a                   	pop    rdx
    7ffff7fb828b:	48 89 f7             	mov    rdi,rsi
    7ffff7fb828e:	4c 89 ee             	mov    rsi,r13
    7ffff7fb8291:	e8 5c ff ff ff       	call   0x7ffff7fb81f2
    7ffff7fb8296:	49 89 c6             	mov    r14,rax
    7ffff7fb8299:	48 85 c0             	test   rax,rax
    7ffff7fb829c:	74 08                	je     0x7ffff7fb82a6
    7ffff7fb829e:	49 89 d7             	mov    r15,rdx
    7ffff7fb82a1:	4d 89 f4             	mov    r12,r14
    7ffff7fb82a4:	eb 1f                	jmp    0x7ffff7fb82c5
    7ffff7fb82a6:	6a 2b                	push   0x2b
    7ffff7fb82a8:	5a                   	pop    rdx
    7ffff7fb82a9:	48 89 ef             	mov    rdi,rbp
    7ffff7fb82ac:	4c 89 ee             	mov    rsi,r13
    7ffff7fb82af:	e8 3e ff ff ff       	call   0x7ffff7fb81f2
    7ffff7fb82b4:	49 89 c4             	mov    r12,rax
    7ffff7fb82b7:	49 89 d7             	mov    r15,rdx
    7ffff7fb82ba:	48 85 c0             	test   rax,rax
    7ffff7fb82bd:	4c 0f 44 e5          	cmove  r12,rbp
    7ffff7fb82c1:	4d 0f 44 fd          	cmove  r15,r13
    7ffff7fb82c5:	4d 85 ff             	test   r15,r15
    7ffff7fb82c8:	0f 84 bf 00 00 00    	je     0x7ffff7fb838d
    7ffff7fb82ce:	6a 30                	push   0x30
    7ffff7fb82d0:	5d                   	pop    rbp
    7ffff7fb82d1:	4c 89 e7             	mov    rdi,r12
    7ffff7fb82d4:	4c 89 fe             	mov    rsi,r15
    7ffff7fb82d7:	89 ea                	mov    edx,ebp
    7ffff7fb82d9:	e8 14 ff ff ff       	call   0x7ffff7fb81f2
    7ffff7fb82de:	48 85 c0             	test   rax,rax
    7ffff7fb82e1:	74 08                	je     0x7ffff7fb82eb
    7ffff7fb82e3:	49 89 d7             	mov    r15,rdx
    7ffff7fb82e6:	49 89 c4             	mov    r12,rax
    7ffff7fb82e9:	eb e6                	jmp    0x7ffff7fb82d1
    7ffff7fb82eb:	48 89 5c 24 08       	mov    QWORD PTR [rsp+0x8],rbx
    7ffff7fb82f0:	49 83 ff 11          	cmp    r15,0x11
    7ffff7fb82f4:	0f 82 9b 00 00 00    	jb     0x7ffff7fb8395
    7ffff7fb82fa:	4a 8d 34 bd ff ff ff 	lea    rsi,[r15*4-0x1]
    7ffff7fb8301:	ff 
    7ffff7fb8302:	48 c1 ee 06          	shr    rsi,0x6
    7ffff7fb8306:	48 ff c6             	inc    rsi
    7ffff7fb8309:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
    7ffff7fb830e:	48 89 ef             	mov    rdi,rbp
    7ffff7fb8311:	e8 6b e0 ff ff       	call   0x7ffff7fb6381
    7ffff7fb8316:	4d 01 e7             	add    r15,r12
    7ffff7fb8319:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
    7ffff7fb831d:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
    7ffff7fb8322:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
    7ffff7fb8326:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
    7ffff7fb832b:	48 8b 6d 08          	mov    rbp,QWORD PTR [rbp+0x8]
    7ffff7fb832f:	45 31 ed             	xor    r13d,r13d
    7ffff7fb8332:	31 c9                	xor    ecx,ecx
    7ffff7fb8334:	89 cb                	mov    ebx,ecx
    7ffff7fb8336:	4d 39 e7             	cmp    r15,r12
    7ffff7fb8339:	0f 84 96 00 00 00    	je     0x7ffff7fb83d5
    7ffff7fb833f:	41 8a 47 ff          	mov    al,BYTE PTR [r15-0x1]
    7ffff7fb8343:	49 ff cf             	dec    r15
    7ffff7fb8346:	3c 5f                	cmp    al,0x5f
    7ffff7fb8348:	74 ec                	je     0x7ffff7fb8336
    7ffff7fb834a:	0f b6 f8             	movzx  edi,al
    7ffff7fb834d:	e8 e8 fe ff ff       	call   0x7ffff7fb823a
    7ffff7fb8352:	a8 01                	test   al,0x1
    7ffff7fb8354:	0f 84 27 01 00 00    	je     0x7ffff7fb8481
    7ffff7fb835a:	89 d0                	mov    eax,edx
    7ffff7fb835c:	c4 e2 e1 f7 c8       	shlx   rcx,rax,rbx
    7ffff7fb8361:	49 09 cd             	or     r13,rcx
    7ffff7fb8364:	8d 4b 04             	lea    ecx,[rbx+0x4]
    7ffff7fb8367:	83 fb 3b             	cmp    ebx,0x3b
    7ffff7fb836a:	76 c8                	jbe    0x7ffff7fb8334
    7ffff7fb836c:	48 8b 4c 24 10       	mov    rcx,QWORD PTR [rsp+0x10]
    7ffff7fb8371:	4c 89 2c e9          	mov    QWORD PTR [rcx+rbp*8],r13
    7ffff7fb8375:	48 ff c5             	inc    rbp
    7ffff7fb8378:	48 89 6c 24 28       	mov    QWORD PTR [rsp+0x28],rbp
    7ffff7fb837d:	89 d9                	mov    ecx,ebx
    7ffff7fb837f:	f6 d9                	neg    cl
    7ffff7fb8381:	c4 62 f3 f7 e8       	shrx   r13,rax,rcx
    7ffff7fb8386:	83 c3 c4             	add    ebx,0xffffffc4
    7ffff7fb8389:	89 d9                	mov    ecx,ebx
    7ffff7fb838b:	eb a7                	jmp    0x7ffff7fb8334
    7ffff7fb838d:	45 31 ed             	xor    r13d,r13d
    7ffff7fb8390:	e9 92 00 00 00       	jmp    0x7ffff7fb8427
    7ffff7fb8395:	4d 01 e7             	add    r15,r12
    7ffff7fb8398:	31 db                	xor    ebx,ebx
    7ffff7fb839a:	45 31 ed             	xor    r13d,r13d
    7ffff7fb839d:	4d 39 e7             	cmp    r15,r12
    7ffff7fb83a0:	0f 84 8b 00 00 00    	je     0x7ffff7fb8431
    7ffff7fb83a6:	41 8a 47 ff          	mov    al,BYTE PTR [r15-0x1]
    7ffff7fb83aa:	49 ff cf             	dec    r15
    7ffff7fb83ad:	3c 5f                	cmp    al,0x5f
    7ffff7fb83af:	74 ec                	je     0x7ffff7fb839d
    7ffff7fb83b1:	0f b6 f8             	movzx  edi,al
    7ffff7fb83b4:	e8 81 fe ff ff       	call   0x7ffff7fb823a
    7ffff7fb83b9:	a8 01                	test   al,0x1
    7ffff7fb83bb:	0f 84 cf 00 00 00    	je     0x7ffff7fb8490
    7ffff7fb83c1:	89 d0                	mov    eax,edx
    7ffff7fb83c3:	89 d9                	mov    ecx,ebx
    7ffff7fb83c5:	80 e1 3c             	and    cl,0x3c
    7ffff7fb83c8:	c4 e2 f1 f7 c0       	shlx   rax,rax,rcx
    7ffff7fb83cd:	49 09 c5             	or     r13,rax
    7ffff7fb83d0:	83 c3 04             	add    ebx,0x4
    7ffff7fb83d3:	eb c8                	jmp    0x7ffff7fb839d
    7ffff7fb83d5:	85 db                	test   ebx,ebx
    7ffff7fb83d7:	74 11                	je     0x7ffff7fb83ea
    7ffff7fb83d9:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
    7ffff7fb83de:	4c 89 2c e8          	mov    QWORD PTR [rax+rbp*8],r13
    7ffff7fb83e2:	48 ff c5             	inc    rbp
    7ffff7fb83e5:	48 89 6c 24 28       	mov    QWORD PTR [rsp+0x28],rbp
    7ffff7fb83ea:	48 8b 44 24 30       	mov    rax,QWORD PTR [rsp+0x30]
    7ffff7fb83ef:	48 8d 74 24 50       	lea    rsi,[rsp+0x50]
    7ffff7fb83f4:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb83f8:	48 8b 44 24 20       	mov    rax,QWORD PTR [rsp+0x20]
    7ffff7fb83fd:	48 89 06             	mov    QWORD PTR [rsi],rax
    7ffff7fb8400:	48 8b 44 24 28       	mov    rax,QWORD PTR [rsp+0x28]
    7ffff7fb8405:	48 89 46 08          	mov    QWORD PTR [rsi+0x8],rax
    7ffff7fb8409:	4c 8d 7c 24 38       	lea    r15,[rsp+0x38]
    7ffff7fb840e:	4c 89 ff             	mov    rdi,r15
    7ffff7fb8411:	e8 de dd ff ff       	call   0x7ffff7fb61f4
    7ffff7fb8416:	49 8b 47 10          	mov    rax,QWORD PTR [r15+0x10]
    7ffff7fb841a:	45 8a 2f             	mov    r13b,BYTE PTR [r15]
    7ffff7fb841d:	48 85 c0             	test   rax,rax
    7ffff7fb8420:	48 8b 5c 24 08       	mov    rbx,QWORD PTR [rsp+0x8]
    7ffff7fb8425:	75 1d                	jne    0x7ffff7fb8444
    7ffff7fb8427:	44 88 2b             	mov    BYTE PTR [rbx],r13b
    7ffff7fb842a:	48 83 63 10 00       	and    QWORD PTR [rbx+0x10],0x0
    7ffff7fb842f:	eb 41                	jmp    0x7ffff7fb8472
    7ffff7fb8431:	4c 89 6c 24 38       	mov    QWORD PTR [rsp+0x38],r13
    7ffff7fb8436:	48 83 64 24 40 00    	and    QWORD PTR [rsp+0x40],0x0
    7ffff7fb843c:	6a 01                	push   0x1
    7ffff7fb843e:	58                   	pop    rax
    7ffff7fb843f:	48 8b 5c 24 08       	mov    rbx,QWORD PTR [rsp+0x8]
    7ffff7fb8444:	31 d2                	xor    edx,edx
    7ffff7fb8446:	4d 85 f6             	test   r14,r14
    7ffff7fb8449:	0f 95 c2             	setne  dl
    7ffff7fb844c:	48 8b 4c 24 39       	mov    rcx,QWORD PTR [rsp+0x39]
    7ffff7fb8451:	48 8b 7c 24 40       	mov    rdi,QWORD PTR [rsp+0x40]
    7ffff7fb8456:	48 8d 74 24 50       	lea    rsi,[rsp+0x50]
    7ffff7fb845b:	48 89 7e 08          	mov    QWORD PTR [rsi+0x8],rdi
    7ffff7fb845f:	48 89 4e 01          	mov    QWORD PTR [rsi+0x1],rcx
    7ffff7fb8463:	44 88 2e             	mov    BYTE PTR [rsi],r13b
    7ffff7fb8466:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
    7ffff7fb846a:	48 89 df             	mov    rdi,rbx
    7ffff7fb846d:	e8 4d fb ff ff       	call   0x7ffff7fb7fbf
    7ffff7fb8472:	48 83 c4 68          	add    rsp,0x68
    7ffff7fb8476:	5b                   	pop    rbx
    7ffff7fb8477:	41 5c                	pop    r12
    7ffff7fb8479:	41 5d                	pop    r13
    7ffff7fb847b:	41 5e                	pop    r14
    7ffff7fb847d:	41 5f                	pop    r15
    7ffff7fb847f:	5d                   	pop    rbp
    7ffff7fb8480:	c3                   	ret
    7ffff7fb8481:	48 8b 7c 24 10       	mov    rdi,QWORD PTR [rsp+0x10]
    7ffff7fb8486:	48 8b 74 24 18       	mov    rsi,QWORD PTR [rsp+0x18]
    7ffff7fb848b:	e8 e0 de ff ff       	call   0x7ffff7fb6370
    7ffff7fb8490:	41 b5 01             	mov    r13b,0x1
    7ffff7fb8493:	48 8b 5c 24 08       	mov    rbx,QWORD PTR [rsp+0x8]
    7ffff7fb8498:	eb 8d                	jmp    0x7ffff7fb8427
    7ffff7fb849a:	55                   	push   rbp
    7ffff7fb849b:	41 57                	push   r15
    7ffff7fb849d:	41 56                	push   r14
    7ffff7fb849f:	41 55                	push   r13
    7ffff7fb84a1:	41 54                	push   r12
    7ffff7fb84a3:	53                   	push   rbx
    7ffff7fb84a4:	48 83 ec 38          	sub    rsp,0x38
    7ffff7fb84a8:	4c 8b 6e 10          	mov    r13,QWORD PTR [rsi+0x10]
    7ffff7fb84ac:	4c 89 ed             	mov    rbp,r13
    7ffff7fb84af:	48 f7 dd             	neg    rbp
    7ffff7fb84b2:	49 0f 48 ed          	cmovs  rbp,r13
    7ffff7fb84b6:	48 83 fd 03          	cmp    rbp,0x3
    7ffff7fb84ba:	73 0b                	jae    0x7ffff7fb84c7
    7ffff7fb84bc:	c5 f8 10 06          	vmovups xmm0,XMMWORD PTR [rsi]
    7ffff7fb84c0:	c5 f8 29 04 24       	vmovaps XMMWORD PTR [rsp],xmm0
    7ffff7fb84c5:	eb 65                	jmp    0x7ffff7fb852c
    7ffff7fb84c7:	48 8b 06             	mov    rax,QWORD PTR [rsi]
    7ffff7fb84ca:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
    7ffff7fb84cf:	4c 8b 7e 08          	mov    r15,QWORD PTR [rsi+0x8]
    7ffff7fb84d3:	4c 8d 64 24 20       	lea    r12,[rsp+0x20]
    7ffff7fb84d8:	49 89 fe             	mov    r14,rdi
    7ffff7fb84db:	4c 89 e7             	mov    rdi,r12
    7ffff7fb84de:	4c 89 fe             	mov    rsi,r15
    7ffff7fb84e1:	e8 9b de ff ff       	call   0x7ffff7fb6381
    7ffff7fb84e6:	49 8b 5c 24 08       	mov    rbx,QWORD PTR [r12+0x8]
    7ffff7fb84eb:	49 8b 6c 24 10       	mov    rbp,QWORD PTR [r12+0x10]
    7ffff7fb84f0:	48 8d 3c dd 00 00 00 	lea    rdi,[rbx*8+0x0]
    7ffff7fb84f7:	00 
    7ffff7fb84f8:	49 03 3c 24          	add    rdi,QWORD PTR [r12]
    7ffff7fb84fc:	4a 8d 14 fd 00 00 00 	lea    rdx,[r15*8+0x0]
    7ffff7fb8503:	00 
    7ffff7fb8504:	48 8b 74 24 18       	mov    rsi,QWORD PTR [rsp+0x18]
    7ffff7fb8509:	ff 15 59 06 00 00    	call   QWORD PTR [rip+0x659]        # 0x7ffff7fb8b68
    7ffff7fb850f:	4c 89 f7             	mov    rdi,r14
    7ffff7fb8512:	4c 01 fb             	add    rbx,r15
    7ffff7fb8515:	49 89 5c 24 08       	mov    QWORD PTR [r12+0x8],rbx
    7ffff7fb851a:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
    7ffff7fb851e:	48 89 04 24          	mov    QWORD PTR [rsp],rax
    7ffff7fb8522:	49 8b 44 24 08       	mov    rax,QWORD PTR [r12+0x8]
    7ffff7fb8527:	48 89 44 24 08       	mov    QWORD PTR [rsp+0x8],rax
    7ffff7fb852c:	31 d2                	xor    edx,edx
    7ffff7fb852e:	4d 85 ed             	test   r13,r13
    7ffff7fb8531:	0f 9e c2             	setle  dl
    7ffff7fb8534:	48 8b 04 24          	mov    rax,QWORD PTR [rsp]
    7ffff7fb8538:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
    7ffff7fb853d:	48 8d 74 24 20       	lea    rsi,[rsp+0x20]
    7ffff7fb8542:	48 89 06             	mov    QWORD PTR [rsi],rax
    7ffff7fb8545:	48 89 4e 08          	mov    QWORD PTR [rsi+0x8],rcx
    7ffff7fb8549:	48 89 6e 10          	mov    QWORD PTR [rsi+0x10],rbp
    7ffff7fb854d:	e8 6d fa ff ff       	call   0x7ffff7fb7fbf
    7ffff7fb8552:	48 83 c4 38          	add    rsp,0x38
    7ffff7fb8556:	5b                   	pop    rbx
    7ffff7fb8557:	41 5c                	pop    r12
    7ffff7fb8559:	41 5d                	pop    r13
    7ffff7fb855b:	41 5e                	pop    r14
    7ffff7fb855d:	41 5f                	pop    r15
    7ffff7fb855f:	5d                   	pop    rbp
    7ffff7fb8560:	c3                   	ret
    7ffff7fb8561:	53                   	push   rbx
    7ffff7fb8562:	48 89 d0             	mov    rax,rdx
    7ffff7fb8565:	4c 8b 54 24 10       	mov    r10,QWORD PTR [rsp+0x10]
    7ffff7fb856a:	4c 8b 4c 24 18       	mov    r9,QWORD PTR [rsp+0x18]
    7ffff7fb856f:	4c 89 ca             	mov    rdx,r9
    7ffff7fb8572:	c4 e2 f3 f6 d1       	mulx   rdx,rcx,rcx ;mulx
    7ffff7fb8577:	4c 01 d1             	add    rcx,r10
    7ffff7fb857a:	4c 11 ca             	adc    rdx,r9
    7ffff7fb857d:	49 89 d1             	mov    r9,rdx
    7ffff7fb8580:	4c 0f af c8          	imul   r9,rax
    7ffff7fb8584:	4d 29 ca             	sub    r10,r9
    7ffff7fb8587:	c4 62 b3 f6 de       	mulx   r11,r9,rsi ;mulx
    7ffff7fb858c:	49 01 f1             	add    r9,rsi
    7ffff7fb858f:	49 11 c3             	adc    r11,rax
    7ffff7fb8592:	31 db                	xor    ebx,ebx
    7ffff7fb8594:	4d 29 c8             	sub    r8,r9
    7ffff7fb8597:	41 b9 00 00 00 00    	mov    r9d,0x0
    7ffff7fb859d:	4d 19 d9             	sbb    r9,r11
    7ffff7fb85a0:	4d 01 d1             	add    r9,r10
    7ffff7fb85a3:	49 39 c9             	cmp    r9,rcx
    7ffff7fb85a6:	b9 00 00 00 00       	mov    ecx,0x0
    7ffff7fb85ab:	48 19 c9             	sbb    rcx,rcx
    7ffff7fb85ae:	48 29 ca             	sub    rdx,rcx


    # ---------------------------상수 시간 스왑 로직-----------------------------------


    7ffff7fb85b1:	c4 62 f0 f2 d0       	andn   r10,rcx,rax ; r10 = (~rcx) & rax
    7ffff7fb85b6:	c4 e2 f0 f2 ce       	andn   rcx,rcx,rsi ; rcx = (~rcx) & rsi
    7ffff7fb85bb:	4c 01 c1             	add    rcx,r8
    7ffff7fb85be:	4d 11 ca             	adc    r10,r9
    7ffff7fb85c1:	48 39 f1             	cmp    rcx,rsi
    7ffff7fb85c4:	4d 89 d0             	mov    r8,r10
    7ffff7fb85c7:	49 19 c0             	sbb    r8,rax
    7ffff7fb85ca:	48 0f 42 c3          	cmovb  rax,rbx
    7ffff7fb85ce:	48 0f 43 de          	cmovae rbx,rsi
    7ffff7fb85d2:	48 83 da ff          	sbb    rdx,0xffffffffffffffff
    7ffff7fb85d6:	48 29 d9             	sub    rcx,rbx
    7ffff7fb85d9:	49 19 c2             	sbb    r10,rax
    7ffff7fb85dc:	48 89 17             	mov    QWORD PTR [rdi],rdx
    7ffff7fb85df:	48 89 4f 10          	mov    QWORD PTR [rdi+0x10],rcx
    7ffff7fb85e3:	4c 89 57 18          	mov    QWORD PTR [rdi+0x18],r10
    7ffff7fb85e7:	5b                   	pop    rbx
    7ffff7fb85e8:	c3                   	ret
    7ffff7fb85e9:	50                   	push   rax
    7ffff7fb85ea:	48 89 e0             	mov    rax,rsp
    7ffff7fb85ed:	48 89 38             	mov    QWORD PTR [rax],rdi
    7ffff7fb85f0:	48 89 c7             	mov    rdi,rax
    7ffff7fb85f3:	e8 de 00 00 00       	call   0x7ffff7fb86d6
    7ffff7fb85f8:	59                   	pop    rcx
    7ffff7fb85f9:	c3                   	ret
    7ffff7fb85fa:	50                   	push   rax
    7ffff7fb85fb:	48 89 3c 24          	mov    QWORD PTR [rsp],rdi
    7ffff7fb85ff:	48 89 f7             	mov    rdi,rsi
    7ffff7fb8602:	48 89 d6             	mov    rsi,rdx
    7ffff7fb8605:	48 89 ca             	mov    rdx,rcx
    7ffff7fb8608:	e8 3f 00 00 00       	call   0x7ffff7fb864c
    7ffff7fb860d:	59                   	pop    rcx
    7ffff7fb860e:	c3                   	ret
    7ffff7fb860f:	50                   	push   rax
    7ffff7fb8610:	e8 13 00 00 00       	call   0x7ffff7fb8628
    7ffff7fb8615:	59                   	pop    rcx
    7ffff7fb8616:	c3                   	ret
    7ffff7fb8617:	50                   	push   rax
    7ffff7fb8618:	48 89 e0             	mov    rax,rsp
    7ffff7fb861b:	48 89 38             	mov    QWORD PTR [rax],rdi
    7ffff7fb861e:	48 89 c7             	mov    rdi,rax
    7ffff7fb8621:	e8 6a 00 00 00       	call   0x7ffff7fb8690
    7ffff7fb8626:	59                   	pop    rcx
    7ffff7fb8627:	c3                   	ret
    7ffff7fb8628:	31 c0                	xor    eax,eax
    7ffff7fb862a:	31 c9                	xor    ecx,ecx
    7ffff7fb862c:	48 39 ca             	cmp    rdx,rcx
    7ffff7fb862f:	74 1a                	je     0x7ffff7fb864b
    7ffff7fb8631:	44 0f b6 04 0f       	movzx  r8d,BYTE PTR [rdi+rcx*1]
    7ffff7fb8636:	44 0f b6 0c 0e       	movzx  r9d,BYTE PTR [rsi+rcx*1]
    7ffff7fb863b:	45 38 c8             	cmp    r8b,r9b
    7ffff7fb863e:	75 05                	jne    0x7ffff7fb8645
    7ffff7fb8640:	48 ff c1             	inc    rcx
    7ffff7fb8643:	eb e7                	jmp    0x7ffff7fb862c
    7ffff7fb8645:	45 29 c8             	sub    r8d,r9d
    7ffff7fb8648:	44 89 c0             	mov    eax,r8d
    7ffff7fb864b:	c3                   	ret
    7ffff7fb864c:	48 89 f9             	mov    rcx,rdi
    7ffff7fb864f:	49 89 d0             	mov    r8,rdx
    7ffff7fb8652:	49 83 e0 fe          	and    r8,0xfffffffffffffffe
    7ffff7fb8656:	4c 01 c7             	add    rdi,r8
    7ffff7fb8659:	4a 8d 04 06          	lea    rax,[rsi+r8*1]
    7ffff7fb865d:	4d 85 c0             	test   r8,r8
    7ffff7fb8660:	74 18                	je     0x7ffff7fb867a
    7ffff7fb8662:	44 0f b7 09          	movzx  r9d,WORD PTR [rcx]
    7ffff7fb8666:	66 44 3b 0e          	cmp    r9w,WORD PTR [rsi]
    7ffff7fb866a:	75 19                	jne    0x7ffff7fb8685
    7ffff7fb866c:	48 83 c1 02          	add    rcx,0x2
    7ffff7fb8670:	48 83 c6 02          	add    rsi,0x2
    7ffff7fb8674:	49 83 c0 fe          	add    r8,0xfffffffffffffffe
    7ffff7fb8678:	eb e3                	jmp    0x7ffff7fb865d
    7ffff7fb867a:	83 e2 01             	and    edx,0x1
    7ffff7fb867d:	48 89 c6             	mov    rsi,rax
    7ffff7fb8680:	e9 8a ff ff ff       	jmp    0x7ffff7fb860f
    7ffff7fb8685:	6a 02                	push   0x2
    7ffff7fb8687:	5a                   	pop    rdx
    7ffff7fb8688:	48 89 cf             	mov    rdi,rcx
    7ffff7fb868b:	e9 7f ff ff ff       	jmp    0x7ffff7fb860f
    7ffff7fb8690:	48 8b 07             	mov    rax,QWORD PTR [rdi]
    7ffff7fb8693:	48 8b 38             	mov    rdi,QWORD PTR [rax]
    7ffff7fb8696:	49 89 c9             	mov    r9,rcx
    7ffff7fb8699:	49 83 e1 fc          	and    r9,0xfffffffffffffffc
    7ffff7fb869d:	4a 8d 04 0e          	lea    rax,[rsi+r9*1]
    7ffff7fb86a1:	4e 8d 04 0a          	lea    r8,[rdx+r9*1]
    7ffff7fb86a5:	4d 85 c9             	test   r9,r9
    7ffff7fb86a8:	74 16                	je     0x7ffff7fb86c0
    7ffff7fb86aa:	44 8b 16             	mov    r10d,DWORD PTR [rsi]
    7ffff7fb86ad:	44 3b 12             	cmp    r10d,DWORD PTR [rdx]
    7ffff7fb86b0:	75 1c                	jne    0x7ffff7fb86ce
    7ffff7fb86b2:	48 83 c6 04          	add    rsi,0x4
    7ffff7fb86b6:	48 83 c2 04          	add    rdx,0x4
    7ffff7fb86ba:	49 83 c1 fc          	add    r9,0xfffffffffffffffc
    7ffff7fb86be:	eb e5                	jmp    0x7ffff7fb86a5
    7ffff7fb86c0:	83 e1 03             	and    ecx,0x3
    7ffff7fb86c3:	48 89 c6             	mov    rsi,rax
    7ffff7fb86c6:	4c 89 c2             	mov    rdx,r8
    7ffff7fb86c9:	e9 2c ff ff ff       	jmp    0x7ffff7fb85fa
    7ffff7fb86ce:	6a 04                	push   0x4
    7ffff7fb86d0:	59                   	pop    rcx
    7ffff7fb86d1:	e9 24 ff ff ff       	jmp    0x7ffff7fb85fa
    7ffff7fb86d6:	48 8b 07             	mov    rax,QWORD PTR [rdi]
    7ffff7fb86d9:	48 8b 38             	mov    rdi,QWORD PTR [rax]
    7ffff7fb86dc:	49 89 c9             	mov    r9,rcx
    7ffff7fb86df:	49 83 e1 f8          	and    r9,0xfffffffffffffff8
    7ffff7fb86e3:	4a 8d 04 0e          	lea    rax,[rsi+r9*1]
    7ffff7fb86e7:	4e 8d 04 0a          	lea    r8,[rdx+r9*1]
    7ffff7fb86eb:	4d 85 c9             	test   r9,r9
    7ffff7fb86ee:	74 16                	je     0x7ffff7fb8706
    7ffff7fb86f0:	4c 8b 16             	mov    r10,QWORD PTR [rsi]
    7ffff7fb86f3:	4c 3b 12             	cmp    r10,QWORD PTR [rdx]
    7ffff7fb86f6:	75 1c                	jne    0x7ffff7fb8714
    7ffff7fb86f8:	48 83 c6 08          	add    rsi,0x8
    7ffff7fb86fc:	48 83 c2 08          	add    rdx,0x8
    7ffff7fb8700:	49 83 c1 f8          	add    r9,0xfffffffffffffff8
    7ffff7fb8704:	eb e5                	jmp    0x7ffff7fb86eb
    7ffff7fb8706:	83 e1 07             	and    ecx,0x7
    7ffff7fb8709:	48 89 c6             	mov    rsi,rax
    7ffff7fb870c:	4c 89 c2             	mov    rdx,r8
    7ffff7fb870f:	e9 03 ff ff ff       	jmp    0x7ffff7fb8617
    7ffff7fb8714:	6a 08                	push   0x8
    7ffff7fb8716:	59                   	pop    rcx
    7ffff7fb8717:	e9 fb fe ff ff       	jmp    0x7ffff7fb8617
    7ffff7fb871c:	55                   	push   rbp
    7ffff7fb871d:	41 57                	push   r15
    7ffff7fb871f:	41 56                	push   r14
    7ffff7fb8721:	41 55                	push   r13
    7ffff7fb8723:	41 54                	push   r12
    7ffff7fb8725:	53                   	push   rbx
    7ffff7fb8726:	50                   	push   rax
    7ffff7fb8727:	49 89 cc             	mov    r12,rcx
    7ffff7fb872a:	49 89 d7             	mov    r15,rdx
    7ffff7fb872d:	49 89 f6             	mov    r14,rsi
    7ffff7fb8730:	48 89 fb             	mov    rbx,rdi
    7ffff7fb8733:	4d 85 c0             	test   r8,r8
    7ffff7fb8736:	74 77                	je     0x7ffff7fb87af
    7ffff7fb8738:	4d 89 c5             	mov    r13,r8
    7ffff7fb873b:	f3 49 0f bd e8       	lzcnt  rbp,r8
    7ffff7fb8740:	b0 40                	mov    al,0x40
    7ffff7fb8742:	40 28 e8             	sub    al,bpl
    7ffff7fb8745:	0f b6 d0             	movzx  edx,al
    7ffff7fb8748:	4c 89 e7             	mov    rdi,r12
    7ffff7fb874b:	4c 89 c6             	mov    rsi,r8
    7ffff7fb874e:	ff 15 34 04 00 00    	call   QWORD PTR [rip+0x434]        # 0x7ffff7fb8b88
    7ffff7fb8754:	48 89 c1             	mov    rcx,rax
    7ffff7fb8757:	4c 89 f8             	mov    rax,r15
    7ffff7fb875a:	4c 0f a4 f0 3f       	shld   rax,r14,0x3f
    7ffff7fb875f:	4c 89 fa             	mov    rdx,r15
    7ffff7fb8762:	48 d1 ea             	shr    rdx,1
    7ffff7fb8765:	48 f7 f1             	div    rcx
    7ffff7fb8768:	40 f6 d5             	not    bpl
    7ffff7fb876b:	c4 e2 d3 f7 c0       	shrx   rax,rax,rbp
    7ffff7fb8770:	31 c9                	xor    ecx,ecx
    7ffff7fb8772:	48 83 e8 01          	sub    rax,0x1
    7ffff7fb8776:	48 0f 42 c1          	cmovb  rax,rcx
    7ffff7fb877a:	48 89 c6             	mov    rsi,rax
    7ffff7fb877d:	49 0f af f5          	imul   rsi,r13
    7ffff7fb8781:	48 89 c2             	mov    rdx,rax
    7ffff7fb8784:	c4 c2 eb f6 fc       	mulx   rdi,rdx,r12
    7ffff7fb8789:	48 01 f7             	add    rdi,rsi
    7ffff7fb878c:	49 29 d6             	sub    r14,rdx
    7ffff7fb878f:	49 19 ff             	sbb    r15,rdi
    7ffff7fb8792:	4d 39 e6             	cmp    r14,r12
    7ffff7fb8795:	4c 89 fa             	mov    rdx,r15
    7ffff7fb8798:	4c 19 ea             	sbb    rdx,r13
    7ffff7fb879b:	4c 0f 42 e9          	cmovb  r13,rcx
    7ffff7fb879f:	4c 0f 42 e1          	cmovb  r12,rcx
    7ffff7fb87a3:	48 83 d8 ff          	sbb    rax,0xffffffffffffffff
    7ffff7fb87a7:	4d 29 e6             	sub    r14,r12
    7ffff7fb87aa:	4d 19 ef             	sbb    r15,r13
    7ffff7fb87ad:	eb 29                	jmp    0x7ffff7fb87d8
    7ffff7fb87af:	4d 39 e7             	cmp    r15,r12
    7ffff7fb87b2:	73 0d                	jae    0x7ffff7fb87c1
    

    # -------------------------모듈러 감산---------------------------


    7ffff7fb87b4:	4c 89 f0             	mov    rax,r14 ; 나눌 수 (하위)
    7ffff7fb87b7:	4c 89 fa             	mov    rdx,r15 ; 나눌 수 (상위)
    7ffff7fb87ba:	49 f7 f4             	div    r12  ; ★ 핵심! (rdx:rax / r12) = 유한체 소수
    7ffff7fb87bd:	31 c9                	xor    ecx,ecx
    7ffff7fb87bf:	eb 11                	jmp    0x7ffff7fb87d2
    7ffff7fb87c1:	4c 89 f8             	mov    rax,r15
    7ffff7fb87c4:	31 d2                	xor    edx,edx
    7ffff7fb87c6:	49 f7 f4             	div    r12
    7ffff7fb87c9:	48 89 c1             	mov    rcx,rax
    7ffff7fb87cc:	4c 89 f0             	mov    rax,r14
    7ffff7fb87cf:	49 f7 f4             	div    r12
    7ffff7fb87d2:	45 31 ff             	xor    r15d,r15d
    7ffff7fb87d5:	49 89 d6             	mov    r14,rdx  ; rdx는 나머지(Remainder) -> r14에 저장
    7ffff7fb87d8:	48 89 03             	mov    QWORD PTR [rbx],rax
    7ffff7fb87db:	48 89 4b 08          	mov    QWORD PTR [rbx+0x8],rcx
    7ffff7fb87df:	4c 89 73 10          	mov    QWORD PTR [rbx+0x10],r14
    7ffff7fb87e3:	4c 89 7b 18          	mov    QWORD PTR [rbx+0x18],r15
    7ffff7fb87e7:	48 89 d8             	mov    rax,rbx
    7ffff7fb87ea:	48 83 c4 08          	add    rsp,0x8
    7ffff7fb87ee:	5b                   	pop    rbx
    7ffff7fb87ef:	41 5c                	pop    r12
    7ffff7fb87f1:	41 5d                	pop    r13
    7ffff7fb87f3:	41 5e                	pop    r14
    7ffff7fb87f5:	41 5f                	pop    r15
    7ffff7fb87f7:	5d                   	pop    rbp
    7ffff7fb87f8:	c3                   	ret
    7ffff7fb87f9:	89 d1                	mov    ecx,edx
    7ffff7fb87fb:	48 89 f8             	mov    rax,rdi
    7ffff7fb87fe:	f6 c1 40             	test   cl,0x40
    7ffff7fb8801:	75 1f                	jne    0x7ffff7fb8822
    7ffff7fb8803:	48 89 f2             	mov    rdx,rsi
    7ffff7fb8806:	85 c9                	test   ecx,ecx
    7ffff7fb8808:	74 17                	je     0x7ffff7fb8821
    7ffff7fb880a:	89 ce                	mov    esi,ecx
    7ffff7fb880c:	40 f6 de             	neg    sil
    7ffff7fb880f:	c4 e2 cb f7 f0       	shrx   rsi,rax,rsi
    7ffff7fb8814:	c4 e2 f1 f7 c0       	shlx   rax,rax,rcx
    7ffff7fb8819:	c4 e2 f1 f7 d2       	shlx   rdx,rdx,rcx
    7ffff7fb881e:	48 09 f2             	or     rdx,rsi ; 결과 결합


    # ---------------------------------------------------------------------


    7ffff7fb8821:	c3                   	ret
    7ffff7fb8822:	c4 e2 f1 f7 d0       	shlx   rdx,rax,rcx
    7ffff7fb8827:	31 c0                	xor    eax,eax
    7ffff7fb8829:	c3                   	ret
    7ffff7fb882a:	e9 ca ff ff ff       	jmp    0x7ffff7fb87f9
    7ffff7fb882f:	89 d1                	mov    ecx,edx
    7ffff7fb8831:	48 89 f2             	mov    rdx,rsi
    7ffff7fb8834:	f6 c1 40             	test   cl,0x40
    7ffff7fb8837:	75 1e                	jne    0x7ffff7fb8857
    7ffff7fb8839:	48 89 f8             	mov    rax,rdi
    7ffff7fb883c:	85 c9                	test   ecx,ecx
    7ffff7fb883e:	74 16                	je     0x7ffff7fb8856
    7ffff7fb8840:	c4 e2 f3 f7 f0       	shrx   rsi,rax,rcx
    7ffff7fb8845:	89 c8                	mov    eax,ecx
    7ffff7fb8847:	f6 d8                	neg    al
    7ffff7fb8849:	c4 e2 f9 f7 c2       	shlx   rax,rdx,rax
    7ffff7fb884e:	48 09 f0             	or     rax,rsi
    7ffff7fb8851:	c4 e2 f3 f7 d2       	shrx   rdx,rdx,rcx
    7ffff7fb8856:	c3                   	ret
    7ffff7fb8857:	c4 e2 f3 f7 c2       	shrx   rax,rdx,rcx
    7ffff7fb885c:	31 d2                	xor    edx,edx
    7ffff7fb885e:	c3                   	ret
    7ffff7fb885f:	e9 cb ff ff ff       	jmp    0x7ffff7fb882f
    7ffff7fb8864:	53                   	push   rbx
    7ffff7fb8865:	48 83 ec 20          	sub    rsp,0x20
    7ffff7fb8869:	49 89 c8             	mov    r8,rcx
    7ffff7fb886c:	48 89 d1             	mov    rcx,rdx
    7ffff7fb886f:	48 89 f2             	mov    rdx,rsi
    7ffff7fb8872:	48 89 fe             	mov    rsi,rdi
    7ffff7fb8875:	48 89 e3             	mov    rbx,rsp
    7ffff7fb8878:	48 89 df             	mov    rdi,rbx
    7ffff7fb887b:	e8 9c fe ff ff       	call   0x7ffff7fb871c
    7ffff7fb8880:	48 8b 03             	mov    rax,QWORD PTR [rbx]
    7ffff7fb8883:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
    7ffff7fb8887:	48 83 c4 20          	add    rsp,0x20
    7ffff7fb888b:	5b                   	pop    rbx
    7ffff7fb888c:	c3                   	ret
    7ffff7fb888d:	e9 d2 ff ff ff       	jmp    0x7ffff7fb8864
    7ffff7fb8892:	53                   	push   rbx
    7ffff7fb8893:	48 83 ec 20          	sub    rsp,0x20
    7ffff7fb8897:	49 89 c8             	mov    r8,rcx
    7ffff7fb889a:	48 89 d1             	mov    rcx,rdx
    7ffff7fb889d:	48 89 f2             	mov    rdx,rsi
    7ffff7fb88a0:	48 89 fe             	mov    rsi,rdi
    7ffff7fb88a3:	48 89 e3             	mov    rbx,rsp
    7ffff7fb88a6:	48 89 df             	mov    rdi,rbx
    7ffff7fb88a9:	e8 6e fe ff ff       	call   0x7ffff7fb871c
    7ffff7fb88ae:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
    7ffff7fb88b2:	48 8b 53 18          	mov    rdx,QWORD PTR [rbx+0x18]
    7ffff7fb88b6:	48 83 c4 20          	add    rsp,0x20
    7ffff7fb88ba:	5b                   	pop    rbx
    7ffff7fb88bb:	c3                   	ret
    7ffff7fb88bc:	e9 d1 ff ff ff       	jmp    0x7ffff7fb8892
    7ffff7fb88c1:	48 89 d1             	mov    rcx,rdx
    7ffff7fb88c4:	48 89 f8             	mov    rax,rdi
    7ffff7fb88c7:	f3 a4                	rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]
    7ffff7fb88c9:	c3                   	ret
    7ffff7fb88ca:	48 89 f8             	mov    rax,rdi
    7ffff7fb88cd:	48 89 f9             	mov    rcx,rdi
    7ffff7fb88d0:	48 29 f1             	sub    rcx,rsi
    7ffff7fb88d3:	48 39 d1             	cmp    rcx,rdx
    7ffff7fb88d6:	73 51                	jae    0x7ffff7fb8929
    7ffff7fb88d8:	41 89 c0             	mov    r8d,eax
    7ffff7fb88db:	41 f7 d8             	neg    r8d
    7ffff7fb88de:	41 83 e0 07          	and    r8d,0x7
    7ffff7fb88e2:	49 39 d0             	cmp    r8,rdx
    7ffff7fb88e5:	4c 0f 43 c2          	cmovae r8,rdx
    7ffff7fb88e9:	48 89 d1             	mov    rcx,rdx
    7ffff7fb88ec:	4c 29 c1             	sub    rcx,r8
    7ffff7fb88ef:	49 89 c9             	mov    r9,rcx
    7ffff7fb88f2:	49 c1 e9 03          	shr    r9,0x3
    7ffff7fb88f6:	83 e1 07             	and    ecx,0x7
    7ffff7fb88f9:	48 8d 3c 10          	lea    rdi,[rax+rdx*1]
    7ffff7fb88fd:	48 ff cf             	dec    rdi
    7ffff7fb8900:	48 01 d6             	add    rsi,rdx
    7ffff7fb8903:	48 ff ce             	dec    rsi
    7ffff7fb8906:	fd                   	std
    7ffff7fb8907:	f3 a4                	rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]
    7ffff7fb8909:	48 83 ee 07          	sub    rsi,0x7
    7ffff7fb890d:	48 83 ef 07          	sub    rdi,0x7
    7ffff7fb8911:	4c 89 c9             	mov    rcx,r9
    7ffff7fb8914:	f3 48 a5             	rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]
    7ffff7fb8917:	45 85 c0             	test   r8d,r8d
    7ffff7fb891a:	48 83 c6 07          	add    rsi,0x7
    7ffff7fb891e:	48 83 c7 07          	add    rdi,0x7
    7ffff7fb8922:	44 89 c1             	mov    ecx,r8d
    7ffff7fb8925:	f3 a4                	rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]
    7ffff7fb8927:	fc                   	cld
    7ffff7fb8928:	c3                   	ret
    7ffff7fb8929:	48 89 c7             	mov    rdi,rax
    7ffff7fb892c:	48 89 d1             	mov    rcx,rdx
    7ffff7fb892f:	f3 a4                	rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]
    7ffff7fb8931:	c3                   	ret
    7ffff7fb8932:	e9 93 ff ff ff       	jmp    0x7ffff7fb88ca
    7ffff7fb8937:	48 83 ec 18          	sub    rsp,0x18
    7ffff7fb893b:	48 89 d1             	mov    rcx,rdx
    7ffff7fb893e:	49 89 f0             	mov    r8,rsi
    7ffff7fb8941:	48 89 f8             	mov    rax,rdi
    7ffff7fb8944:	48 8d 54 24 07       	lea    rdx,[rsp+0x7]
    7ffff7fb8949:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
    7ffff7fb894e:	48 89 16             	mov    QWORD PTR [rsi],rdx
    7ffff7fb8951:	48 89 74 24 08       	mov    QWORD PTR [rsp+0x8],rsi
    7ffff7fb8956:	48 89 cf             	mov    rdi,rcx
    7ffff7fb8959:	48 83 e7 f0          	and    rdi,0xfffffffffffffff0
    7ffff7fb895d:	48 8d 34 38          	lea    rsi,[rax+rdi*1]
    7ffff7fb8961:	49 8d 14 38          	lea    rdx,[r8+rdi*1]
    7ffff7fb8965:	48 85 ff             	test   rdi,rdi
    7ffff7fb8968:	74 1e                	je     0x7ffff7fb8988
    7ffff7fb896a:	c5 fa 6f 00          	vmovdqu xmm0,XMMWORD PTR [rax]
    7ffff7fb896e:	c4 c1 79 ef 00       	vpxor  xmm0,xmm0,XMMWORD PTR [r8]
    7ffff7fb8973:	c4 e2 79 17 c0       	vptest xmm0,xmm0
    7ffff7fb8978:	75 18                	jne    0x7ffff7fb8992
    7ffff7fb897a:	48 83 c0 10          	add    rax,0x10
    7ffff7fb897e:	49 83 c0 10          	add    r8,0x10
    7ffff7fb8982:	48 83 c7 f0          	add    rdi,0xfffffffffffffff0
    7ffff7fb8986:	eb dd                	jmp    0x7ffff7fb8965
    7ffff7fb8988:	83 e1 0f             	and    ecx,0xf
    7ffff7fb898b:	48 8d 7c 24 08       	lea    rdi,[rsp+0x8]
    7ffff7fb8990:	eb 0e                	jmp    0x7ffff7fb89a0
    7ffff7fb8992:	48 8d 7c 24 08       	lea    rdi,[rsp+0x8]
    7ffff7fb8997:	6a 10                	push   0x10
    7ffff7fb8999:	59                   	pop    rcx
    7ffff7fb899a:	48 89 c6             	mov    rsi,rax
    7ffff7fb899d:	4c 89 c2             	mov    rdx,r8
    7ffff7fb89a0:	e8 44 fc ff ff       	call   0x7ffff7fb85e9
    7ffff7fb89a5:	48 83 c4 18          	add    rsp,0x18
    7ffff7fb89a9:	c3                   	ret
    7ffff7fb89aa:	e9 88 ff ff ff       	jmp    0x7ffff7fb8937
    7ffff7fb89af:	e9 83 ff ff ff       	jmp    0x7ffff7fb8937
	...
    7ffff7fb8a38:	78 f3                	js     0x7ffff7fb8a2d
    7ffff7fb8a3a:	fa                   	cli
    7ffff7fb8a3b:	f7 ff                	idiv   edi
    7ffff7fb8a3d:	7f 00                	jg     0x7ffff7fb8a3f
    7ffff7fb8a3f:	00 20                	add    BYTE PTR [rax],ah
    7ffff7fb8a41:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a43:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a45:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a47:	00 38                	add    BYTE PTR [rax],bh
    7ffff7fb8a49:	f3 fa                	repz cli
    7ffff7fb8a4b:	f7 ff                	idiv   edi
    7ffff7fb8a4d:	7f 00                	jg     0x7ffff7fb8a4f
    7ffff7fb8a4f:	00 20                	add    BYTE PTR [rax],ah
    7ffff7fb8a51:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a53:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a55:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a57:	00 18                	add    BYTE PTR [rax],bl
    7ffff7fb8a59:	f3 fa                	repz cli
    7ffff7fb8a5b:	f7 ff                	idiv   edi
    7ffff7fb8a5d:	7f 00                	jg     0x7ffff7fb8a5f
    7ffff7fb8a5f:	00 20                	add    BYTE PTR [rax],ah
    7ffff7fb8a61:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a63:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a65:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a67:	00 f8                	add    al,bh
    7ffff7fb8a69:	f2 fa                	repnz cli
    7ffff7fb8a6b:	f7 ff                	idiv   edi
    7ffff7fb8a6d:	7f 00                	jg     0x7ffff7fb8a6f
    7ffff7fb8a6f:	00 20                	add    BYTE PTR [rax],ah
    7ffff7fb8a71:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a73:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a75:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a77:	00 8b 36 fb f7 ff    	add    BYTE PTR [rbx-0x804ca],cl
    7ffff7fb8a7d:	7f 00                	jg     0x7ffff7fb8a7f
    7ffff7fb8a7f:	00 99 36 fb f7 ff    	add    BYTE PTR [rcx-0x804ca],bl
    7ffff7fb8a85:	7f 00                	jg     0x7ffff7fb8a87
    7ffff7fb8a87:	00 9e 36 fb f7 ff    	add    BYTE PTR [rsi-0x804ca],bl
    7ffff7fb8a8d:	7f 00                	jg     0x7ffff7fb8a8f
    7ffff7fb8a8f:	00 43 32             	add    BYTE PTR [rbx+0x32],al
    7ffff7fb8a92:	fb                   	sti
    7ffff7fb8a93:	f7 ff                	idiv   edi
    7ffff7fb8a95:	7f 00                	jg     0x7ffff7fb8a97
    7ffff7fb8a97:	00 07                	add    BYTE PTR [rdi],al
    7ffff7fb8a99:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a9b:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a9d:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8a9f:	00 70 02             	add    BYTE PTR [rax+0x2],dh
    7ffff7fb8aa2:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8aa4:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8aa6:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8aa8:	08 00                	or     BYTE PTR [rax],al
    7ffff7fb8aaa:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8aac:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8aae:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8ab0:	80 01 00             	add    BYTE PTR [rcx],0x0
    7ffff7fb8ab3:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8ab5:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8ab7:	00 09                	add    BYTE PTR [rcx],cl
    7ffff7fb8ab9:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8abb:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8abd:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8abf:	00 18                	add    BYTE PTR [rax],bl
	...
    7ffff7fb8b65:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8b67:	00 c1                	add    cl,al
    7ffff7fb8b69:	88 fb                	mov    bl,bh
    7ffff7fb8b6b:	f7 ff                	idiv   edi
    7ffff7fb8b6d:	7f 00                	jg     0x7ffff7fb8b6f
    7ffff7fb8b6f:	00 bc 88 fb f7 ff 7f 	add    BYTE PTR [rax+rcx*4+0x7ffff7fb],bh
    7ffff7fb8b76:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8b78:	8d 88 fb f7 ff 7f    	lea    ecx,[rax+0x7ffff7fb]
    7ffff7fb8b7e:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8b80:	2a 88 fb f7 ff 7f    	sub    cl,BYTE PTR [rax+0x7ffff7fb]
    7ffff7fb8b86:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8b88:	5f                   	pop    rdi
    7ffff7fb8b89:	88 fb                	mov    bl,bh
    7ffff7fb8b8b:	f7 ff                	idiv   edi
    7ffff7fb8b8d:	7f 00                	jg     0x7ffff7fb8b8f
    7ffff7fb8b8f:	00 aa 89 fb f7 ff    	add    BYTE PTR [rdx-0x80477],ch
    7ffff7fb8b95:	7f 00                	jg     0x7ffff7fb8b97
    7ffff7fb8b97:	00 32                	add    BYTE PTR [rdx],dh
    7ffff7fb8b99:	89 fb                	mov    ebx,edi
    7ffff7fb8b9b:	f7 ff                	idiv   edi
    7ffff7fb8b9d:	7f 00                	jg     0x7ffff7fb8b9f
    7ffff7fb8b9f:	00 af 89 fb f7 ff    	add    BYTE PTR [rdi-0x80477],ch
    7ffff7fb8ba5:	7f 00                	jg     0x7ffff7fb8ba7
	...
    7ffff7fb8ca7:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8ca9:	d0 f8                	sar    al,1
    7ffff7fb8cab:	f7 ff                	idiv   edi
    7ffff7fb8cad:	7f 00                	jg     0x7ffff7fb8caf
    7ffff7fb8caf:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8cb1:	00 01                	add    BYTE PTR [rcx],al
	...
    7ffff7fb8cd7:	00 c8                	add    al,cl
    7ffff7fb8cd9:	8c fb                	mov    ebx,?
    7ffff7fb8cdb:	f7 ff                	idiv   edi
    7ffff7fb8cdd:	7f 00                	jg     0x7ffff7fb8cdf
    7ffff7fb8cdf:	00 c8                	add    al,cl
    7ffff7fb8ce1:	8c fb                	mov    ebx,?
    7ffff7fb8ce3:	f7 ff                	idiv   edi
    7ffff7fb8ce5:	7f 00                	jg     0x7ffff7fb8ce7
    7ffff7fb8ce7:	00 d8                	add    al,bl
    7ffff7fb8ce9:	8c fb                	mov    ebx,?
    7ffff7fb8ceb:	f7 ff                	idiv   edi
    7ffff7fb8ced:	7f 00                	jg     0x7ffff7fb8cef
    7ffff7fb8cef:	00 d8                	add    al,bl
    7ffff7fb8cf1:	8c fb                	mov    ebx,?
    7ffff7fb8cf3:	f7 ff                	idiv   edi
    7ffff7fb8cf5:	7f 00                	jg     0x7ffff7fb8cf7
    7ffff7fb8cf7:	00 e8                	add    al,ch
    7ffff7fb8cf9:	8c fb                	mov    ebx,?
    7ffff7fb8cfb:	f7 ff                	idiv   edi
    7ffff7fb8cfd:	7f 00                	jg     0x7ffff7fb8cff
    7ffff7fb8cff:	00 e8                	add    al,ch
    7ffff7fb8d01:	8c fb                	mov    ebx,?
    7ffff7fb8d03:	f7 ff                	idiv   edi
    7ffff7fb8d05:	7f 00                	jg     0x7ffff7fb8d07
    7ffff7fb8d07:	00 f8                	add    al,bh
    7ffff7fb8d09:	8c fb                	mov    ebx,?
    7ffff7fb8d0b:	f7 ff                	idiv   edi
    7ffff7fb8d0d:	7f 00                	jg     0x7ffff7fb8d0f
    7ffff7fb8d0f:	00 f8                	add    al,bh
    7ffff7fb8d11:	8c fb                	mov    ebx,?
    7ffff7fb8d13:	f7 ff                	idiv   edi
    7ffff7fb8d15:	7f 00                	jg     0x7ffff7fb8d17
    7ffff7fb8d17:	00 08                	add    BYTE PTR [rax],cl
    7ffff7fb8d19:	8d                   	lea    edi,(bad)
    7ffff7fb8d1a:	fb                   	sti
    7ffff7fb8d1b:	f7 ff                	idiv   edi
    7ffff7fb8d1d:	7f 00                	jg     0x7ffff7fb8d1f
    7ffff7fb8d1f:	00 08                	add    BYTE PTR [rax],cl
    7ffff7fb8d21:	8d                   	lea    edi,(bad)
    7ffff7fb8d22:	fb                   	sti
    7ffff7fb8d23:	f7 ff                	idiv   edi
    7ffff7fb8d25:	7f 00                	jg     0x7ffff7fb8d27
    7ffff7fb8d27:	00 18                	add    BYTE PTR [rax],bl
    7ffff7fb8d29:	8d                   	lea    edi,(bad)
    7ffff7fb8d2a:	fb                   	sti
    7ffff7fb8d2b:	f7 ff                	idiv   edi
    7ffff7fb8d2d:	7f 00                	jg     0x7ffff7fb8d2f
    7ffff7fb8d2f:	00 18                	add    BYTE PTR [rax],bl
    7ffff7fb8d31:	8d                   	lea    edi,(bad)
    7ffff7fb8d32:	fb                   	sti
    7ffff7fb8d33:	f7 ff                	idiv   edi
    7ffff7fb8d35:	7f 00                	jg     0x7ffff7fb8d37
    7ffff7fb8d37:	00 60 d1             	add    BYTE PTR [rax-0x2f],ah
    7ffff7fb8d3a:	f8                   	clc
    7ffff7fb8d3b:	f7 ff                	idiv   edi
    7ffff7fb8d3d:	7f 00                	jg     0x7ffff7fb8d3f
    7ffff7fb8d3f:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8d41:	d0 f8                	sar    al,1
    7ffff7fb8d43:	f7 ff                	idiv   edi
    7ffff7fb8d45:	7f 00                	jg     0x7ffff7fb8d47
    7ffff7fb8d47:	00 38                	add    BYTE PTR [rax],bh
    7ffff7fb8d49:	8d                   	lea    edi,(bad)
    7ffff7fb8d4a:	fb                   	sti
    7ffff7fb8d4b:	f7 ff                	idiv   edi
    7ffff7fb8d4d:	7f 00                	jg     0x7ffff7fb8d4f
    7ffff7fb8d4f:	00 38                	add    BYTE PTR [rax],bh
    7ffff7fb8d51:	8d                   	lea    edi,(bad)
    7ffff7fb8d52:	fb                   	sti
    7ffff7fb8d53:	f7 ff                	idiv   edi
    7ffff7fb8d55:	7f 00                	jg     0x7ffff7fb8d57
    7ffff7fb8d57:	00 d0                	add    al,dl
    7ffff7fb8d59:	d0 f8                	sar    al,1
    7ffff7fb8d5b:	f7 ff                	idiv   edi
    7ffff7fb8d5d:	7f 00                	jg     0x7ffff7fb8d5f
    7ffff7fb8d5f:	00 d0                	add    al,dl
    7ffff7fb8d61:	d0 f8                	sar    al,1
    7ffff7fb8d63:	f7 ff                	idiv   edi
    7ffff7fb8d65:	7f 00                	jg     0x7ffff7fb8d67
    7ffff7fb8d67:	00 58 8d             	add    BYTE PTR [rax-0x73],bl
    7ffff7fb8d6a:	fb                   	sti
    7ffff7fb8d6b:	f7 ff                	idiv   edi
    7ffff7fb8d6d:	7f 00                	jg     0x7ffff7fb8d6f
    7ffff7fb8d6f:	00 58 8d             	add    BYTE PTR [rax-0x73],bl
    7ffff7fb8d72:	fb                   	sti
    7ffff7fb8d73:	f7 ff                	idiv   edi
    7ffff7fb8d75:	7f 00                	jg     0x7ffff7fb8d77
    7ffff7fb8d77:	00 68 8d             	add    BYTE PTR [rax-0x73],ch
    7ffff7fb8d7a:	fb                   	sti
    7ffff7fb8d7b:	f7 ff                	idiv   edi
    7ffff7fb8d7d:	7f 00                	jg     0x7ffff7fb8d7f
    7ffff7fb8d7f:	00 68 8d             	add    BYTE PTR [rax-0x73],ch
    7ffff7fb8d82:	fb                   	sti
    7ffff7fb8d83:	f7 ff                	idiv   edi
    7ffff7fb8d85:	7f 00                	jg     0x7ffff7fb8d87
    7ffff7fb8d87:	00 78 8d             	add    BYTE PTR [rax-0x73],bh
    7ffff7fb8d8a:	fb                   	sti
    7ffff7fb8d8b:	f7 ff                	idiv   edi
    7ffff7fb8d8d:	7f 00                	jg     0x7ffff7fb8d8f
    7ffff7fb8d8f:	00 78 8d             	add    BYTE PTR [rax-0x73],bh
    7ffff7fb8d92:	fb                   	sti
    7ffff7fb8d93:	f7 ff                	idiv   edi
    7ffff7fb8d95:	7f 00                	jg     0x7ffff7fb8d97
    7ffff7fb8d97:	00 88 8d fb f7 ff    	add    BYTE PTR [rax-0x80473],cl
    7ffff7fb8d9d:	7f 00                	jg     0x7ffff7fb8d9f
    7ffff7fb8d9f:	00 88 8d fb f7 ff    	add    BYTE PTR [rax-0x80473],cl
    7ffff7fb8da5:	7f 00                	jg     0x7ffff7fb8da7
    7ffff7fb8da7:	00 98 8d fb f7 ff    	add    BYTE PTR [rax-0x80473],bl
    7ffff7fb8dad:	7f 00                	jg     0x7ffff7fb8daf
    7ffff7fb8daf:	00 98 8d fb f7 ff    	add    BYTE PTR [rax-0x80473],bl
    7ffff7fb8db5:	7f 00                	jg     0x7ffff7fb8db7
    7ffff7fb8db7:	00 a8 8d fb f7 ff    	add    BYTE PTR [rax-0x80473],ch
    7ffff7fb8dbd:	7f 00                	jg     0x7ffff7fb8dbf
    7ffff7fb8dbf:	00 a8 8d fb f7 ff    	add    BYTE PTR [rax-0x80473],ch
    7ffff7fb8dc5:	7f 00                	jg     0x7ffff7fb8dc7
    7ffff7fb8dc7:	00 b8 8d fb f7 ff    	add    BYTE PTR [rax-0x80473],bh
    7ffff7fb8dcd:	7f 00                	jg     0x7ffff7fb8dcf
    7ffff7fb8dcf:	00 b8 8d fb f7 ff    	add    BYTE PTR [rax-0x80473],bh
    7ffff7fb8dd5:	7f 00                	jg     0x7ffff7fb8dd7
    7ffff7fb8dd7:	00 90 d0 f8 f7 ff    	add    BYTE PTR [rax-0x80730],dl
    7ffff7fb8ddd:	7f 00                	jg     0x7ffff7fb8ddf
    7ffff7fb8ddf:	00 90 d0 f8 f7 ff    	add    BYTE PTR [rax-0x80730],dl
    7ffff7fb8de5:	7f 00                	jg     0x7ffff7fb8de7
    7ffff7fb8de7:	00 d8                	add    al,bl
    7ffff7fb8de9:	8d                   	lea    edi,(bad)
    7ffff7fb8dea:	fb                   	sti
    7ffff7fb8deb:	f7 ff                	idiv   edi
    7ffff7fb8ded:	7f 00                	jg     0x7ffff7fb8def
    7ffff7fb8def:	00 d8                	add    al,bl
    7ffff7fb8df1:	8d                   	lea    edi,(bad)
    7ffff7fb8df2:	fb                   	sti
    7ffff7fb8df3:	f7 ff                	idiv   edi
    7ffff7fb8df5:	7f 00                	jg     0x7ffff7fb8df7
    7ffff7fb8df7:	00 e8                	add    al,ch
    7ffff7fb8df9:	8d                   	lea    edi,(bad)
    7ffff7fb8dfa:	fb                   	sti
    7ffff7fb8dfb:	f7 ff                	idiv   edi
    7ffff7fb8dfd:	7f 00                	jg     0x7ffff7fb8dff
    7ffff7fb8dff:	00 e8                	add    al,ch
    7ffff7fb8e01:	8d                   	lea    edi,(bad)
    7ffff7fb8e02:	fb                   	sti
    7ffff7fb8e03:	f7 ff                	idiv   edi
    7ffff7fb8e05:	7f 00                	jg     0x7ffff7fb8e07
    7ffff7fb8e07:	00 f8                	add    al,bh
    7ffff7fb8e09:	8d                   	lea    edi,(bad)
    7ffff7fb8e0a:	fb                   	sti
    7ffff7fb8e0b:	f7 ff                	idiv   edi
    7ffff7fb8e0d:	7f 00                	jg     0x7ffff7fb8e0f
    7ffff7fb8e0f:	00 f8                	add    al,bh
    7ffff7fb8e11:	8d                   	lea    edi,(bad)
    7ffff7fb8e12:	fb                   	sti
    7ffff7fb8e13:	f7 ff                	idiv   edi
    7ffff7fb8e15:	7f 00                	jg     0x7ffff7fb8e17
    7ffff7fb8e17:	00 08                	add    BYTE PTR [rax],cl
    7ffff7fb8e19:	8e fb                	mov    ?,ebx
    7ffff7fb8e1b:	f7 ff                	idiv   edi
    7ffff7fb8e1d:	7f 00                	jg     0x7ffff7fb8e1f
    7ffff7fb8e1f:	00 08                	add    BYTE PTR [rax],cl
    7ffff7fb8e21:	8e fb                	mov    ?,ebx
    7ffff7fb8e23:	f7 ff                	idiv   edi
    7ffff7fb8e25:	7f 00                	jg     0x7ffff7fb8e27
    7ffff7fb8e27:	00 18                	add    BYTE PTR [rax],bl
    7ffff7fb8e29:	8e fb                	mov    ?,ebx
    7ffff7fb8e2b:	f7 ff                	idiv   edi
    7ffff7fb8e2d:	7f 00                	jg     0x7ffff7fb8e2f
    7ffff7fb8e2f:	00 18                	add    BYTE PTR [rax],bl
    7ffff7fb8e31:	8e fb                	mov    ?,ebx
    7ffff7fb8e33:	f7 ff                	idiv   edi
    7ffff7fb8e35:	7f 00                	jg     0x7ffff7fb8e37
    7ffff7fb8e37:	00 28                	add    BYTE PTR [rax],ch
    7ffff7fb8e39:	8e fb                	mov    ?,ebx
    7ffff7fb8e3b:	f7 ff                	idiv   edi
    7ffff7fb8e3d:	7f 00                	jg     0x7ffff7fb8e3f
    7ffff7fb8e3f:	00 28                	add    BYTE PTR [rax],ch
    7ffff7fb8e41:	8e fb                	mov    ?,ebx
    7ffff7fb8e43:	f7 ff                	idiv   edi
    7ffff7fb8e45:	7f 00                	jg     0x7ffff7fb8e47
    7ffff7fb8e47:	00 38                	add    BYTE PTR [rax],bh
    7ffff7fb8e49:	8e fb                	mov    ?,ebx
    7ffff7fb8e4b:	f7 ff                	idiv   edi
    7ffff7fb8e4d:	7f 00                	jg     0x7ffff7fb8e4f
    7ffff7fb8e4f:	00 38                	add    BYTE PTR [rax],bh
    7ffff7fb8e51:	8e fb                	mov    ?,ebx
    7ffff7fb8e53:	f7 ff                	idiv   edi
    7ffff7fb8e55:	7f 00                	jg     0x7ffff7fb8e57
    7ffff7fb8e57:	00 48 8e             	add    BYTE PTR [rax-0x72],cl
    7ffff7fb8e5a:	fb                   	sti
    7ffff7fb8e5b:	f7 ff                	idiv   edi
    7ffff7fb8e5d:	7f 00                	jg     0x7ffff7fb8e5f
    7ffff7fb8e5f:	00 48 8e             	add    BYTE PTR [rax-0x72],cl
    7ffff7fb8e62:	fb                   	sti
    7ffff7fb8e63:	f7 ff                	idiv   edi
    7ffff7fb8e65:	7f 00                	jg     0x7ffff7fb8e67
    7ffff7fb8e67:	00 58 8e             	add    BYTE PTR [rax-0x72],bl
    7ffff7fb8e6a:	fb                   	sti
    7ffff7fb8e6b:	f7 ff                	idiv   edi
    7ffff7fb8e6d:	7f 00                	jg     0x7ffff7fb8e6f
    7ffff7fb8e6f:	00 58 8e             	add    BYTE PTR [rax-0x72],bl
    7ffff7fb8e72:	fb                   	sti
    7ffff7fb8e73:	f7 ff                	idiv   edi
    7ffff7fb8e75:	7f 00                	jg     0x7ffff7fb8e77
    7ffff7fb8e77:	00 68 8e             	add    BYTE PTR [rax-0x72],ch
    7ffff7fb8e7a:	fb                   	sti
    7ffff7fb8e7b:	f7 ff                	idiv   edi
    7ffff7fb8e7d:	7f 00                	jg     0x7ffff7fb8e7f
    7ffff7fb8e7f:	00 68 8e             	add    BYTE PTR [rax-0x72],ch
    7ffff7fb8e82:	fb                   	sti
    7ffff7fb8e83:	f7 ff                	idiv   edi
    7ffff7fb8e85:	7f 00                	jg     0x7ffff7fb8e87
    7ffff7fb8e87:	00 78 8e             	add    BYTE PTR [rax-0x72],bh
    7ffff7fb8e8a:	fb                   	sti
    7ffff7fb8e8b:	f7 ff                	idiv   edi
    7ffff7fb8e8d:	7f 00                	jg     0x7ffff7fb8e8f
    7ffff7fb8e8f:	00 78 8e             	add    BYTE PTR [rax-0x72],bh
    7ffff7fb8e92:	fb                   	sti
    7ffff7fb8e93:	f7 ff                	idiv   edi
    7ffff7fb8e95:	7f 00                	jg     0x7ffff7fb8e97
    7ffff7fb8e97:	00 88 8e fb f7 ff    	add    BYTE PTR [rax-0x80472],cl
    7ffff7fb8e9d:	7f 00                	jg     0x7ffff7fb8e9f
    7ffff7fb8e9f:	00 88 8e fb f7 ff    	add    BYTE PTR [rax-0x80472],cl
    7ffff7fb8ea5:	7f 00                	jg     0x7ffff7fb8ea7
    7ffff7fb8ea7:	00 98 8e fb f7 ff    	add    BYTE PTR [rax-0x80472],bl
    7ffff7fb8ead:	7f 00                	jg     0x7ffff7fb8eaf
    7ffff7fb8eaf:	00 98 8e fb f7 ff    	add    BYTE PTR [rax-0x80472],bl
    7ffff7fb8eb5:	7f 00                	jg     0x7ffff7fb8eb7
    7ffff7fb8eb7:	00 a8 8e fb f7 ff    	add    BYTE PTR [rax-0x80472],ch
    7ffff7fb8ebd:	7f 00                	jg     0x7ffff7fb8ebf
    7ffff7fb8ebf:	00 a8 8e fb f7 ff    	add    BYTE PTR [rax-0x80472],ch
    7ffff7fb8ec5:	7f 00                	jg     0x7ffff7fb8ec7
    7ffff7fb8ec7:	00 b8 8e fb f7 ff    	add    BYTE PTR [rax-0x80472],bh
    7ffff7fb8ecd:	7f 00                	jg     0x7ffff7fb8ecf
    7ffff7fb8ecf:	00 b8 8e fb f7 ff    	add    BYTE PTR [rax-0x80472],bh
    7ffff7fb8ed5:	7f 00                	jg     0x7ffff7fb8ed7
	...
    7ffff7fb8edf:	00 d0                	add    al,dl
    7ffff7fb8ee1:	fd                   	std
	...
    7ffff7fb8eee:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8ef0:	e0 d1                	loopne 0x7ffff7fb8ec3
    7ffff7fb8ef2:	f8                   	clc
    7ffff7fb8ef3:	f7 ff                	idiv   edi
    7ffff7fb8ef5:	7f 00                	jg     0x7ffff7fb8ef7
    7ffff7fb8ef7:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8ef9:	00 01                	add    BYTE PTR [rcx],al
    7ffff7fb8efb:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8efd:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8eff:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f01:	00 01                	add    BYTE PTR [rcx],al
    7ffff7fb8f03:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f05:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f07:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f09:	00 20                	add    BYTE PTR [rax],ah
    7ffff7fb8f0b:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f0d:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f0f:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f11:	d0 f8                	sar    al,1
    7ffff7fb8f13:	f7 ff                	idiv   edi
    7ffff7fb8f15:	7f 00                	jg     0x7ffff7fb8f17
    7ffff7fb8f17:	00 ff                	add    bh,bh
    7ffff7fb8f19:	0f 00 00             	sldt   WORD PTR [rax]
    7ffff7fb8f1c:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f1e:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb8f20:	40 01 00             	rex add DWORD PTR [rax],eax
	...
    7ffff7fb92f7:	00 50 db             	add    BYTE PTR [rax-0x25],dl
    7ffff7fb92fa:	ff                   	(bad)
    7ffff7fb92fb:	ff                   	(bad)
    7ffff7fb92fc:	ff                   	(bad)
    7ffff7fb92fd:	7f 00                	jg     0x7ffff7fb92ff
    7ffff7fb92ff:	00 00                	add    BYTE PTR [rax],al
    7ffff7fb9301:	00 22                	add    BYTE PTR [rdx],ah
	...
