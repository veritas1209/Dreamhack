
chall:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
       0:	7f 45                	jg     0x47
       2:	4c                   	rex.WR
       3:	46 02 01             	rex.RX add r8b,BYTE PTR [rcx]
       6:	01 00                	add    DWORD PTR [rax],eax
	...
      10:	03 00                	add    eax,DWORD PTR [rax]
      12:	3e 00 01             	ds add BYTE PTR [rcx],al
      15:	00 00                	add    BYTE PTR [rax],al
      17:	00 80 07 00 00 00    	add    BYTE PTR [rax+0x7],al
      1d:	00 00                	add    BYTE PTR [rax],al
      1f:	00 40 00             	add    BYTE PTR [rax+0x0],al
      22:	00 00                	add    BYTE PTR [rax],al
      24:	00 00                	add    BYTE PTR [rax],al
      26:	00 00                	add    BYTE PTR [rax],al
      28:	e0 1a                	loopne 0x44
	...
      32:	00 00                	add    BYTE PTR [rax],al
      34:	40 00 38             	add    BYTE PTR [rax],dil
      37:	00 09                	add    BYTE PTR [rcx],cl
      39:	00 40 00             	add    BYTE PTR [rax+0x0],al
      3c:	1d 00 1c 00 06       	sbb    eax,0x6001c00
      41:	00 00                	add    BYTE PTR [rax],al
      43:	00 04 00             	add    BYTE PTR [rax+rax*1],al
      46:	00 00                	add    BYTE PTR [rax],al
      48:	40 00 00             	rex add BYTE PTR [rax],al
      4b:	00 00                	add    BYTE PTR [rax],al
      4d:	00 00                	add    BYTE PTR [rax],al
      4f:	00 40 00             	add    BYTE PTR [rax+0x0],al
      52:	00 00                	add    BYTE PTR [rax],al
      54:	00 00                	add    BYTE PTR [rax],al
      56:	00 00                	add    BYTE PTR [rax],al
      58:	40 00 00             	rex add BYTE PTR [rax],al
      5b:	00 00                	add    BYTE PTR [rax],al
      5d:	00 00                	add    BYTE PTR [rax],al
      5f:	00 f8                	add    al,bh
      61:	01 00                	add    DWORD PTR [rax],eax
      63:	00 00                	add    BYTE PTR [rax],al
      65:	00 00                	add    BYTE PTR [rax],al
      67:	00 f8                	add    al,bh
      69:	01 00                	add    DWORD PTR [rax],eax
      6b:	00 00                	add    BYTE PTR [rax],al
      6d:	00 00                	add    BYTE PTR [rax],al
      6f:	00 08                	add    BYTE PTR [rax],cl
      71:	00 00                	add    BYTE PTR [rax],al
      73:	00 00                	add    BYTE PTR [rax],al
      75:	00 00                	add    BYTE PTR [rax],al
      77:	00 03                	add    BYTE PTR [rbx],al
      79:	00 00                	add    BYTE PTR [rax],al
      7b:	00 04 00             	add    BYTE PTR [rax+rax*1],al
      7e:	00 00                	add    BYTE PTR [rax],al
      80:	38 02                	cmp    BYTE PTR [rdx],al
      82:	00 00                	add    BYTE PTR [rax],al
      84:	00 00                	add    BYTE PTR [rax],al
      86:	00 00                	add    BYTE PTR [rax],al
      88:	38 02                	cmp    BYTE PTR [rdx],al
      8a:	00 00                	add    BYTE PTR [rax],al
      8c:	00 00                	add    BYTE PTR [rax],al
      8e:	00 00                	add    BYTE PTR [rax],al
      90:	38 02                	cmp    BYTE PTR [rdx],al
      92:	00 00                	add    BYTE PTR [rax],al
      94:	00 00                	add    BYTE PTR [rax],al
      96:	00 00                	add    BYTE PTR [rax],al
      98:	1c 00                	sbb    al,0x0
      9a:	00 00                	add    BYTE PTR [rax],al
      9c:	00 00                	add    BYTE PTR [rax],al
      9e:	00 00                	add    BYTE PTR [rax],al
      a0:	1c 00                	sbb    al,0x0
      a2:	00 00                	add    BYTE PTR [rax],al
      a4:	00 00                	add    BYTE PTR [rax],al
      a6:	00 00                	add    BYTE PTR [rax],al
      a8:	01 00                	add    DWORD PTR [rax],eax
      aa:	00 00                	add    BYTE PTR [rax],al
      ac:	00 00                	add    BYTE PTR [rax],al
      ae:	00 00                	add    BYTE PTR [rax],al
      b0:	01 00                	add    DWORD PTR [rax],eax
      b2:	00 00                	add    BYTE PTR [rax],al
      b4:	05 00 00 00 00       	add    eax,0x0
	...
      cd:	00 00                	add    BYTE PTR [rax],al
      cf:	00 60 0d             	add    BYTE PTR [rax+0xd],ah
      d2:	00 00                	add    BYTE PTR [rax],al
      d4:	00 00                	add    BYTE PTR [rax],al
      d6:	00 00                	add    BYTE PTR [rax],al
      d8:	60                   	(bad)
      d9:	0d 00 00 00 00       	or     eax,0x0
      de:	00 00                	add    BYTE PTR [rax],al
      e0:	00 00                	add    BYTE PTR [rax],al
      e2:	20 00                	and    BYTE PTR [rax],al
      e4:	00 00                	add    BYTE PTR [rax],al
      e6:	00 00                	add    BYTE PTR [rax],al
      e8:	01 00                	add    DWORD PTR [rax],eax
      ea:	00 00                	add    BYTE PTR [rax],al
      ec:	06                   	(bad)
      ed:	00 00                	add    BYTE PTR [rax],al
      ef:	00 78 0d             	add    BYTE PTR [rax+0xd],bh
      f2:	00 00                	add    BYTE PTR [rax],al
      f4:	00 00                	add    BYTE PTR [rax],al
      f6:	00 00                	add    BYTE PTR [rax],al
      f8:	78 0d                	js     0x107
      fa:	20 00                	and    BYTE PTR [rax],al
      fc:	00 00                	add    BYTE PTR [rax],al
      fe:	00 00                	add    BYTE PTR [rax],al
     100:	78 0d                	js     0x10f
     102:	20 00                	and    BYTE PTR [rax],al
     104:	00 00                	add    BYTE PTR [rax],al
     106:	00 00                	add    BYTE PTR [rax],al
     108:	98                   	cwde
     109:	02 00                	add    al,BYTE PTR [rax]
     10b:	00 00                	add    BYTE PTR [rax],al
     10d:	00 00                	add    BYTE PTR [rax],al
     10f:	00 a0 02 00 00 00    	add    BYTE PTR [rax+0x2],ah
     115:	00 00                	add    BYTE PTR [rax],al
     117:	00 00                	add    BYTE PTR [rax],al
     119:	00 20                	add    BYTE PTR [rax],ah
     11b:	00 00                	add    BYTE PTR [rax],al
     11d:	00 00                	add    BYTE PTR [rax],al
     11f:	00 02                	add    BYTE PTR [rdx],al
     121:	00 00                	add    BYTE PTR [rax],al
     123:	00 06                	add    BYTE PTR [rsi],al
     125:	00 00                	add    BYTE PTR [rax],al
     127:	00 88 0d 00 00 00    	add    BYTE PTR [rax+0xd],cl
     12d:	00 00                	add    BYTE PTR [rax],al
     12f:	00 88 0d 20 00 00    	add    BYTE PTR [rax+0x200d],cl
     135:	00 00                	add    BYTE PTR [rax],al
     137:	00 88 0d 20 00 00    	add    BYTE PTR [rax+0x200d],cl
     13d:	00 00                	add    BYTE PTR [rax],al
     13f:	00 f0                	add    al,dh
     141:	01 00                	add    DWORD PTR [rax],eax
     143:	00 00                	add    BYTE PTR [rax],al
     145:	00 00                	add    BYTE PTR [rax],al
     147:	00 f0                	add    al,dh
     149:	01 00                	add    DWORD PTR [rax],eax
     14b:	00 00                	add    BYTE PTR [rax],al
     14d:	00 00                	add    BYTE PTR [rax],al
     14f:	00 08                	add    BYTE PTR [rax],cl
     151:	00 00                	add    BYTE PTR [rax],al
     153:	00 00                	add    BYTE PTR [rax],al
     155:	00 00                	add    BYTE PTR [rax],al
     157:	00 04 00             	add    BYTE PTR [rax+rax*1],al
     15a:	00 00                	add    BYTE PTR [rax],al
     15c:	04 00                	add    al,0x0
     15e:	00 00                	add    BYTE PTR [rax],al
     160:	54                   	push   rsp
     161:	02 00                	add    al,BYTE PTR [rax]
     163:	00 00                	add    BYTE PTR [rax],al
     165:	00 00                	add    BYTE PTR [rax],al
     167:	00 54 02 00          	add    BYTE PTR [rdx+rax*1+0x0],dl
     16b:	00 00                	add    BYTE PTR [rax],al
     16d:	00 00                	add    BYTE PTR [rax],al
     16f:	00 54 02 00          	add    BYTE PTR [rdx+rax*1+0x0],dl
     173:	00 00                	add    BYTE PTR [rax],al
     175:	00 00                	add    BYTE PTR [rax],al
     177:	00 44 00 00          	add    BYTE PTR [rax+rax*1+0x0],al
     17b:	00 00                	add    BYTE PTR [rax],al
     17d:	00 00                	add    BYTE PTR [rax],al
     17f:	00 44 00 00          	add    BYTE PTR [rax+rax*1+0x0],al
     183:	00 00                	add    BYTE PTR [rax],al
     185:	00 00                	add    BYTE PTR [rax],al
     187:	00 04 00             	add    BYTE PTR [rax+rax*1],al
     18a:	00 00                	add    BYTE PTR [rax],al
     18c:	00 00                	add    BYTE PTR [rax],al
     18e:	00 00                	add    BYTE PTR [rax],al
     190:	50                   	push   rax
     191:	e5 74                	in     eax,0x74
     193:	64 04 00             	fs add al,0x0
     196:	00 00                	add    BYTE PTR [rax],al
     198:	d4                   	(bad)
     199:	0b 00                	or     eax,DWORD PTR [rax]
     19b:	00 00                	add    BYTE PTR [rax],al
     19d:	00 00                	add    BYTE PTR [rax],al
     19f:	00 d4                	add    ah,dl
     1a1:	0b 00                	or     eax,DWORD PTR [rax]
     1a3:	00 00                	add    BYTE PTR [rax],al
     1a5:	00 00                	add    BYTE PTR [rax],al
     1a7:	00 d4                	add    ah,dl
     1a9:	0b 00                	or     eax,DWORD PTR [rax]
     1ab:	00 00                	add    BYTE PTR [rax],al
     1ad:	00 00                	add    BYTE PTR [rax],al
     1af:	00 4c 00 00          	add    BYTE PTR [rax+rax*1+0x0],cl
     1b3:	00 00                	add    BYTE PTR [rax],al
     1b5:	00 00                	add    BYTE PTR [rax],al
     1b7:	00 4c 00 00          	add    BYTE PTR [rax+rax*1+0x0],cl
     1bb:	00 00                	add    BYTE PTR [rax],al
     1bd:	00 00                	add    BYTE PTR [rax],al
     1bf:	00 04 00             	add    BYTE PTR [rax+rax*1],al
     1c2:	00 00                	add    BYTE PTR [rax],al
     1c4:	00 00                	add    BYTE PTR [rax],al
     1c6:	00 00                	add    BYTE PTR [rax],al
     1c8:	51                   	push   rcx
     1c9:	e5 74                	in     eax,0x74
     1cb:	64 06                	fs (bad)
	...
     1f5:	00 00                	add    BYTE PTR [rax],al
     1f7:	00 10                	add    BYTE PTR [rax],dl
     1f9:	00 00                	add    BYTE PTR [rax],al
     1fb:	00 00                	add    BYTE PTR [rax],al
     1fd:	00 00                	add    BYTE PTR [rax],al
     1ff:	00 52 e5             	add    BYTE PTR [rdx-0x1b],dl
     202:	74 64                	je     0x268
     204:	04 00                	add    al,0x0
     206:	00 00                	add    BYTE PTR [rax],al
     208:	78 0d                	js     0x217
     20a:	00 00                	add    BYTE PTR [rax],al
     20c:	00 00                	add    BYTE PTR [rax],al
     20e:	00 00                	add    BYTE PTR [rax],al
     210:	78 0d                	js     0x21f
     212:	20 00                	and    BYTE PTR [rax],al
     214:	00 00                	add    BYTE PTR [rax],al
     216:	00 00                	add    BYTE PTR [rax],al
     218:	78 0d                	js     0x227
     21a:	20 00                	and    BYTE PTR [rax],al
     21c:	00 00                	add    BYTE PTR [rax],al
     21e:	00 00                	add    BYTE PTR [rax],al
     220:	88 02                	mov    BYTE PTR [rdx],al
     222:	00 00                	add    BYTE PTR [rax],al
     224:	00 00                	add    BYTE PTR [rax],al
     226:	00 00                	add    BYTE PTR [rax],al
     228:	88 02                	mov    BYTE PTR [rdx],al
     22a:	00 00                	add    BYTE PTR [rax],al
     22c:	00 00                	add    BYTE PTR [rax],al
     22e:	00 00                	add    BYTE PTR [rax],al
     230:	01 00                	add    DWORD PTR [rax],eax
     232:	00 00                	add    BYTE PTR [rax],al
     234:	00 00                	add    BYTE PTR [rax],al
     236:	00 00                	add    BYTE PTR [rax],al
     238:	2f                   	(bad)
     239:	6c                   	ins    BYTE PTR es:[rdi],dx
     23a:	69 62 36 34 2f 6c 64 	imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
     241:	2d 6c 69 6e 75       	sub    eax,0x756e696c
     246:	78 2d                	js     0x275
     248:	78 38                	js     0x282
     24a:	36 2d 36 34 2e 73    	ss sub eax,0x732e3436
     250:	6f                   	outs   dx,DWORD PTR ds:[rsi]
     251:	2e 32 00             	cs xor al,BYTE PTR [rax]
     254:	04 00                	add    al,0x0
     256:	00 00                	add    BYTE PTR [rax],al
     258:	10 00                	adc    BYTE PTR [rax],al
     25a:	00 00                	add    BYTE PTR [rax],al
     25c:	01 00                	add    DWORD PTR [rax],eax
     25e:	00 00                	add    BYTE PTR [rax],al
     260:	47                   	rex.RXB
     261:	4e 55                	rex.WRX push rbp
     263:	00 00                	add    BYTE PTR [rax],al
     265:	00 00                	add    BYTE PTR [rax],al
     267:	00 03                	add    BYTE PTR [rbx],al
     269:	00 00                	add    BYTE PTR [rax],al
     26b:	00 02                	add    BYTE PTR [rdx],al
     26d:	00 00                	add    BYTE PTR [rax],al
     26f:	00 00                	add    BYTE PTR [rax],al
     271:	00 00                	add    BYTE PTR [rax],al
     273:	00 04 00             	add    BYTE PTR [rax+rax*1],al
     276:	00 00                	add    BYTE PTR [rax],al
     278:	14 00                	adc    al,0x0
     27a:	00 00                	add    BYTE PTR [rax],al
     27c:	03 00                	add    eax,DWORD PTR [rax]
     27e:	00 00                	add    BYTE PTR [rax],al
     280:	47                   	rex.RXB
     281:	4e 55                	rex.WRX push rbp
     283:	00 63 16             	add    BYTE PTR [rbx+0x16],ah
     286:	39 11                	cmp    DWORD PTR [rcx],edx
     288:	2a b8 53 62 19 05    	sub    bh,BYTE PTR [rax+0x5196253]
     28e:	ca b1 6f             	retf   0x6fb1
     291:	e3 29                	jrcxz  0x2bc
     293:	08 0d 47 92 3c 01    	or     BYTE PTR [rip+0x13c9247],cl        # 0x13c94e0
     299:	00 00                	add    BYTE PTR [rax],al
     29b:	00 01                	add    BYTE PTR [rcx],al
     29d:	00 00                	add    BYTE PTR [rax],al
     29f:	00 01                	add    BYTE PTR [rcx],al
	...
     2cd:	00 00                	add    BYTE PTR [rax],al
     2cf:	00 72 00             	add    BYTE PTR [rdx+0x0],dh
     2d2:	00 00                	add    BYTE PTR [rax],al
     2d4:	20 00                	and    BYTE PTR [rax],al
	...
     2e6:	00 00                	add    BYTE PTR [rax],al
     2e8:	17                   	(bad)
     2e9:	00 00                	add    BYTE PTR [rax],al
     2eb:	00 12                	add    BYTE PTR [rdx],dl
	...
     2fd:	00 00                	add    BYTE PTR [rax],al
     2ff:	00 2d 00 00 00 12    	add    BYTE PTR [rip+0x12000000],ch        # 0x12000305
	...
     315:	00 00                	add    BYTE PTR [rax],al
     317:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
     31a:	00 00                	add    BYTE PTR [rax],al
     31c:	12 00                	adc    al,BYTE PTR [rax]
	...
     32e:	00 00                	add    BYTE PTR [rax],al
     330:	21 00                	and    DWORD PTR [rax],eax
     332:	00 00                	add    BYTE PTR [rax],al
     334:	12 00                	adc    al,BYTE PTR [rax]
	...
     346:	00 00                	add    BYTE PTR [rax],al
     348:	28 00                	sub    BYTE PTR [rax],al
     34a:	00 00                	add    BYTE PTR [rax],al
     34c:	12 00                	adc    al,BYTE PTR [rax]
	...
     35e:	00 00                	add    BYTE PTR [rax],al
     360:	4b 00 00             	rex.WXB add BYTE PTR [r8],al
     363:	00 12                	add    BYTE PTR [rdx],dl
	...
     375:	00 00                	add    BYTE PTR [rax],al
     377:	00 8e 00 00 00 20    	add    BYTE PTR [rsi+0x20000000],cl
	...
     38d:	00 00                	add    BYTE PTR [rax],al
     38f:	00 5d 00             	add    BYTE PTR [rbp+0x0],bl
     392:	00 00                	add    BYTE PTR [rax],al
     394:	12 00                	adc    al,BYTE PTR [rax]
	...
     3a6:	00 00                	add    BYTE PTR [rax],al
     3a8:	37                   	(bad)
     3a9:	00 00                	add    BYTE PTR [rax],al
     3ab:	00 12                	add    BYTE PTR [rdx],dl
	...
     3bd:	00 00                	add    BYTE PTR [rax],al
     3bf:	00 10                	add    BYTE PTR [rax],dl
     3c1:	00 00                	add    BYTE PTR [rax],al
     3c3:	00 12                	add    BYTE PTR [rdx],dl
	...
     3d5:	00 00                	add    BYTE PTR [rax],al
     3d7:	00 0b                	add    BYTE PTR [rbx],cl
     3d9:	00 00                	add    BYTE PTR [rax],al
     3db:	00 12                	add    BYTE PTR [rdx],dl
	...
     3ed:	00 00                	add    BYTE PTR [rax],al
     3ef:	00 9d 00 00 00 20    	add    BYTE PTR [rbp+0x20000000],bl
	...
     405:	00 00                	add    BYTE PTR [rax],al
     407:	00 3c 00             	add    BYTE PTR [rax+rax*1],bh
     40a:	00 00                	add    BYTE PTR [rax],al
     40c:	22 00                	and    al,BYTE PTR [rax]
	...
     41e:	00 00                	add    BYTE PTR [rax],al
     420:	00 6c 69 62          	add    BYTE PTR [rcx+rbp*2+0x62],ch
     424:	63 2e                	movsxd ebp,DWORD PTR [rsi]
     426:	73 6f                	jae    0x497
     428:	2e 36 00 65 78       	cs ss add BYTE PTR [rbp+0x78],ah
     42d:	69 74 00 70 65 72 72 	imul   esi,DWORD PTR [rax+rax*1+0x70],0x6f727265
     434:	6f 
     435:	72 00                	jb     0x437
     437:	70 75                	jo     0x4ae
     439:	74 73                	je     0x4ae
     43b:	00 6d 6d             	add    BYTE PTR [rbp+0x6d],ch
     43e:	61                   	(bad)
     43f:	70 00                	jo     0x441
     441:	6d                   	ins    DWORD PTR es:[rdi],dx
     442:	65 6d                	gs ins DWORD PTR es:[rdi],dx
     444:	73 65                	jae    0x4ab
     446:	74 00                	je     0x448
     448:	72 65                	jb     0x4af
     44a:	61                   	(bad)
     44b:	64 00 73 69          	add    BYTE PTR fs:[rbx+0x69],dh
     44f:	67 61                	addr32 (bad)
     451:	63 74 69 6f          	movsxd esi,DWORD PTR [rcx+rbp*2+0x6f]
     455:	6e                   	outs   dx,BYTE PTR ds:[rsi]
     456:	00 6f 70             	add    BYTE PTR [rdi+0x70],ch
     459:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
     45b:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
     45e:	63 78 61             	movsxd edi,DWORD PTR [rax+0x61]
     461:	5f                   	pop    rdi
     462:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
     468:	7a 65                	jp     0x4cf
     46a:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
     46d:	6c                   	ins    BYTE PTR es:[rdi],dx
     46e:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
     475:	72 74                	jb     0x4eb
     477:	5f                   	pop    rdi
     478:	6d                   	ins    DWORD PTR es:[rdi],dx
     479:	61                   	(bad)
     47a:	69 6e 00 5f 5f 66 78 	imul   ebp,DWORD PTR [rsi+0x0],0x78665f5f
     481:	73 74                	jae    0x4f7
     483:	61                   	(bad)
     484:	74 00                	je     0x486
     486:	47                   	rex.RXB
     487:	4c                   	rex.WR
     488:	49                   	rex.WB
     489:	42                   	rex.X
     48a:	43 5f                	rex.XB pop r15
     48c:	32 2e                	xor    ch,BYTE PTR [rsi]
     48e:	32 2e                	xor    ch,BYTE PTR [rsi]
     490:	35 00 5f 49 54       	xor    eax,0x54495f00
     495:	4d 5f                	rex.WRB pop r15
     497:	64 65 72 65          	fs gs jb 0x500
     49b:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
     4a2:	4d 
     4a3:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
     4a5:	6f                   	outs   dx,DWORD PTR ds:[rsi]
     4a6:	6e                   	outs   dx,BYTE PTR ds:[rsi]
     4a7:	65 54                	gs push rsp
     4a9:	61                   	(bad)
     4aa:	62 6c 65             	(bad)
     4ad:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
     4b0:	67 6d                	ins    DWORD PTR es:[edi],dx
     4b2:	6f                   	outs   dx,DWORD PTR ds:[rsi]
     4b3:	6e                   	outs   dx,BYTE PTR ds:[rsi]
     4b4:	5f                   	pop    rdi
     4b5:	73 74                	jae    0x52b
     4b7:	61                   	(bad)
     4b8:	72 74                	jb     0x52e
     4ba:	5f                   	pop    rdi
     4bb:	5f                   	pop    rdi
     4bc:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
     4bf:	54                   	push   rsp
     4c0:	4d 5f                	rex.WRB pop r15
     4c2:	72 65                	jb     0x529
     4c4:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
     4cb:	4d 
     4cc:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
     4ce:	6f                   	outs   dx,DWORD PTR ds:[rsi]
     4cf:	6e                   	outs   dx,BYTE PTR ds:[rsi]
     4d0:	65 54                	gs push rsp
     4d2:	61                   	(bad)
     4d3:	62 6c 65             	(bad)
     4d6:	00 00                	add    BYTE PTR [rax],al
     4d8:	00 00                	add    BYTE PTR [rax],al
     4da:	00 00                	add    BYTE PTR [rax],al
     4dc:	02 00                	add    al,BYTE PTR [rax]
     4de:	02 00                	add    al,BYTE PTR [rax]
     4e0:	02 00                	add    al,BYTE PTR [rax]
     4e2:	02 00                	add    al,BYTE PTR [rax]
     4e4:	02 00                	add    al,BYTE PTR [rax]
     4e6:	02 00                	add    al,BYTE PTR [rax]
     4e8:	00 00                	add    BYTE PTR [rax],al
     4ea:	02 00                	add    al,BYTE PTR [rax]
     4ec:	02 00                	add    al,BYTE PTR [rax]
     4ee:	02 00                	add    al,BYTE PTR [rax]
     4f0:	02 00                	add    al,BYTE PTR [rax]
     4f2:	00 00                	add    BYTE PTR [rax],al
     4f4:	02 00                	add    al,BYTE PTR [rax]
     4f6:	00 00                	add    BYTE PTR [rax],al
     4f8:	01 00                	add    DWORD PTR [rax],eax
     4fa:	01 00                	add    DWORD PTR [rax],eax
     4fc:	01 00                	add    DWORD PTR [rax],eax
     4fe:	00 00                	add    BYTE PTR [rax],al
     500:	10 00                	adc    BYTE PTR [rax],al
     502:	00 00                	add    BYTE PTR [rax],al
     504:	00 00                	add    BYTE PTR [rax],al
     506:	00 00                	add    BYTE PTR [rax],al
     508:	75 1a                	jne    0x524
     50a:	69 09 00 00 02 00    	imul   ecx,DWORD PTR [rcx],0x20000
     510:	66 00 00             	data16 add BYTE PTR [rax],al
     513:	00 00                	add    BYTE PTR [rax],al
     515:	00 00                	add    BYTE PTR [rax],al
     517:	00 78 0d             	add    BYTE PTR [rax+0xd],bh
     51a:	20 00                	and    BYTE PTR [rax],al
     51c:	00 00                	add    BYTE PTR [rax],al
     51e:	00 00                	add    BYTE PTR [rax],al
     520:	08 00                	or     BYTE PTR [rax],al
     522:	00 00                	add    BYTE PTR [rax],al
     524:	00 00                	add    BYTE PTR [rax],al
     526:	00 00                	add    BYTE PTR [rax],al
     528:	80 08 00             	or     BYTE PTR [rax],0x0
     52b:	00 00                	add    BYTE PTR [rax],al
     52d:	00 00                	add    BYTE PTR [rax],al
     52f:	00 80 0d 20 00 00    	add    BYTE PTR [rax+0x200d],al
     535:	00 00                	add    BYTE PTR [rax],al
     537:	00 08                	add    BYTE PTR [rax],cl
     539:	00 00                	add    BYTE PTR [rax],al
     53b:	00 00                	add    BYTE PTR [rax],al
     53d:	00 00                	add    BYTE PTR [rax],al
     53f:	00 40 08             	add    BYTE PTR [rax+0x8],al
     542:	00 00                	add    BYTE PTR [rax],al
     544:	00 00                	add    BYTE PTR [rax],al
     546:	00 00                	add    BYTE PTR [rax],al
     548:	08 10                	or     BYTE PTR [rax],dl
     54a:	20 00                	and    BYTE PTR [rax],al
     54c:	00 00                	add    BYTE PTR [rax],al
     54e:	00 00                	add    BYTE PTR [rax],al
     550:	08 00                	or     BYTE PTR [rax],al
     552:	00 00                	add    BYTE PTR [rax],al
     554:	00 00                	add    BYTE PTR [rax],al
     556:	00 00                	add    BYTE PTR [rax],al
     558:	08 10                	or     BYTE PTR [rax],dl
     55a:	20 00                	and    BYTE PTR [rax],al
     55c:	00 00                	add    BYTE PTR [rax],al
     55e:	00 00                	add    BYTE PTR [rax],al
     560:	d8 0f                	fmul   DWORD PTR [rdi]
     562:	20 00                	and    BYTE PTR [rax],al
     564:	00 00                	add    BYTE PTR [rax],al
     566:	00 00                	add    BYTE PTR [rax],al
     568:	06                   	(bad)
     569:	00 00                	add    BYTE PTR [rax],al
     56b:	00 01                	add    BYTE PTR [rcx],al
	...
     575:	00 00                	add    BYTE PTR [rax],al
     577:	00 e0                	add    al,ah
     579:	0f 20 00             	mov    rax,cr0
     57c:	00 00                	add    BYTE PTR [rax],al
     57e:	00 00                	add    BYTE PTR [rax],al
     580:	06                   	(bad)
     581:	00 00                	add    BYTE PTR [rax],al
     583:	00 07                	add    BYTE PTR [rdi],al
	...
     58d:	00 00                	add    BYTE PTR [rax],al
     58f:	00 e8                	add    al,ch
     591:	0f 20 00             	mov    rax,cr0
     594:	00 00                	add    BYTE PTR [rax],al
     596:	00 00                	add    BYTE PTR [rax],al
     598:	06                   	(bad)
     599:	00 00                	add    BYTE PTR [rax],al
     59b:	00 08                	add    BYTE PTR [rax],cl
	...
     5a5:	00 00                	add    BYTE PTR [rax],al
     5a7:	00 f0                	add    al,dh
     5a9:	0f 20 00             	mov    rax,cr0
     5ac:	00 00                	add    BYTE PTR [rax],al
     5ae:	00 00                	add    BYTE PTR [rax],al
     5b0:	06                   	(bad)
     5b1:	00 00                	add    BYTE PTR [rax],al
     5b3:	00 0d 00 00 00 00    	add    BYTE PTR [rip+0x0],cl        # 0x5b9
     5b9:	00 00                	add    BYTE PTR [rax],al
     5bb:	00 00                	add    BYTE PTR [rax],al
     5bd:	00 00                	add    BYTE PTR [rax],al
     5bf:	00 f8                	add    al,bh
     5c1:	0f 20 00             	mov    rax,cr0
     5c4:	00 00                	add    BYTE PTR [rax],al
     5c6:	00 00                	add    BYTE PTR [rax],al
     5c8:	06                   	(bad)
     5c9:	00 00                	add    BYTE PTR [rax],al
     5cb:	00 0e                	add    BYTE PTR [rsi],cl
	...
     5d5:	00 00                	add    BYTE PTR [rax],al
     5d7:	00 90 0f 20 00 00    	add    BYTE PTR [rax+0x200f],dl
     5dd:	00 00                	add    BYTE PTR [rax],al
     5df:	00 07                	add    BYTE PTR [rdi],al
     5e1:	00 00                	add    BYTE PTR [rax],al
     5e3:	00 02                	add    BYTE PTR [rdx],al
	...
     5ed:	00 00                	add    BYTE PTR [rax],al
     5ef:	00 98 0f 20 00 00    	add    BYTE PTR [rax+0x200f],bl
     5f5:	00 00                	add    BYTE PTR [rax],al
     5f7:	00 07                	add    BYTE PTR [rdi],al
     5f9:	00 00                	add    BYTE PTR [rax],al
     5fb:	00 03                	add    BYTE PTR [rbx],al
	...
     605:	00 00                	add    BYTE PTR [rax],al
     607:	00 a0 0f 20 00 00    	add    BYTE PTR [rax+0x200f],ah
     60d:	00 00                	add    BYTE PTR [rax],al
     60f:	00 07                	add    BYTE PTR [rdi],al
     611:	00 00                	add    BYTE PTR [rax],al
     613:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
     61e:	00 00                	add    BYTE PTR [rax],al
     620:	a8 0f                	test   al,0xf
     622:	20 00                	and    BYTE PTR [rax],al
     624:	00 00                	add    BYTE PTR [rax],al
     626:	00 00                	add    BYTE PTR [rax],al
     628:	07                   	(bad)
     629:	00 00                	add    BYTE PTR [rax],al
     62b:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 0x631
     631:	00 00                	add    BYTE PTR [rax],al
     633:	00 00                	add    BYTE PTR [rax],al
     635:	00 00                	add    BYTE PTR [rax],al
     637:	00 b0 0f 20 00 00    	add    BYTE PTR [rax+0x200f],dh
     63d:	00 00                	add    BYTE PTR [rax],al
     63f:	00 07                	add    BYTE PTR [rdi],al
     641:	00 00                	add    BYTE PTR [rax],al
     643:	00 06                	add    BYTE PTR [rsi],al
	...
     64d:	00 00                	add    BYTE PTR [rax],al
     64f:	00 b8 0f 20 00 00    	add    BYTE PTR [rax+0x200f],bh
     655:	00 00                	add    BYTE PTR [rax],al
     657:	00 07                	add    BYTE PTR [rdi],al
     659:	00 00                	add    BYTE PTR [rax],al
     65b:	00 09                	add    BYTE PTR [rcx],cl
	...
     665:	00 00                	add    BYTE PTR [rax],al
     667:	00 c0                	add    al,al
     669:	0f 20 00             	mov    rax,cr0
     66c:	00 00                	add    BYTE PTR [rax],al
     66e:	00 00                	add    BYTE PTR [rax],al
     670:	07                   	(bad)
     671:	00 00                	add    BYTE PTR [rax],al
     673:	00 0a                	add    BYTE PTR [rdx],cl
	...
     67d:	00 00                	add    BYTE PTR [rax],al
     67f:	00 c8                	add    al,cl
     681:	0f 20 00             	mov    rax,cr0
     684:	00 00                	add    BYTE PTR [rax],al
     686:	00 00                	add    BYTE PTR [rax],al
     688:	07                   	(bad)
     689:	00 00                	add    BYTE PTR [rax],al
     68b:	00 0b                	add    BYTE PTR [rbx],cl
	...
     695:	00 00                	add    BYTE PTR [rax],al
     697:	00 d0                	add    al,dl
     699:	0f 20 00             	mov    rax,cr0
     69c:	00 00                	add    BYTE PTR [rax],al
     69e:	00 00                	add    BYTE PTR [rax],al
     6a0:	07                   	(bad)
     6a1:	00 00                	add    BYTE PTR [rax],al
     6a3:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
	...
     6ae:	00 00                	add    BYTE PTR [rax],al
     6b0:	48 83 ec 08          	sub    rsp,0x8
     6b4:	48 8b 05 2d 09 20 00 	mov    rax,QWORD PTR [rip+0x20092d]        # 0x200fe8
     6bb:	48 85 c0             	test   rax,rax
     6be:	74 02                	je     0x6c2
     6c0:	ff d0                	call   rax
     6c2:	48 83 c4 08          	add    rsp,0x8
     6c6:	c3                   	ret
	...
     6cf:	00 ff                	add    bh,bh
     6d1:	35 aa 08 20 00       	xor    eax,0x2008aa
     6d6:	ff 25 ac 08 20 00    	jmp    QWORD PTR [rip+0x2008ac]        # 0x200f88
     6dc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
     6e0:	ff 25 aa 08 20 00    	jmp    QWORD PTR [rip+0x2008aa]        # 0x200f90
     6e6:	68 00 00 00 00       	push   0x0
     6eb:	e9 e0 ff ff ff       	jmp    0x6d0
     6f0:	ff 25 a2 08 20 00    	jmp    QWORD PTR [rip+0x2008a2]        # 0x200f98
     6f6:	68 01 00 00 00       	push   0x1
     6fb:	e9 d0 ff ff ff       	jmp    0x6d0
     700:	ff 25 9a 08 20 00    	jmp    QWORD PTR [rip+0x20089a]        # 0x200fa0
     706:	68 02 00 00 00       	push   0x2
     70b:	e9 c0 ff ff ff       	jmp    0x6d0
     710:	ff 25 92 08 20 00    	jmp    QWORD PTR [rip+0x200892]        # 0x200fa8
     716:	68 03 00 00 00       	push   0x3
     71b:	e9 b0 ff ff ff       	jmp    0x6d0
     720:	ff 25 8a 08 20 00    	jmp    QWORD PTR [rip+0x20088a]        # 0x200fb0
     726:	68 04 00 00 00       	push   0x4
     72b:	e9 a0 ff ff ff       	jmp    0x6d0
     730:	ff 25 82 08 20 00    	jmp    QWORD PTR [rip+0x200882]        # 0x200fb8
     736:	68 05 00 00 00       	push   0x5
     73b:	e9 90 ff ff ff       	jmp    0x6d0
     740:	ff 25 7a 08 20 00    	jmp    QWORD PTR [rip+0x20087a]        # 0x200fc0
     746:	68 06 00 00 00       	push   0x6
     74b:	e9 80 ff ff ff       	jmp    0x6d0
     750:	ff 25 72 08 20 00    	jmp    QWORD PTR [rip+0x200872]        # 0x200fc8
     756:	68 07 00 00 00       	push   0x7
     75b:	e9 70 ff ff ff       	jmp    0x6d0
     760:	ff 25 6a 08 20 00    	jmp    QWORD PTR [rip+0x20086a]        # 0x200fd0
     766:	68 08 00 00 00       	push   0x8
     76b:	e9 60 ff ff ff       	jmp    0x6d0
     770:	ff 25 82 08 20 00    	jmp    QWORD PTR [rip+0x200882]        # 0x200ff8
     776:	66 90                	xchg   ax,ax
	...
     780:	31 ed                	xor    ebp,ebp
     782:	49 89 d1             	mov    r9,rdx
     785:	5e                   	pop    rsi
     786:	48 89 e2             	mov    rdx,rsp
     789:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
     78d:	50                   	push   rax
     78e:	54                   	push   rsp
     78f:	4c 8d 05 ca 03 00 00 	lea    r8,[rip+0x3ca]        # 0xb60
     796:	48 8d 0d 53 03 00 00 	lea    rcx,[rip+0x353]        # 0xaf0
     79d:	48 8d 3d 0f 01 00 00 	lea    rdi,[rip+0x10f]        # 0x8b3
     7a4:	ff 15 36 08 20 00    	call   QWORD PTR [rip+0x200836]        # 0x200fe0
     7aa:	f4                   	hlt
     7ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
     7b0:	48 8d 3d 59 08 20 00 	lea    rdi,[rip+0x200859]        # 0x201010
     7b7:	55                   	push   rbp
     7b8:	48 8d 05 51 08 20 00 	lea    rax,[rip+0x200851]        # 0x201010
     7bf:	48 39 f8             	cmp    rax,rdi
     7c2:	48 89 e5             	mov    rbp,rsp
     7c5:	74 19                	je     0x7e0
     7c7:	48 8b 05 0a 08 20 00 	mov    rax,QWORD PTR [rip+0x20080a]        # 0x200fd8
     7ce:	48 85 c0             	test   rax,rax
     7d1:	74 0d                	je     0x7e0
     7d3:	5d                   	pop    rbp
     7d4:	ff e0                	jmp    rax
     7d6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
     7dd:	00 00 00 
     7e0:	5d                   	pop    rbp
     7e1:	c3                   	ret
     7e2:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
     7e6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
     7ed:	00 00 00 
     7f0:	48 8d 3d 19 08 20 00 	lea    rdi,[rip+0x200819]        # 0x201010
     7f7:	48 8d 35 12 08 20 00 	lea    rsi,[rip+0x200812]        # 0x201010
     7fe:	55                   	push   rbp
     7ff:	48 29 fe             	sub    rsi,rdi
     802:	48 89 e5             	mov    rbp,rsp
     805:	48 c1 fe 03          	sar    rsi,0x3
     809:	48 89 f0             	mov    rax,rsi
     80c:	48 c1 e8 3f          	shr    rax,0x3f
     810:	48 01 c6             	add    rsi,rax
     813:	48 d1 fe             	sar    rsi,1
     816:	74 18                	je     0x830
     818:	48 8b 05 d1 07 20 00 	mov    rax,QWORD PTR [rip+0x2007d1]        # 0x200ff0
     81f:	48 85 c0             	test   rax,rax
     822:	74 0c                	je     0x830
     824:	5d                   	pop    rbp
     825:	ff e0                	jmp    rax
     827:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
     82e:	00 00 
     830:	5d                   	pop    rbp
     831:	c3                   	ret
     832:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
     836:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
     83d:	00 00 00 
     840:	80 3d c9 07 20 00 00 	cmp    BYTE PTR [rip+0x2007c9],0x0        # 0x201010
     847:	75 2f                	jne    0x878
     849:	48 83 3d a7 07 20 00 	cmp    QWORD PTR [rip+0x2007a7],0x0        # 0x200ff8
     850:	00 
     851:	55                   	push   rbp
     852:	48 89 e5             	mov    rbp,rsp
     855:	74 0c                	je     0x863
     857:	48 8b 3d aa 07 20 00 	mov    rdi,QWORD PTR [rip+0x2007aa]        # 0x201008
     85e:	e8 0d ff ff ff       	call   0x770
     863:	e8 48 ff ff ff       	call   0x7b0
     868:	c6 05 a1 07 20 00 01 	mov    BYTE PTR [rip+0x2007a1],0x1        # 0x201010
     86f:	5d                   	pop    rbp
     870:	c3                   	ret
     871:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
     878:	f3 c3                	repz ret
     87a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
     880:	55                   	push   rbp
     881:	48 89 e5             	mov    rbp,rsp
     884:	5d                   	pop    rbp
     885:	e9 66 ff ff ff       	jmp    0x7f0
     88a:	55                   	push   rbp
     88b:	48 89 e5             	mov    rbp,rsp
     88e:	48 83 ec 20          	sub    rsp,0x20
     892:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
     895:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
     899:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
     89d:	48 8d 3d ec 02 00 00 	lea    rdi,[rip+0x2ec]        # 0xb90
     8a4:	e8 37 fe ff ff       	call   0x6e0
     8a9:	bf 00 00 00 00       	mov    edi,0x0
     8ae:	e8 ad fe ff ff       	call   0x760
     8b3:	55                   	push   rbp
     8b4:	48 89 e5             	mov    rbp,rsp
     8b7:	48 81 ec 50 01 00 00 	sub    rsp,0x150
     8be:	48 8d 85 b0 fe ff ff 	lea    rax,[rbp-0x150]
     8c5:	ba 98 00 00 00       	mov    edx,0x98
     8ca:	be 00 00 00 00       	mov    esi,0x0
     8cf:	48 89 c7             	mov    rdi,rax
     8d2:	e8 39 fe ff ff       	call   0x710
     8d7:	c7 85 38 ff ff ff 04 	mov    DWORD PTR [rbp-0xc8],0x4
     8de:	00 00 00 
     8e1:	48 8d 05 a2 ff ff ff 	lea    rax,[rip+0xffffffffffffffa2]        # 0x88a
     8e8:	48 89 85 b0 fe ff ff 	mov    QWORD PTR [rbp-0x150],rax
     8ef:	48 8d 85 b0 fe ff ff 	lea    rax,[rbp-0x150]
     8f6:	ba 00 00 00 00       	mov    edx,0x0
     8fb:	48 89 c6             	mov    rsi,rax
     8fe:	bf 0b 00 00 00       	mov    edi,0xb
     903:	e8 e8 fd ff ff       	call   0x6f0
     908:	41 b9 00 00 00 00    	mov    r9d,0x0
     90e:	41 b8 ff ff ff ff    	mov    r8d,0xffffffff
     914:	b9 21 00 00 00       	mov    ecx,0x21
     919:	ba 07 00 00 00       	mov    edx,0x7
     91e:	be 00 10 00 00       	mov    esi,0x1000
     923:	bf 00 40 22 01       	mov    edi,0x1224000
     928:	e8 d3 fd ff ff       	call   0x700
     92d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
     931:	48 83 7d f8 ff       	cmp    QWORD PTR [rbp-0x8],0xffffffffffffffff
     936:	75 16                	jne    0x94e
     938:	48 8d 3d 57 02 00 00 	lea    rdi,[rip+0x257]        # 0xb96
     93f:	e8 0c fe ff ff       	call   0x750
     944:	bf 00 00 00 00       	mov    edi,0x0
     949:	e8 12 fe ff ff       	call   0x760
     94e:	be 00 00 00 00       	mov    esi,0x0
     953:	48 8d 3d 48 02 00 00 	lea    rdi,[rip+0x248]        # 0xba2
     95a:	b8 00 00 00 00       	mov    eax,0x0
     95f:	e8 dc fd ff ff       	call   0x740
     964:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
     967:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
     96a:	83 f8 ff             	cmp    eax,0xffffffff
     96d:	75 16                	jne    0x985
     96f:	48 8d 3d 33 02 00 00 	lea    rdi,[rip+0x233]        # 0xba9
     976:	e8 d5 fd ff ff       	call   0x750
     97b:	bf 00 00 00 00       	mov    edi,0x0
     980:	e8 db fd ff ff       	call   0x760
     985:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
     988:	48 8d 95 50 ff ff ff 	lea    rdx,[rbp-0xb0]
     98f:	48 89 d6             	mov    rsi,rdx
     992:	89 c7                	mov    edi,eax
     994:	e8 d7 01 00 00       	call   0xb70
     999:	83 f8 ff             	cmp    eax,0xffffffff
     99c:	75 16                	jne    0x9b4
     99e:	48 8d 3d 10 02 00 00 	lea    rdi,[rip+0x210]        # 0xbb5
     9a5:	e8 a6 fd ff ff       	call   0x750
     9aa:	bf 00 00 00 00       	mov    edi,0x0
     9af:	e8 ac fd ff ff       	call   0x760
     9b4:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
     9b8:	48 89 c2             	mov    rdx,rax
     9bb:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
     9be:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
     9c2:	48 89 ce             	mov    rsi,rcx
     9c5:	89 c7                	mov    edi,eax
     9c7:	e8 54 fd ff ff       	call   0x720
     9cc:	48 83 f8 ff          	cmp    rax,0xffffffffffffffff
     9d0:	75 16                	jne    0x9e8
     9d2:	48 8d 3d e9 01 00 00 	lea    rdi,[rip+0x1e9]        # 0xbc2
     9d9:	e8 72 fd ff ff       	call   0x750
     9de:	bf 00 00 00 00       	mov    edi,0x0
     9e3:	e8 78 fd ff ff       	call   0x760
     9e8:	41 b9 00 00 00 00    	mov    r9d,0x0
     9ee:	41 b8 ff ff ff ff    	mov    r8d,0xffffffff
     9f4:	b9 21 00 00 00       	mov    ecx,0x21
     9f9:	ba 07 00 00 00       	mov    edx,0x7
     9fe:	be 00 30 00 00       	mov    esi,0x3000
     a03:	bf 00 50 22 01       	mov    edi,0x1225000
     a08:	e8 f3 fc ff ff       	call   0x700
     a0d:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
     a11:	48 83 7d f0 ff       	cmp    QWORD PTR [rbp-0x10],0xffffffffffffffff
     a16:	75 16                	jne    0xa2e
     a18:	48 8d 3d 77 01 00 00 	lea    rdi,[rip+0x177]        # 0xb96
     a1f:	e8 2c fd ff ff       	call   0x750
     a24:	bf 00 00 00 00       	mov    edi,0x0
     a29:	e8 32 fd ff ff       	call   0x760
     a2e:	be 00 00 00 00       	mov    esi,0x0
     a33:	48 8d 3d 94 01 00 00 	lea    rdi,[rip+0x194]        # 0xbce
     a3a:	b8 00 00 00 00       	mov    eax,0x0
     a3f:	e8 fc fc ff ff       	call   0x740
     a44:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
     a47:	83 7d ec ff          	cmp    DWORD PTR [rbp-0x14],0xffffffff
     a4b:	75 16                	jne    0xa63
     a4d:	48 8d 3d 55 01 00 00 	lea    rdi,[rip+0x155]        # 0xba9
     a54:	e8 f7 fc ff ff       	call   0x750
     a59:	bf 00 00 00 00       	mov    edi,0x0
     a5e:	e8 fd fc ff ff       	call   0x760
     a63:	48 8d 95 50 ff ff ff 	lea    rdx,[rbp-0xb0]
     a6a:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
     a6d:	48 89 d6             	mov    rsi,rdx
     a70:	89 c7                	mov    edi,eax
     a72:	e8 f9 00 00 00       	call   0xb70
     a77:	83 f8 ff             	cmp    eax,0xffffffff
     a7a:	75 16                	jne    0xa92
     a7c:	48 8d 3d 32 01 00 00 	lea    rdi,[rip+0x132]        # 0xbb5
     a83:	e8 c8 fc ff ff       	call   0x750
     a88:	bf 00 00 00 00       	mov    edi,0x0
     a8d:	e8 ce fc ff ff       	call   0x760
     a92:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
     a96:	48 89 c2             	mov    rdx,rax
     a99:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
     a9d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
     aa0:	48 89 ce             	mov    rsi,rcx
     aa3:	89 c7                	mov    edi,eax
     aa5:	e8 76 fc ff ff       	call   0x720
     aaa:	48 83 f8 ff          	cmp    rax,0xffffffffffffffff
     aae:	75 16                	jne    0xac6
     ab0:	48 8d 3d 0b 01 00 00 	lea    rdi,[rip+0x10b]        # 0xbc2
     ab7:	e8 94 fc ff ff       	call   0x750
     abc:	bf 00 00 00 00       	mov    edi,0x0
     ac1:	e8 9a fc ff ff       	call   0x760
     ac6:	48 8d 45 e8          	lea    rax,[rbp-0x18]
     aca:	48 83 c0 18          	add    rax,0x18
     ace:	48 c7 00 00 50 22 01 	mov    QWORD PTR [rax],0x1225000
     ad5:	48 8d 45 e8          	lea    rax,[rbp-0x18]
     ad9:	48 83 c0 20          	add    rax,0x20
     add:	48 c7 00 01 40 22 01 	mov    QWORD PTR [rax],0x1224001
     ae4:	b8 00 00 00 00       	mov    eax,0x0
     ae9:	c9                   	leave
     aea:	c3                   	ret
     aeb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
     af0:	41 57                	push   r15
     af2:	41 56                	push   r14
     af4:	49 89 d7             	mov    r15,rdx
     af7:	41 55                	push   r13
     af9:	41 54                	push   r12
     afb:	4c 8d 25 76 02 20 00 	lea    r12,[rip+0x200276]        # 0x200d78
     b02:	55                   	push   rbp
     b03:	48 8d 2d 76 02 20 00 	lea    rbp,[rip+0x200276]        # 0x200d80
     b0a:	53                   	push   rbx
     b0b:	41 89 fd             	mov    r13d,edi
     b0e:	49 89 f6             	mov    r14,rsi
     b11:	4c 29 e5             	sub    rbp,r12
     b14:	48 83 ec 08          	sub    rsp,0x8
     b18:	48 c1 fd 03          	sar    rbp,0x3
     b1c:	e8 8f fb ff ff       	call   0x6b0
     b21:	48 85 ed             	test   rbp,rbp
     b24:	74 20                	je     0xb46
     b26:	31 db                	xor    ebx,ebx
     b28:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
     b2f:	00 
     b30:	4c 89 fa             	mov    rdx,r15
     b33:	4c 89 f6             	mov    rsi,r14
     b36:	44 89 ef             	mov    edi,r13d
     b39:	41 ff 14 dc          	call   QWORD PTR [r12+rbx*8]
     b3d:	48 83 c3 01          	add    rbx,0x1
     b41:	48 39 dd             	cmp    rbp,rbx
     b44:	75 ea                	jne    0xb30
     b46:	48 83 c4 08          	add    rsp,0x8
     b4a:	5b                   	pop    rbx
     b4b:	5d                   	pop    rbp
     b4c:	41 5c                	pop    r12
     b4e:	41 5d                	pop    r13
     b50:	41 5e                	pop    r14
     b52:	41 5f                	pop    r15
     b54:	c3                   	ret
     b55:	90                   	nop
     b56:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
     b5d:	00 00 00 
     b60:	f3 c3                	repz ret
     b62:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
     b69:	00 00 00 
     b6c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
     b70:	48 89 f2             	mov    rdx,rsi
     b73:	89 fe                	mov    esi,edi
     b75:	bf 01 00 00 00       	mov    edi,0x1
     b7a:	e9 b1 fb ff ff       	jmp    0x730
     b7f:	00 48 83             	add    BYTE PTR [rax-0x7d],cl
     b82:	ec                   	in     al,dx
     b83:	08 48 83             	or     BYTE PTR [rax-0x7d],cl
     b86:	c4                   	(bad)
     b87:	08 c3                	or     bl,al
     b89:	00 00                	add    BYTE PTR [rax],al
     b8b:	00 01                	add    BYTE PTR [rcx],al
     b8d:	00 02                	add    BYTE PTR [rdx],al
     b8f:	00 46 61             	add    BYTE PTR [rsi+0x61],al
     b92:	69 6c 21 00 6d 6d 61 	imul   ebp,DWORD PTR [rcx+riz*1+0x0],0x70616d6d
     b99:	70 
     b9a:	20 66 61             	and    BYTE PTR [rsi+0x61],ah
     b9d:	69 6c 65 64 00 6f 70 	imul   ebp,DWORD PTR [rbp+riz*2+0x64],0x63706f00
     ba4:	63 
     ba5:	6f                   	outs   dx,DWORD PTR ds:[rsi]
     ba6:	64 65 00 6f 70       	fs add BYTE PTR gs:[rdi+0x70],ch
     bab:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
     bad:	20 66 61             	and    BYTE PTR [rsi+0x61],ah
     bb0:	69 6c 65 64 00 66 73 	imul   ebp,DWORD PTR [rbp+riz*2+0x64],0x74736600
     bb7:	74 
     bb8:	61                   	(bad)
     bb9:	74 20                	je     0xbdb
     bbb:	66 61                	data16 (bad)
     bbd:	69 6c 65 64 00 72 65 	imul   ebp,DWORD PTR [rbp+riz*2+0x64],0x61657200
     bc4:	61 
     bc5:	64 20 66 61          	and    BYTE PTR fs:[rsi+0x61],ah
     bc9:	69 6c 65 64 00 63 68 	imul   ebp,DWORD PTR [rbp+riz*2+0x64],0x61686300
     bd0:	61 
     bd1:	69 6e 00 01 1b 03 3b 	imul   ebp,DWORD PTR [rsi+0x0],0x3b031b01
     bd8:	48 00 00             	rex.W add BYTE PTR [rax],al
     bdb:	00 08                	add    BYTE PTR [rax],cl
     bdd:	00 00                	add    BYTE PTR [rax],al
     bdf:	00 fc                	add    ah,bh
     be1:	fa                   	cli
     be2:	ff                   	(bad)
     be3:	ff 94 00 00 00 9c fb 	call   QWORD PTR [rax+rax*1-0x4640000]
     bea:	ff                   	(bad)
     beb:	ff                   	(bad)
     bec:	bc 00 00 00 ac       	mov    esp,0xac000000
     bf1:	fb                   	sti
     bf2:	ff                   	(bad)
     bf3:	ff 64 00 00          	jmp    QWORD PTR [rax+rax*1+0x0]
     bf7:	00 b6 fc ff ff d4    	add    BYTE PTR [rsi-0x2b000004],dh
     bfd:	00 00                	add    BYTE PTR [rax],al
     bff:	00 df                	add    bh,bl
     c01:	fc                   	cld
     c02:	ff                   	(bad)
     c03:	ff f0                	push   rax
     c05:	00 00                	add    BYTE PTR [rax],al
     c07:	00 1c ff             	add    BYTE PTR [rdi+rdi*8],bl
     c0a:	ff                   	(bad)
     c0b:	ff 14 01             	call   QWORD PTR [rcx+rax*1]
     c0e:	00 00                	add    BYTE PTR [rax],al
     c10:	8c ff                	mov    edi,?
     c12:	ff                   	(bad)
     c13:	ff 5c 01 00          	call   FWORD PTR [rcx+rax*1+0x0]
     c17:	00 9c ff ff ff 74 01 	add    BYTE PTR [rdi+rdi*8+0x174ffff],bl
     c1e:	00 00                	add    BYTE PTR [rax],al
     c20:	14 00                	adc    al,0x0
     c22:	00 00                	add    BYTE PTR [rax],al
     c24:	00 00                	add    BYTE PTR [rax],al
     c26:	00 00                	add    BYTE PTR [rax],al
     c28:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
     c2b:	00 01                	add    BYTE PTR [rcx],al
     c2d:	78 10                	js     0xc3f
     c2f:	01 1b                	add    DWORD PTR [rbx],ebx
     c31:	0c 07                	or     al,0x7
     c33:	08 90 01 07 10 14    	or     BYTE PTR [rax+0x14100701],dl
     c39:	00 00                	add    BYTE PTR [rax],al
     c3b:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
     c3e:	00 00                	add    BYTE PTR [rax],al
     c40:	40 fb                	rex sti
     c42:	ff                   	(bad)
     c43:	ff 2b                	jmp    FWORD PTR [rbx]
	...
     c4d:	00 00                	add    BYTE PTR [rax],al
     c4f:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
     c52:	00 00                	add    BYTE PTR [rax],al
     c54:	00 00                	add    BYTE PTR [rax],al
     c56:	00 00                	add    BYTE PTR [rax],al
     c58:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
     c5b:	00 01                	add    BYTE PTR [rcx],al
     c5d:	78 10                	js     0xc6f
     c5f:	01 1b                	add    DWORD PTR [rbx],ebx
     c61:	0c 07                	or     al,0x7
     c63:	08 90 01 00 00 24    	or     BYTE PTR [rax+0x24000001],dl
     c69:	00 00                	add    BYTE PTR [rax],al
     c6b:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
     c6e:	00 00                	add    BYTE PTR [rax],al
     c70:	60                   	(bad)
     c71:	fa                   	cli
     c72:	ff                   	(bad)
     c73:	ff a0 00 00 00 00    	jmp    QWORD PTR [rax+0x0]
     c79:	0e                   	(bad)
     c7a:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
     c7d:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
     c80:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
     c83:	80 00 3f             	add    BYTE PTR [rax],0x3f
     c86:	1a 3b                	sbb    bh,BYTE PTR [rbx]
     c88:	2a 33                	sub    dh,BYTE PTR [rbx]
     c8a:	24 22                	and    al,0x22
     c8c:	00 00                	add    BYTE PTR [rax],al
     c8e:	00 00                	add    BYTE PTR [rax],al
     c90:	14 00                	adc    al,0x0
     c92:	00 00                	add    BYTE PTR [rax],al
     c94:	44 00 00             	add    BYTE PTR [rax],r8b
     c97:	00 d8                	add    al,bl
     c99:	fa                   	cli
     c9a:	ff                   	(bad)
     c9b:	ff 08                	dec    DWORD PTR [rax]
	...
     ca5:	00 00                	add    BYTE PTR [rax],al
     ca7:	00 18                	add    BYTE PTR [rax],bl
     ca9:	00 00                	add    BYTE PTR [rax],al
     cab:	00 5c 00 00          	add    BYTE PTR [rax+rax*1+0x0],bl
     caf:	00 da                	add    dl,bl
     cb1:	fb                   	sti
     cb2:	ff                   	(bad)
     cb3:	ff 29                	jmp    FWORD PTR [rcx]
     cb5:	00 00                	add    BYTE PTR [rax],al
     cb7:	00 00                	add    BYTE PTR [rax],al
     cb9:	41 0e                	rex.B (bad)
     cbb:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
     cc1:	00 00                	add    BYTE PTR [rax],al
     cc3:	00 20                	add    BYTE PTR [rax],ah
     cc5:	00 00                	add    BYTE PTR [rax],al
     cc7:	00 78 00             	add    BYTE PTR [rax+0x0],bh
     cca:	00 00                	add    BYTE PTR [rax],al
     ccc:	e7 fb                	out    0xfb,eax
     cce:	ff                   	(bad)
     ccf:	ff                   	(bad)
     cd0:	38 02                	cmp    BYTE PTR [rdx],al
     cd2:	00 00                	add    BYTE PTR [rax],al
     cd4:	00 41 0e             	add    BYTE PTR [rcx+0xe],al
     cd7:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
     cdd:	03 33                	add    esi,DWORD PTR [rbx]
     cdf:	02 0c 07             	add    cl,BYTE PTR [rdi+rax*1]
     ce2:	08 00                	or     BYTE PTR [rax],al
     ce4:	00 00                	add    BYTE PTR [rax],al
     ce6:	00 00                	add    BYTE PTR [rax],al
     ce8:	44 00 00             	add    BYTE PTR [rax],r8b
     ceb:	00 9c 00 00 00 00 fe 	add    BYTE PTR [rax+rax*1-0x2000000],bl
     cf2:	ff                   	(bad)
     cf3:	ff 65 00             	jmp    QWORD PTR [rbp+0x0]
     cf6:	00 00                	add    BYTE PTR [rax],al
     cf8:	00 42 0e             	add    BYTE PTR [rdx+0xe],al
     cfb:	10 8f 02 42 0e 18    	adc    BYTE PTR [rdi+0x180e4202],cl
     d01:	8e 03                	mov    es,WORD PTR [rbx]
     d03:	45 0e                	rex.RB (bad)
     d05:	20 8d 04 42 0e 28    	and    BYTE PTR [rbp+0x280e4204],cl
     d0b:	8c 05 48 0e 30 86    	mov    WORD PTR [rip+0xffffffff86300e48],es        # 0xffffffff86301b59
     d11:	06                   	(bad)
     d12:	48 0e                	rex.W (bad)
     d14:	38 83 07 4d 0e 40    	cmp    BYTE PTR [rbx+0x400e4d07],al
     d1a:	72 0e                	jb     0xd2a
     d1c:	38 41 0e             	cmp    BYTE PTR [rcx+0xe],al
     d1f:	30 41 0e             	xor    BYTE PTR [rcx+0xe],al
     d22:	28 42 0e             	sub    BYTE PTR [rdx+0xe],al
     d25:	20 42 0e             	and    BYTE PTR [rdx+0xe],al
     d28:	18 42 0e             	sbb    BYTE PTR [rdx+0xe],al
     d2b:	10 42 0e             	adc    BYTE PTR [rdx+0xe],al
     d2e:	08 00                	or     BYTE PTR [rax],al
     d30:	14 00                	adc    al,0x0
     d32:	00 00                	add    BYTE PTR [rax],al
     d34:	e4 00                	in     al,0x0
     d36:	00 00                	add    BYTE PTR [rax],al
     d38:	28 fe                	sub    dh,bh
     d3a:	ff                   	(bad)
     d3b:	ff 02                	inc    DWORD PTR [rdx]
	...
     d45:	00 00                	add    BYTE PTR [rax],al
     d47:	00 10                	add    BYTE PTR [rax],dl
     d49:	00 00                	add    BYTE PTR [rax],al
     d4b:	00 fc                	add    ah,bh
     d4d:	00 00                	add    BYTE PTR [rax],al
     d4f:	00 20                	add    BYTE PTR [rax],ah
     d51:	fe                   	(bad)
     d52:	ff                   	(bad)
     d53:	ff 0f                	dec    DWORD PTR [rdi]
	...
     d75:	00 00                	add    BYTE PTR [rax],al
     d77:	00 80 08 00 00 00    	add    BYTE PTR [rax+0x8],al
     d7d:	00 00                	add    BYTE PTR [rax],al
     d7f:	00 40 08             	add    BYTE PTR [rax+0x8],al
     d82:	00 00                	add    BYTE PTR [rax],al
     d84:	00 00                	add    BYTE PTR [rax],al
     d86:	00 00                	add    BYTE PTR [rax],al
     d88:	01 00                	add    DWORD PTR [rax],eax
     d8a:	00 00                	add    BYTE PTR [rax],al
     d8c:	00 00                	add    BYTE PTR [rax],al
     d8e:	00 00                	add    BYTE PTR [rax],al
     d90:	01 00                	add    DWORD PTR [rax],eax
     d92:	00 00                	add    BYTE PTR [rax],al
     d94:	00 00                	add    BYTE PTR [rax],al
     d96:	00 00                	add    BYTE PTR [rax],al
     d98:	0c 00                	or     al,0x0
     d9a:	00 00                	add    BYTE PTR [rax],al
     d9c:	00 00                	add    BYTE PTR [rax],al
     d9e:	00 00                	add    BYTE PTR [rax],al
     da0:	b0 06                	mov    al,0x6
     da2:	00 00                	add    BYTE PTR [rax],al
     da4:	00 00                	add    BYTE PTR [rax],al
     da6:	00 00                	add    BYTE PTR [rax],al
     da8:	0d 00 00 00 00       	or     eax,0x0
     dad:	00 00                	add    BYTE PTR [rax],al
     daf:	00 80 0b 00 00 00    	add    BYTE PTR [rax+0xb],al
     db5:	00 00                	add    BYTE PTR [rax],al
     db7:	00 19                	add    BYTE PTR [rcx],bl
     db9:	00 00                	add    BYTE PTR [rax],al
     dbb:	00 00                	add    BYTE PTR [rax],al
     dbd:	00 00                	add    BYTE PTR [rax],al
     dbf:	00 78 0d             	add    BYTE PTR [rax+0xd],bh
     dc2:	20 00                	and    BYTE PTR [rax],al
     dc4:	00 00                	add    BYTE PTR [rax],al
     dc6:	00 00                	add    BYTE PTR [rax],al
     dc8:	1b 00                	sbb    eax,DWORD PTR [rax]
     dca:	00 00                	add    BYTE PTR [rax],al
     dcc:	00 00                	add    BYTE PTR [rax],al
     dce:	00 00                	add    BYTE PTR [rax],al
     dd0:	08 00                	or     BYTE PTR [rax],al
     dd2:	00 00                	add    BYTE PTR [rax],al
     dd4:	00 00                	add    BYTE PTR [rax],al
     dd6:	00 00                	add    BYTE PTR [rax],al
     dd8:	1a 00                	sbb    al,BYTE PTR [rax]
     dda:	00 00                	add    BYTE PTR [rax],al
     ddc:	00 00                	add    BYTE PTR [rax],al
     dde:	00 00                	add    BYTE PTR [rax],al
     de0:	80 0d 20 00 00 00 00 	or     BYTE PTR [rip+0x20],0x0        # 0xe07
     de7:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
     dea:	00 00                	add    BYTE PTR [rax],al
     dec:	00 00                	add    BYTE PTR [rax],al
     dee:	00 00                	add    BYTE PTR [rax],al
     df0:	08 00                	or     BYTE PTR [rax],al
     df2:	00 00                	add    BYTE PTR [rax],al
     df4:	00 00                	add    BYTE PTR [rax],al
     df6:	00 00                	add    BYTE PTR [rax],al
     df8:	f5                   	cmc
     df9:	fe                   	(bad)
     dfa:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
     dfd:	00 00                	add    BYTE PTR [rax],al
     dff:	00 98 02 00 00 00    	add    BYTE PTR [rax+0x2],bl
     e05:	00 00                	add    BYTE PTR [rax],al
     e07:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 0xe0d
     e0d:	00 00                	add    BYTE PTR [rax],al
     e0f:	00 20                	add    BYTE PTR [rax],ah
     e11:	04 00                	add    al,0x0
     e13:	00 00                	add    BYTE PTR [rax],al
     e15:	00 00                	add    BYTE PTR [rax],al
     e17:	00 06                	add    BYTE PTR [rsi],al
     e19:	00 00                	add    BYTE PTR [rax],al
     e1b:	00 00                	add    BYTE PTR [rax],al
     e1d:	00 00                	add    BYTE PTR [rax],al
     e1f:	00 b8 02 00 00 00    	add    BYTE PTR [rax+0x2],bh
     e25:	00 00                	add    BYTE PTR [rax],al
     e27:	00 0a                	add    BYTE PTR [rdx],cl
     e29:	00 00                	add    BYTE PTR [rax],al
     e2b:	00 00                	add    BYTE PTR [rax],al
     e2d:	00 00                	add    BYTE PTR [rax],al
     e2f:	00 b7 00 00 00 00    	add    BYTE PTR [rdi+0x0],dh
     e35:	00 00                	add    BYTE PTR [rax],al
     e37:	00 0b                	add    BYTE PTR [rbx],cl
     e39:	00 00                	add    BYTE PTR [rax],al
     e3b:	00 00                	add    BYTE PTR [rax],al
     e3d:	00 00                	add    BYTE PTR [rax],al
     e3f:	00 18                	add    BYTE PTR [rax],bl
     e41:	00 00                	add    BYTE PTR [rax],al
     e43:	00 00                	add    BYTE PTR [rax],al
     e45:	00 00                	add    BYTE PTR [rax],al
     e47:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 0xe4d
	...
     e55:	00 00                	add    BYTE PTR [rax],al
     e57:	00 03                	add    BYTE PTR [rbx],al
     e59:	00 00                	add    BYTE PTR [rax],al
     e5b:	00 00                	add    BYTE PTR [rax],al
     e5d:	00 00                	add    BYTE PTR [rax],al
     e5f:	00 78 0f             	add    BYTE PTR [rax+0xf],bh
     e62:	20 00                	and    BYTE PTR [rax],al
     e64:	00 00                	add    BYTE PTR [rax],al
     e66:	00 00                	add    BYTE PTR [rax],al
     e68:	02 00                	add    al,BYTE PTR [rax]
     e6a:	00 00                	add    BYTE PTR [rax],al
     e6c:	00 00                	add    BYTE PTR [rax],al
     e6e:	00 00                	add    BYTE PTR [rax],al
     e70:	d8 00                	fadd   DWORD PTR [rax]
     e72:	00 00                	add    BYTE PTR [rax],al
     e74:	00 00                	add    BYTE PTR [rax],al
     e76:	00 00                	add    BYTE PTR [rax],al
     e78:	14 00                	adc    al,0x0
     e7a:	00 00                	add    BYTE PTR [rax],al
     e7c:	00 00                	add    BYTE PTR [rax],al
     e7e:	00 00                	add    BYTE PTR [rax],al
     e80:	07                   	(bad)
     e81:	00 00                	add    BYTE PTR [rax],al
     e83:	00 00                	add    BYTE PTR [rax],al
     e85:	00 00                	add    BYTE PTR [rax],al
     e87:	00 17                	add    BYTE PTR [rdi],dl
     e89:	00 00                	add    BYTE PTR [rax],al
     e8b:	00 00                	add    BYTE PTR [rax],al
     e8d:	00 00                	add    BYTE PTR [rax],al
     e8f:	00 d8                	add    al,bl
     e91:	05 00 00 00 00       	add    eax,0x0
     e96:	00 00                	add    BYTE PTR [rax],al
     e98:	07                   	(bad)
     e99:	00 00                	add    BYTE PTR [rax],al
     e9b:	00 00                	add    BYTE PTR [rax],al
     e9d:	00 00                	add    BYTE PTR [rax],al
     e9f:	00 18                	add    BYTE PTR [rax],bl
     ea1:	05 00 00 00 00       	add    eax,0x0
     ea6:	00 00                	add    BYTE PTR [rax],al
     ea8:	08 00                	or     BYTE PTR [rax],al
     eaa:	00 00                	add    BYTE PTR [rax],al
     eac:	00 00                	add    BYTE PTR [rax],al
     eae:	00 00                	add    BYTE PTR [rax],al
     eb0:	c0 00 00             	rol    BYTE PTR [rax],0x0
     eb3:	00 00                	add    BYTE PTR [rax],al
     eb5:	00 00                	add    BYTE PTR [rax],al
     eb7:	00 09                	add    BYTE PTR [rcx],cl
     eb9:	00 00                	add    BYTE PTR [rax],al
     ebb:	00 00                	add    BYTE PTR [rax],al
     ebd:	00 00                	add    BYTE PTR [rax],al
     ebf:	00 18                	add    BYTE PTR [rax],bl
     ec1:	00 00                	add    BYTE PTR [rax],al
     ec3:	00 00                	add    BYTE PTR [rax],al
     ec5:	00 00                	add    BYTE PTR [rax],al
     ec7:	00 1e                	add    BYTE PTR [rsi],bl
     ec9:	00 00                	add    BYTE PTR [rax],al
     ecb:	00 00                	add    BYTE PTR [rax],al
     ecd:	00 00                	add    BYTE PTR [rax],al
     ecf:	00 08                	add    BYTE PTR [rax],cl
     ed1:	00 00                	add    BYTE PTR [rax],al
     ed3:	00 00                	add    BYTE PTR [rax],al
     ed5:	00 00                	add    BYTE PTR [rax],al
     ed7:	00 fb                	add    bl,bh
     ed9:	ff                   	(bad)
     eda:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
     edd:	00 00                	add    BYTE PTR [rax],al
     edf:	00 01                	add    BYTE PTR [rcx],al
     ee1:	00 00                	add    BYTE PTR [rax],al
     ee3:	08 00                	or     BYTE PTR [rax],al
     ee5:	00 00                	add    BYTE PTR [rax],al
     ee7:	00 fe                	add    dh,bh
     ee9:	ff                   	(bad)
     eea:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
     eed:	00 00                	add    BYTE PTR [rax],al
     eef:	00 f8                	add    al,bh
     ef1:	04 00                	add    al,0x0
     ef3:	00 00                	add    BYTE PTR [rax],al
     ef5:	00 00                	add    BYTE PTR [rax],al
     ef7:	00 ff                	add    bh,bh
     ef9:	ff                   	(bad)
     efa:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
     efd:	00 00                	add    BYTE PTR [rax],al
     eff:	00 01                	add    BYTE PTR [rcx],al
     f01:	00 00                	add    BYTE PTR [rax],al
     f03:	00 00                	add    BYTE PTR [rax],al
     f05:	00 00                	add    BYTE PTR [rax],al
     f07:	00 f0                	add    al,dh
     f09:	ff                   	(bad)
     f0a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
     f0d:	00 00                	add    BYTE PTR [rax],al
     f0f:	00 d8                	add    al,bl
     f11:	04 00                	add    al,0x0
     f13:	00 00                	add    BYTE PTR [rax],al
     f15:	00 00                	add    BYTE PTR [rax],al
     f17:	00 f9                	add    cl,bh
     f19:	ff                   	(bad)
     f1a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
     f1d:	00 00                	add    BYTE PTR [rax],al
     f1f:	00 03                	add    BYTE PTR [rbx],al
	...
     f75:	00 00                	add    BYTE PTR [rax],al
     f77:	00 88 0d 20 00 00    	add    BYTE PTR [rax+0x200d],cl
	...
     f8d:	00 00                	add    BYTE PTR [rax],al
     f8f:	00 e6                	add    dh,ah
     f91:	06                   	(bad)
     f92:	00 00                	add    BYTE PTR [rax],al
     f94:	00 00                	add    BYTE PTR [rax],al
     f96:	00 00                	add    BYTE PTR [rax],al
     f98:	f6 06 00             	test   BYTE PTR [rsi],0x0
     f9b:	00 00                	add    BYTE PTR [rax],al
     f9d:	00 00                	add    BYTE PTR [rax],al
     f9f:	00 06                	add    BYTE PTR [rsi],al
     fa1:	07                   	(bad)
     fa2:	00 00                	add    BYTE PTR [rax],al
     fa4:	00 00                	add    BYTE PTR [rax],al
     fa6:	00 00                	add    BYTE PTR [rax],al
     fa8:	16                   	(bad)
     fa9:	07                   	(bad)
     faa:	00 00                	add    BYTE PTR [rax],al
     fac:	00 00                	add    BYTE PTR [rax],al
     fae:	00 00                	add    BYTE PTR [rax],al
     fb0:	26 07                	es (bad)
     fb2:	00 00                	add    BYTE PTR [rax],al
     fb4:	00 00                	add    BYTE PTR [rax],al
     fb6:	00 00                	add    BYTE PTR [rax],al
     fb8:	36 07                	ss (bad)
     fba:	00 00                	add    BYTE PTR [rax],al
     fbc:	00 00                	add    BYTE PTR [rax],al
     fbe:	00 00                	add    BYTE PTR [rax],al
     fc0:	46 07                	rex.RX (bad)
     fc2:	00 00                	add    BYTE PTR [rax],al
     fc4:	00 00                	add    BYTE PTR [rax],al
     fc6:	00 00                	add    BYTE PTR [rax],al
     fc8:	56                   	push   rsi
     fc9:	07                   	(bad)
     fca:	00 00                	add    BYTE PTR [rax],al
     fcc:	00 00                	add    BYTE PTR [rax],al
     fce:	00 00                	add    BYTE PTR [rax],al
     fd0:	66 07                	data16 (bad)
	...
    1006:	00 00                	add    BYTE PTR [rax],al
    1008:	08 10                	or     BYTE PTR [rax],dl
    100a:	20 00                	and    BYTE PTR [rax],al
    100c:	00 00                	add    BYTE PTR [rax],al
    100e:	00 00                	add    BYTE PTR [rax],al
    1010:	47                   	rex.RXB
    1011:	43                   	rex.XB
    1012:	43 3a 20             	rex.XB cmp spl,BYTE PTR [r8]
    1015:	28 55 62             	sub    BYTE PTR [rbp+0x62],dl
    1018:	75 6e                	jne    0x1088
    101a:	74 75                	je     0x1091
    101c:	20 37                	and    BYTE PTR [rdi],dh
    101e:	2e 35 2e 30 2d 33    	cs xor eax,0x332d302e
    1024:	75 62                	jne    0x1088
    1026:	75 6e                	jne    0x1096
    1028:	74 75                	je     0x109f
    102a:	31 7e 31             	xor    DWORD PTR [rsi+0x31],edi
    102d:	38 2e                	cmp    BYTE PTR [rsi],ch
    102f:	30 34 29             	xor    BYTE PTR [rcx+rbp*1],dh
    1032:	20 37                	and    BYTE PTR [rdi],dh
    1034:	2e 35 2e 30 00 00    	cs xor eax,0x302e
	...
    105a:	00 00                	add    BYTE PTR [rax],al
    105c:	03 00                	add    eax,DWORD PTR [rax]
    105e:	01 00                	add    DWORD PTR [rax],eax
    1060:	38 02                	cmp    BYTE PTR [rdx],al
	...
    1072:	00 00                	add    BYTE PTR [rax],al
    1074:	03 00                	add    eax,DWORD PTR [rax]
    1076:	02 00                	add    al,BYTE PTR [rax]
    1078:	54                   	push   rsp
    1079:	02 00                	add    al,BYTE PTR [rax]
	...
    108b:	00 03                	add    BYTE PTR [rbx],al
    108d:	00 03                	add    BYTE PTR [rbx],al
    108f:	00 74 02 00          	add    BYTE PTR [rdx+rax*1+0x0],dh
	...
    10a3:	00 03                	add    BYTE PTR [rbx],al
    10a5:	00 04 00             	add    BYTE PTR [rax+rax*1],al
    10a8:	98                   	cwde
    10a9:	02 00                	add    al,BYTE PTR [rax]
	...
    10bb:	00 03                	add    BYTE PTR [rbx],al
    10bd:	00 05 00 b8 02 00    	add    BYTE PTR [rip+0x2b800],al        # 0x2c8c3
	...
    10d3:	00 03                	add    BYTE PTR [rbx],al
    10d5:	00 06                	add    BYTE PTR [rsi],al
    10d7:	00 20                	add    BYTE PTR [rax],ah
    10d9:	04 00                	add    al,0x0
	...
    10eb:	00 03                	add    BYTE PTR [rbx],al
    10ed:	00 07                	add    BYTE PTR [rdi],al
    10ef:	00 d8                	add    al,bl
    10f1:	04 00                	add    al,0x0
	...
    1103:	00 03                	add    BYTE PTR [rbx],al
    1105:	00 08                	add    BYTE PTR [rax],cl
    1107:	00 f8                	add    al,bh
    1109:	04 00                	add    al,0x0
	...
    111b:	00 03                	add    BYTE PTR [rbx],al
    111d:	00 09                	add    BYTE PTR [rcx],cl
    111f:	00 18                	add    BYTE PTR [rax],bl
    1121:	05 00 00 00 00       	add    eax,0x0
	...
    1132:	00 00                	add    BYTE PTR [rax],al
    1134:	03 00                	add    eax,DWORD PTR [rax]
    1136:	0a 00                	or     al,BYTE PTR [rax]
    1138:	d8 05 00 00 00 00    	fadd   DWORD PTR [rip+0x0]        # 0x113e
	...
    114a:	00 00                	add    BYTE PTR [rax],al
    114c:	03 00                	add    eax,DWORD PTR [rax]
    114e:	0b 00                	or     eax,DWORD PTR [rax]
    1150:	b0 06                	mov    al,0x6
	...
    1162:	00 00                	add    BYTE PTR [rax],al
    1164:	03 00                	add    eax,DWORD PTR [rax]
    1166:	0c 00                	or     al,0x0
    1168:	d0 06                	rol    BYTE PTR [rsi],1
	...
    117a:	00 00                	add    BYTE PTR [rax],al
    117c:	03 00                	add    eax,DWORD PTR [rax]
    117e:	0d 00 70 07 00       	or     eax,0x77000
	...
    1193:	00 03                	add    BYTE PTR [rbx],al
    1195:	00 0e                	add    BYTE PTR [rsi],cl
    1197:	00 80 07 00 00 00    	add    BYTE PTR [rax+0x7],al
	...
    11a9:	00 00                	add    BYTE PTR [rax],al
    11ab:	00 03                	add    BYTE PTR [rbx],al
    11ad:	00 0f                	add    BYTE PTR [rdi],cl
    11af:	00 80 0b 00 00 00    	add    BYTE PTR [rax+0xb],al
	...
    11c1:	00 00                	add    BYTE PTR [rax],al
    11c3:	00 03                	add    BYTE PTR [rbx],al
    11c5:	00 10                	add    BYTE PTR [rax],dl
    11c7:	00 8c 0b 00 00 00 00 	add    BYTE PTR [rbx+rcx*1+0x0],cl
	...
    11da:	00 00                	add    BYTE PTR [rax],al
    11dc:	03 00                	add    eax,DWORD PTR [rax]
    11de:	11 00                	adc    DWORD PTR [rax],eax
    11e0:	d4                   	(bad)
    11e1:	0b 00                	or     eax,DWORD PTR [rax]
	...
    11f3:	00 03                	add    BYTE PTR [rbx],al
    11f5:	00 12                	add    BYTE PTR [rdx],dl
    11f7:	00 20                	add    BYTE PTR [rax],ah
    11f9:	0c 00                	or     al,0x0
	...
    120b:	00 03                	add    BYTE PTR [rbx],al
    120d:	00 13                	add    BYTE PTR [rbx],dl
    120f:	00 78 0d             	add    BYTE PTR [rax+0xd],bh
    1212:	20 00                	and    BYTE PTR [rax],al
	...
    1224:	03 00                	add    eax,DWORD PTR [rax]
    1226:	14 00                	adc    al,0x0
    1228:	80 0d 20 00 00 00 00 	or     BYTE PTR [rip+0x20],0x0        # 0x124f
	...
    123b:	00 03                	add    BYTE PTR [rbx],al
    123d:	00 15 00 88 0d 20    	add    BYTE PTR [rip+0x200d8800],dl        # 0x200d9a43
	...
    1253:	00 03                	add    BYTE PTR [rbx],al
    1255:	00 16                	add    BYTE PTR [rsi],dl
    1257:	00 78 0f             	add    BYTE PTR [rax+0xf],bh
    125a:	20 00                	and    BYTE PTR [rax],al
	...
    126c:	03 00                	add    eax,DWORD PTR [rax]
    126e:	17                   	(bad)
    126f:	00 00                	add    BYTE PTR [rax],al
    1271:	10 20                	adc    BYTE PTR [rax],ah
	...
    1283:	00 03                	add    BYTE PTR [rbx],al
    1285:	00 18                	add    BYTE PTR [rax],bl
    1287:	00 10                	add    BYTE PTR [rax],dl
    1289:	10 20                	adc    BYTE PTR [rax],ah
	...
    129b:	00 03                	add    BYTE PTR [rbx],al
    129d:	00 19                	add    BYTE PTR [rcx],bl
	...
    12af:	00 01                	add    BYTE PTR [rcx],al
    12b1:	00 00                	add    BYTE PTR [rax],al
    12b3:	00 04 00             	add    BYTE PTR [rax+rax*1],al
    12b6:	f1                   	int1
    12b7:	ff 00                	inc    DWORD PTR [rax]
	...
    12c5:	00 00                	add    BYTE PTR [rax],al
    12c7:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
    12ca:	00 00                	add    BYTE PTR [rax],al
    12cc:	02 00                	add    al,BYTE PTR [rax]
    12ce:	0e                   	(bad)
    12cf:	00 b0 07 00 00 00    	add    BYTE PTR [rax+0x7],dh
	...
    12dd:	00 00                	add    BYTE PTR [rax],al
    12df:	00 0e                	add    BYTE PTR [rsi],cl
    12e1:	00 00                	add    BYTE PTR [rax],al
    12e3:	00 02                	add    BYTE PTR [rdx],al
    12e5:	00 0e                	add    BYTE PTR [rsi],cl
    12e7:	00 f0                	add    al,dh
    12e9:	07                   	(bad)
	...
    12f6:	00 00                	add    BYTE PTR [rax],al
    12f8:	21 00                	and    DWORD PTR [rax],eax
    12fa:	00 00                	add    BYTE PTR [rax],al
    12fc:	02 00                	add    al,BYTE PTR [rax]
    12fe:	0e                   	(bad)
    12ff:	00 40 08             	add    BYTE PTR [rax+0x8],al
	...
    130e:	00 00                	add    BYTE PTR [rax],al
    1310:	37                   	(bad)
    1311:	00 00                	add    BYTE PTR [rax],al
    1313:	00 01                	add    BYTE PTR [rcx],al
    1315:	00 18                	add    BYTE PTR [rax],bl
    1317:	00 10                	add    BYTE PTR [rax],dl
    1319:	10 20                	adc    BYTE PTR [rax],ah
    131b:	00 00                	add    BYTE PTR [rax],al
    131d:	00 00                	add    BYTE PTR [rax],al
    131f:	00 01                	add    BYTE PTR [rcx],al
    1321:	00 00                	add    BYTE PTR [rax],al
    1323:	00 00                	add    BYTE PTR [rax],al
    1325:	00 00                	add    BYTE PTR [rax],al
    1327:	00 46 00             	add    BYTE PTR [rsi+0x0],al
    132a:	00 00                	add    BYTE PTR [rax],al
    132c:	01 00                	add    DWORD PTR [rax],eax
    132e:	14 00                	adc    al,0x0
    1330:	80 0d 20 00 00 00 00 	or     BYTE PTR [rip+0x20],0x0        # 0x1357
	...
    133f:	00 6d 00             	add    BYTE PTR [rbp+0x0],ch
    1342:	00 00                	add    BYTE PTR [rax],al
    1344:	02 00                	add    al,BYTE PTR [rax]
    1346:	0e                   	(bad)
    1347:	00 80 08 00 00 00    	add    BYTE PTR [rax+0x8],al
	...
    1355:	00 00                	add    BYTE PTR [rax],al
    1357:	00 79 00             	add    BYTE PTR [rcx+0x0],bh
    135a:	00 00                	add    BYTE PTR [rax],al
    135c:	01 00                	add    DWORD PTR [rax],eax
    135e:	13 00                	adc    eax,DWORD PTR [rax]
    1360:	78 0d                	js     0x136f
    1362:	20 00                	and    BYTE PTR [rax],al
	...
    1370:	98                   	cwde
    1371:	00 00                	add    BYTE PTR [rax],al
    1373:	00 04 00             	add    BYTE PTR [rax+rax*1],al
    1376:	f1                   	int1
    1377:	ff 00                	inc    DWORD PTR [rax]
	...
    1385:	00 00                	add    BYTE PTR [rax],al
    1387:	00 a0 00 00 00 02    	add    BYTE PTR [rax+0x2000000],ah
    138d:	00 0e                	add    BYTE PTR [rsi],cl
    138f:	00 8a 08 00 00 00    	add    BYTE PTR [rdx+0x8],cl
    1395:	00 00                	add    BYTE PTR [rax],al
    1397:	00 29                	add    BYTE PTR [rcx],ch
    1399:	00 00                	add    BYTE PTR [rax],al
    139b:	00 00                	add    BYTE PTR [rax],al
    139d:	00 00                	add    BYTE PTR [rax],al
    139f:	00 01                	add    BYTE PTR [rcx],al
    13a1:	00 00                	add    BYTE PTR [rax],al
    13a3:	00 04 00             	add    BYTE PTR [rax+rax*1],al
    13a6:	f1                   	int1
    13a7:	ff 00                	inc    DWORD PTR [rax]
	...
    13b5:	00 00                	add    BYTE PTR [rax],al
    13b7:	00 a8 00 00 00 01    	add    BYTE PTR [rax+0x1000000],ch
    13bd:	00 12                	add    BYTE PTR [rdx],dl
    13bf:	00 5c 0d 00          	add    BYTE PTR [rbp+rcx*1+0x0],bl
	...
    13d3:	00 04 00             	add    BYTE PTR [rax+rax*1],al
    13d6:	f1                   	int1
    13d7:	ff 00                	inc    DWORD PTR [rax]
	...
    13e5:	00 00                	add    BYTE PTR [rax],al
    13e7:	00 42 02             	add    BYTE PTR [rdx+0x2],al
    13ea:	00 00                	add    BYTE PTR [rax],al
    13ec:	02 00                	add    al,BYTE PTR [rax]
    13ee:	0e                   	(bad)
    13ef:	00 70 0b             	add    BYTE PTR [rax+0xb],dh
    13f2:	00 00                	add    BYTE PTR [rax],al
    13f4:	00 00                	add    BYTE PTR [rax],al
    13f6:	00 00                	add    BYTE PTR [rax],al
    13f8:	0f 00 00             	sldt   WORD PTR [rax]
    13fb:	00 00                	add    BYTE PTR [rax],al
    13fd:	00 00                	add    BYTE PTR [rax],al
    13ff:	00 b6 00 00 00 00    	add    BYTE PTR [rsi+0x0],dh
    1405:	00 13                	add    BYTE PTR [rbx],dl
    1407:	00 80 0d 20 00 00    	add    BYTE PTR [rax+0x200d],al
	...
    1415:	00 00                	add    BYTE PTR [rax],al
    1417:	00 c7                	add    bh,al
    1419:	00 00                	add    BYTE PTR [rax],al
    141b:	00 01                	add    BYTE PTR [rcx],al
    141d:	00 15 00 88 0d 20    	add    BYTE PTR [rip+0x200d8800],dl        # 0x200d9c23
	...
    142f:	00 d0                	add    al,dl
    1431:	00 00                	add    BYTE PTR [rax],al
    1433:	00 00                	add    BYTE PTR [rax],al
    1435:	00 13                	add    BYTE PTR [rbx],dl
    1437:	00 78 0d             	add    BYTE PTR [rax+0xd],bh
    143a:	20 00                	and    BYTE PTR [rax],al
	...
    1448:	e3 00                	jrcxz  0x144a
    144a:	00 00                	add    BYTE PTR [rax],al
    144c:	00 00                	add    BYTE PTR [rax],al
    144e:	11 00                	adc    DWORD PTR [rax],eax
    1450:	d4                   	(bad)
    1451:	0b 00                	or     eax,DWORD PTR [rax]
	...
    145f:	00 f6                	add    dh,dh
    1461:	00 00                	add    BYTE PTR [rax],al
    1463:	00 01                	add    BYTE PTR [rcx],al
    1465:	00 16                	add    BYTE PTR [rsi],dl
    1467:	00 78 0f             	add    BYTE PTR [rax+0xf],bh
    146a:	20 00                	and    BYTE PTR [rax],al
	...
    1478:	0c 01                	or     al,0x1
    147a:	00 00                	add    BYTE PTR [rax],al
    147c:	12 00                	adc    al,BYTE PTR [rax]
    147e:	0e                   	(bad)
    147f:	00 60 0b             	add    BYTE PTR [rax+0xb],ah
    1482:	00 00                	add    BYTE PTR [rax],al
    1484:	00 00                	add    BYTE PTR [rax],al
    1486:	00 00                	add    BYTE PTR [rax],al
    1488:	02 00                	add    al,BYTE PTR [rax]
    148a:	00 00                	add    BYTE PTR [rax],al
    148c:	00 00                	add    BYTE PTR [rax],al
    148e:	00 00                	add    BYTE PTR [rax],al
    1490:	1c 01                	sbb    al,0x1
    1492:	00 00                	add    BYTE PTR [rax],al
    1494:	20 00                	and    BYTE PTR [rax],al
	...
    14a6:	00 00                	add    BYTE PTR [rax],al
    14a8:	c1 01 00             	rol    DWORD PTR [rcx],0x0
    14ab:	00 20                	add    BYTE PTR [rax],ah
    14ad:	00 17                	add    BYTE PTR [rdi],dl
    14af:	00 00                	add    BYTE PTR [rax],al
    14b1:	10 20                	adc    BYTE PTR [rax],ah
	...
    14bf:	00 38                	add    BYTE PTR [rax],bh
    14c1:	01 00                	add    DWORD PTR [rax],eax
    14c3:	00 12                	add    BYTE PTR [rdx],dl
	...
    14d5:	00 00                	add    BYTE PTR [rax],al
    14d7:	00 4a 01             	add    BYTE PTR [rdx+0x1],cl
    14da:	00 00                	add    BYTE PTR [rax],al
    14dc:	12 00                	adc    al,BYTE PTR [rax]
	...
    14ee:	00 00                	add    BYTE PTR [rax],al
    14f0:	61                   	(bad)
    14f1:	01 00                	add    DWORD PTR [rax],eax
    14f3:	00 10                	add    BYTE PTR [rax],dl
    14f5:	00 17                	add    BYTE PTR [rdi],dl
    14f7:	00 10                	add    BYTE PTR [rax],dl
    14f9:	10 20                	adc    BYTE PTR [rax],ah
	...
    1507:	00 16                	add    BYTE PTR [rsi],dl
    1509:	01 00                	add    DWORD PTR [rax],eax
    150b:	00 12                	add    BYTE PTR [rdx],dl
    150d:	00 0f                	add    BYTE PTR [rdi],cl
    150f:	00 80 0b 00 00 00    	add    BYTE PTR [rax+0xb],al
	...
    151d:	00 00                	add    BYTE PTR [rax],al
    151f:	00 68 01             	add    BYTE PTR [rax+0x1],ch
    1522:	00 00                	add    BYTE PTR [rax],al
    1524:	12 00                	adc    al,BYTE PTR [rax]
	...
    1536:	00 00                	add    BYTE PTR [rax],al
    1538:	7a 01                	jp     0x153b
    153a:	00 00                	add    BYTE PTR [rax],al
    153c:	12 00                	adc    al,BYTE PTR [rax]
	...
    154e:	00 00                	add    BYTE PTR [rax],al
    1550:	8e 01                	mov    es,WORD PTR [rcx]
    1552:	00 00                	add    BYTE PTR [rax],al
    1554:	12 00                	adc    al,BYTE PTR [rax]
	...
    1566:	00 00                	add    BYTE PTR [rax],al
    1568:	a0 01 00 00 12 00 00 	movabs al,ds:0x12000001
    156f:	00 00 
	...
    157d:	00 00                	add    BYTE PTR [rax],al
    157f:	00 bf 01 00 00 10    	add    BYTE PTR [rdi+0x10000001],bh
    1585:	00 17                	add    BYTE PTR [rdi],dl
    1587:	00 00                	add    BYTE PTR [rax],al
    1589:	10 20                	adc    BYTE PTR [rax],ah
	...
    1597:	00 cc                	add    ah,cl
    1599:	01 00                	add    DWORD PTR [rax],eax
    159b:	00 20                	add    BYTE PTR [rax],ah
	...
    15ad:	00 00                	add    BYTE PTR [rax],al
    15af:	00 db                	add    bl,bl
    15b1:	01 00                	add    DWORD PTR [rax],eax
    15b3:	00 11                	add    BYTE PTR [rcx],dl
    15b5:	02 17                	add    dl,BYTE PTR [rdi]
    15b7:	00 08                	add    BYTE PTR [rax],cl
    15b9:	10 20                	adc    BYTE PTR [rax],ah
	...
    15c7:	00 e8                	add    al,ch
    15c9:	01 00                	add    DWORD PTR [rax],eax
    15cb:	00 11                	add    BYTE PTR [rcx],dl
    15cd:	00 10                	add    BYTE PTR [rax],dl
    15cf:	00 8c 0b 00 00 00 00 	add    BYTE PTR [rbx+rcx*1+0x0],cl
    15d6:	00 00                	add    BYTE PTR [rax],al
    15d8:	04 00                	add    al,0x0
    15da:	00 00                	add    BYTE PTR [rax],al
    15dc:	00 00                	add    BYTE PTR [rax],al
    15de:	00 00                	add    BYTE PTR [rax],al
    15e0:	f7 01 00 00 12 00    	test   DWORD PTR [rcx],0x120000
    15e6:	0e                   	(bad)
    15e7:	00 f0                	add    al,dh
    15e9:	0a 00                	or     al,BYTE PTR [rax]
    15eb:	00 00                	add    BYTE PTR [rax],al
    15ed:	00 00                	add    BYTE PTR [rax],al
    15ef:	00 65 00             	add    BYTE PTR [rbp+0x0],ah
    15f2:	00 00                	add    BYTE PTR [rax],al
    15f4:	00 00                	add    BYTE PTR [rax],al
    15f6:	00 00                	add    BYTE PTR [rax],al
    15f8:	07                   	(bad)
    15f9:	02 00                	add    al,BYTE PTR [rax]
    15fb:	00 12                	add    BYTE PTR [rdx],dl
	...
    160d:	00 00                	add    BYTE PTR [rax],al
    160f:	00 c2                	add    dl,al
    1611:	00 00                	add    BYTE PTR [rax],al
    1613:	00 10                	add    BYTE PTR [rax],dl
    1615:	00 18                	add    BYTE PTR [rax],bl
    1617:	00 18                	add    BYTE PTR [rax],bl
    1619:	10 20                	adc    BYTE PTR [rax],ah
	...
    1627:	00 c5                	add    ch,al
    1629:	01 00                	add    DWORD PTR [rax],eax
    162b:	00 12                	add    BYTE PTR [rdx],dl
    162d:	00 0e                	add    BYTE PTR [rsi],cl
    162f:	00 80 07 00 00 00    	add    BYTE PTR [rax+0x7],al
    1635:	00 00                	add    BYTE PTR [rax],al
    1637:	00 2b                	add    BYTE PTR [rbx],ch
    1639:	00 00                	add    BYTE PTR [rax],al
    163b:	00 00                	add    BYTE PTR [rax],al
    163d:	00 00                	add    BYTE PTR [rax],al
    163f:	00 1d 02 00 00 10    	add    BYTE PTR [rip+0x10000002],bl        # 0x10001647
    1645:	00 18                	add    BYTE PTR [rax],bl
    1647:	00 10                	add    BYTE PTR [rax],dl
    1649:	10 20                	adc    BYTE PTR [rax],ah
	...
    1657:	00 29                	add    BYTE PTR [rcx],ch
    1659:	02 00                	add    al,BYTE PTR [rax]
    165b:	00 12                	add    BYTE PTR [rdx],dl
    165d:	00 0e                	add    BYTE PTR [rsi],cl
    165f:	00 b3 08 00 00 00    	add    BYTE PTR [rbx+0x8],dh
    1665:	00 00                	add    BYTE PTR [rax],al
    1667:	00 38                	add    BYTE PTR [rax],bh
    1669:	02 00                	add    al,BYTE PTR [rax]
    166b:	00 00                	add    BYTE PTR [rax],al
    166d:	00 00                	add    BYTE PTR [rax],al
    166f:	00 2e                	add    BYTE PTR [rsi],ch
    1671:	02 00                	add    al,BYTE PTR [rax]
    1673:	00 12                	add    BYTE PTR [rdx],dl
	...
    1685:	00 00                	add    BYTE PTR [rax],al
    1687:	00 40 02             	add    BYTE PTR [rax+0x2],al
    168a:	00 00                	add    BYTE PTR [rax],al
    168c:	12 02                	adc    al,BYTE PTR [rdx]
    168e:	0e                   	(bad)
    168f:	00 70 0b             	add    BYTE PTR [rax+0xb],dh
    1692:	00 00                	add    BYTE PTR [rax],al
    1694:	00 00                	add    BYTE PTR [rax],al
    1696:	00 00                	add    BYTE PTR [rax],al
    1698:	0f 00 00             	sldt   WORD PTR [rax]
    169b:	00 00                	add    BYTE PTR [rax],al
    169d:	00 00                	add    BYTE PTR [rax],al
    169f:	00 48 02             	add    BYTE PTR [rax+0x2],cl
    16a2:	00 00                	add    BYTE PTR [rax],al
    16a4:	12 00                	adc    al,BYTE PTR [rax]
	...
    16b6:	00 00                	add    BYTE PTR [rax],al
    16b8:	5c                   	pop    rsp
    16b9:	02 00                	add    al,BYTE PTR [rax]
    16bb:	00 12                	add    BYTE PTR [rdx],dl
	...
    16cd:	00 00                	add    BYTE PTR [rax],al
    16cf:	00 6e 02             	add    BYTE PTR [rsi+0x2],ch
    16d2:	00 00                	add    BYTE PTR [rax],al
    16d4:	11 02                	adc    DWORD PTR [rdx],eax
    16d6:	17                   	(bad)
    16d7:	00 10                	add    BYTE PTR [rax],dl
    16d9:	10 20                	adc    BYTE PTR [rax],ah
	...
    16e7:	00 7a 02             	add    BYTE PTR [rdx+0x2],bh
    16ea:	00 00                	add    BYTE PTR [rax],al
    16ec:	20 00                	and    BYTE PTR [rax],al
	...
    16fe:	00 00                	add    BYTE PTR [rax],al
    1700:	94                   	xchg   esp,eax
    1701:	02 00                	add    al,BYTE PTR [rax]
    1703:	00 22                	add    BYTE PTR [rdx],ah
	...
    1715:	00 00                	add    BYTE PTR [rax],al
    1717:	00 01                	add    BYTE PTR [rcx],al
    1719:	02 00                	add    al,BYTE PTR [rax]
    171b:	00 12                	add    BYTE PTR [rdx],dl
    171d:	00 0b                	add    BYTE PTR [rbx],cl
    171f:	00 b0 06 00 00 00    	add    BYTE PTR [rax+0x6],dh
	...
    1731:	63 72 74             	movsxd esi,DWORD PTR [rdx+0x74]
    1734:	73 74                	jae    0x17aa
    1736:	75 66                	jne    0x179e
    1738:	66 2e 63 00          	cs movsxd ax,DWORD PTR [rax]
    173c:	64 65 72 65          	fs gs jb 0x17a5
    1740:	67 69 73 74 65 72 5f 	imul   esi,DWORD PTR [ebx+0x74],0x745f7265
    1747:	74 
    1748:	6d                   	ins    DWORD PTR es:[rdi],dx
    1749:	5f                   	pop    rdi
    174a:	63 6c 6f 6e          	movsxd ebp,DWORD PTR [rdi+rbp*2+0x6e]
    174e:	65 73 00             	gs jae 0x1751
    1751:	5f                   	pop    rdi
    1752:	5f                   	pop    rdi
    1753:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
    1755:	5f                   	pop    rdi
    1756:	67 6c                	ins    BYTE PTR es:[edi],dx
    1758:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    1759:	62 61 6c 5f 64       	(bad)
    175e:	74 6f                	je     0x17cf
    1760:	72 73                	jb     0x17d5
    1762:	5f                   	pop    rdi
    1763:	61                   	(bad)
    1764:	75 78                	jne    0x17de
    1766:	00 63 6f             	add    BYTE PTR [rbx+0x6f],ah
    1769:	6d                   	ins    DWORD PTR es:[rdi],dx
    176a:	70 6c                	jo     0x17d8
    176c:	65 74 65             	gs je  0x17d4
    176f:	64 2e 37             	fs cs (bad)
    1772:	36 39 38             	ss cmp DWORD PTR [rax],edi
    1775:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
    1778:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
    177a:	5f                   	pop    rdi
    177b:	67 6c                	ins    BYTE PTR es:[edi],dx
    177d:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    177e:	62 61 6c 5f 64       	(bad)
    1783:	74 6f                	je     0x17f4
    1785:	72 73                	jb     0x17fa
    1787:	5f                   	pop    rdi
    1788:	61                   	(bad)
    1789:	75 78                	jne    0x1803
    178b:	5f                   	pop    rdi
    178c:	66 69 6e 69 5f 61    	imul   bp,WORD PTR [rsi+0x69],0x615f
    1792:	72 72                	jb     0x1806
    1794:	61                   	(bad)
    1795:	79 5f                	jns    0x17f6
    1797:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
    1799:	74 72                	je     0x180d
    179b:	79 00                	jns    0x179d
    179d:	66 72 61             	data16 jb 0x1801
    17a0:	6d                   	ins    DWORD PTR es:[rdi],dx
    17a1:	65 5f                	gs pop rdi
    17a3:	64 75 6d             	fs jne 0x1813
    17a6:	6d                   	ins    DWORD PTR es:[rdi],dx
    17a7:	79 00                	jns    0x17a9
    17a9:	5f                   	pop    rdi
    17aa:	5f                   	pop    rdi
    17ab:	66 72 61             	data16 jb 0x180f
    17ae:	6d                   	ins    DWORD PTR es:[rdi],dx
    17af:	65 5f                	gs pop rdi
    17b1:	64 75 6d             	fs jne 0x1821
    17b4:	6d                   	ins    DWORD PTR es:[rdi],dx
    17b5:	79 5f                	jns    0x1816
    17b7:	69 6e 69 74 5f 61 72 	imul   ebp,DWORD PTR [rsi+0x69],0x72615f74
    17be:	72 61                	jb     0x1821
    17c0:	79 5f                	jns    0x1821
    17c2:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
    17c4:	74 72                	je     0x1838
    17c6:	79 00                	jns    0x17c8
    17c8:	63 68 61             	movsxd ebp,DWORD PTR [rax+0x61]
    17cb:	6c                   	ins    BYTE PTR es:[rdi],dx
    17cc:	6c                   	ins    BYTE PTR es:[rdi],dx
    17cd:	2e 63 00             	cs movsxd eax,DWORD PTR [rax]
    17d0:	68 61 6e 64 6c       	push   0x6c646e61
    17d5:	65 72 00             	gs jb  0x17d8
    17d8:	5f                   	pop    rdi
    17d9:	5f                   	pop    rdi
    17da:	46 52                	rex.RX push rdx
    17dc:	41                   	rex.B
    17dd:	4d                   	rex.WRB
    17de:	45 5f                	rex.RB pop r15
    17e0:	45                   	rex.RB
    17e1:	4e                   	rex.WRX
    17e2:	44 5f                	rex.R pop rdi
    17e4:	5f                   	pop    rdi
    17e5:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
    17e8:	69 6e 69 74 5f 61 72 	imul   ebp,DWORD PTR [rsi+0x69],0x72615f74
    17ef:	72 61                	jb     0x1852
    17f1:	79 5f                	jns    0x1852
    17f3:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
    17f5:	64 00 5f 44          	add    BYTE PTR fs:[rdi+0x44],bl
    17f9:	59                   	pop    rcx
    17fa:	4e                   	rex.WRX
    17fb:	41                   	rex.B
    17fc:	4d                   	rex.WRB
    17fd:	49                   	rex.WB
    17fe:	43 00 5f 5f          	rex.XB add BYTE PTR [r15+0x5f],bl
    1802:	69 6e 69 74 5f 61 72 	imul   ebp,DWORD PTR [rsi+0x69],0x72615f74
    1809:	72 61                	jb     0x186c
    180b:	79 5f                	jns    0x186c
    180d:	73 74                	jae    0x1883
    180f:	61                   	(bad)
    1810:	72 74                	jb     0x1886
    1812:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
    1815:	47                   	rex.RXB
    1816:	4e 55                	rex.WRX push rbp
    1818:	5f                   	pop    rdi
    1819:	45                   	rex.RB
    181a:	48 5f                	rex.W pop rdi
    181c:	46 52                	rex.RX push rdx
    181e:	41                   	rex.B
    181f:	4d                   	rex.WRB
    1820:	45 5f                	rex.RB pop r15
    1822:	48                   	rex.W
    1823:	44 52                	rex.R push rdx
    1825:	00 5f 47             	add    BYTE PTR [rdi+0x47],bl
    1828:	4c                   	rex.WR
    1829:	4f                   	rex.WRXB
    182a:	42                   	rex.X
    182b:	41                   	rex.B
    182c:	4c 5f                	rex.WR pop rdi
    182e:	4f                   	rex.WRXB
    182f:	46                   	rex.RX
    1830:	46 53                	rex.RX push rbx
    1832:	45 54                	rex.RB push r12
    1834:	5f                   	pop    rdi
    1835:	54                   	push   rsp
    1836:	41                   	rex.B
    1837:	42                   	rex.X
    1838:	4c                   	rex.WR
    1839:	45 5f                	rex.RB pop r15
    183b:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
    183e:	6c                   	ins    BYTE PTR es:[rdi],dx
    183f:	69 62 63 5f 63 73 75 	imul   esp,DWORD PTR [rdx+0x63],0x7573635f
    1846:	5f                   	pop    rdi
    1847:	66 69 6e 69 00 5f    	imul   bp,WORD PTR [rsi+0x69],0x5f00
    184d:	49 54                	rex.WB push r12
    184f:	4d 5f                	rex.WRB pop r15
    1851:	64 65 72 65          	fs gs jb 0x18ba
    1855:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
    185c:	4d 
    185d:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
    185f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    1860:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    1861:	65 54                	gs push rsp
    1863:	61                   	(bad)
    1864:	62 6c 65             	(bad)
    1867:	00 70 75             	add    BYTE PTR [rax+0x75],dh
    186a:	74 73                	je     0x18df
    186c:	40                   	rex
    186d:	40                   	rex
    186e:	47                   	rex.RXB
    186f:	4c                   	rex.WR
    1870:	49                   	rex.WB
    1871:	42                   	rex.X
    1872:	43 5f                	rex.XB pop r15
    1874:	32 2e                	xor    ch,BYTE PTR [rsi]
    1876:	32 2e                	xor    ch,BYTE PTR [rsi]
    1878:	35 00 73 69 67       	xor    eax,0x67697300
    187d:	61                   	(bad)
    187e:	63 74 69 6f          	movsxd esi,DWORD PTR [rcx+rbp*2+0x6f]
    1882:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    1883:	40                   	rex
    1884:	40                   	rex
    1885:	47                   	rex.RXB
    1886:	4c                   	rex.WR
    1887:	49                   	rex.WB
    1888:	42                   	rex.X
    1889:	43 5f                	rex.XB pop r15
    188b:	32 2e                	xor    ch,BYTE PTR [rsi]
    188d:	32 2e                	xor    ch,BYTE PTR [rsi]
    188f:	35 00 5f 65 64       	xor    eax,0x64655f00
    1894:	61                   	(bad)
    1895:	74 61                	je     0x18f8
    1897:	00 6d 6d             	add    BYTE PTR [rbp+0x6d],ch
    189a:	61                   	(bad)
    189b:	70 40                	jo     0x18dd
    189d:	40                   	rex
    189e:	47                   	rex.RXB
    189f:	4c                   	rex.WR
    18a0:	49                   	rex.WB
    18a1:	42                   	rex.X
    18a2:	43 5f                	rex.XB pop r15
    18a4:	32 2e                	xor    ch,BYTE PTR [rsi]
    18a6:	32 2e                	xor    ch,BYTE PTR [rsi]
    18a8:	35 00 6d 65 6d       	xor    eax,0x6d656d00
    18ad:	73 65                	jae    0x1914
    18af:	74 40                	je     0x18f1
    18b1:	40                   	rex
    18b2:	47                   	rex.RXB
    18b3:	4c                   	rex.WR
    18b4:	49                   	rex.WB
    18b5:	42                   	rex.X
    18b6:	43 5f                	rex.XB pop r15
    18b8:	32 2e                	xor    ch,BYTE PTR [rsi]
    18ba:	32 2e                	xor    ch,BYTE PTR [rsi]
    18bc:	35 00 72 65 61       	xor    eax,0x61657200
    18c1:	64 40                	fs rex
    18c3:	40                   	rex
    18c4:	47                   	rex.RXB
    18c5:	4c                   	rex.WR
    18c6:	49                   	rex.WB
    18c7:	42                   	rex.X
    18c8:	43 5f                	rex.XB pop r15
    18ca:	32 2e                	xor    ch,BYTE PTR [rsi]
    18cc:	32 2e                	xor    ch,BYTE PTR [rsi]
    18ce:	35 00 5f 5f 6c       	xor    eax,0x6c5f5f00
    18d3:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
    18da:	72 74                	jb     0x1950
    18dc:	5f                   	pop    rdi
    18dd:	6d                   	ins    DWORD PTR es:[rdi],dx
    18de:	61                   	(bad)
    18df:	69 6e 40 40 47 4c 49 	imul   ebp,DWORD PTR [rsi+0x40],0x494c4740
    18e6:	42                   	rex.X
    18e7:	43 5f                	rex.XB pop r15
    18e9:	32 2e                	xor    ch,BYTE PTR [rsi]
    18eb:	32 2e                	xor    ch,BYTE PTR [rsi]
    18ed:	35 00 5f 5f 64       	xor    eax,0x645f5f00
    18f2:	61                   	(bad)
    18f3:	74 61                	je     0x1956
    18f5:	5f                   	pop    rdi
    18f6:	73 74                	jae    0x196c
    18f8:	61                   	(bad)
    18f9:	72 74                	jb     0x196f
    18fb:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
    18fe:	67 6d                	ins    DWORD PTR es:[edi],dx
    1900:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    1901:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    1902:	5f                   	pop    rdi
    1903:	73 74                	jae    0x1979
    1905:	61                   	(bad)
    1906:	72 74                	jb     0x197c
    1908:	5f                   	pop    rdi
    1909:	5f                   	pop    rdi
    190a:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
    190d:	64 73 6f             	fs jae 0x197f
    1910:	5f                   	pop    rdi
    1911:	68 61 6e 64 6c       	push   0x6c646e61
    1916:	65 00 5f 49          	add    BYTE PTR gs:[rdi+0x49],bl
    191a:	4f 5f                	rex.WRXB pop r15
    191c:	73 74                	jae    0x1992
    191e:	64 69 6e 5f 75 73 65 	imul   ebp,DWORD PTR fs:[rsi+0x5f],0x64657375
    1925:	64 
    1926:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
    1929:	6c                   	ins    BYTE PTR es:[rdi],dx
    192a:	69 62 63 5f 63 73 75 	imul   esp,DWORD PTR [rdx+0x63],0x7573635f
    1931:	5f                   	pop    rdi
    1932:	69 6e 69 74 00 5f 5f 	imul   ebp,DWORD PTR [rsi+0x69],0x5f5f0074
    1939:	66 78 73             	data16 js 0x19af
    193c:	74 61                	je     0x199f
    193e:	74 40                	je     0x1980
    1940:	40                   	rex
    1941:	47                   	rex.RXB
    1942:	4c                   	rex.WR
    1943:	49                   	rex.WB
    1944:	42                   	rex.X
    1945:	43 5f                	rex.XB pop r15
    1947:	32 2e                	xor    ch,BYTE PTR [rsi]
    1949:	32 2e                	xor    ch,BYTE PTR [rsi]
    194b:	35 00 5f 5f 62       	xor    eax,0x625f5f00
    1950:	73 73                	jae    0x19c5
    1952:	5f                   	pop    rdi
    1953:	73 74                	jae    0x19c9
    1955:	61                   	(bad)
    1956:	72 74                	jb     0x19cc
    1958:	00 6d 61             	add    BYTE PTR [rbp+0x61],ch
    195b:	69 6e 00 6f 70 65 6e 	imul   ebp,DWORD PTR [rsi+0x0],0x6e65706f
    1962:	40                   	rex
    1963:	40                   	rex
    1964:	47                   	rex.RXB
    1965:	4c                   	rex.WR
    1966:	49                   	rex.WB
    1967:	42                   	rex.X
    1968:	43 5f                	rex.XB pop r15
    196a:	32 2e                	xor    ch,BYTE PTR [rsi]
    196c:	32 2e                	xor    ch,BYTE PTR [rsi]
    196e:	35 00 5f 5f 66       	xor    eax,0x665f5f00
    1973:	73 74                	jae    0x19e9
    1975:	61                   	(bad)
    1976:	74 00                	je     0x1978
    1978:	70 65                	jo     0x19df
    197a:	72 72                	jb     0x19ee
    197c:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    197d:	72 40                	jb     0x19bf
    197f:	40                   	rex
    1980:	47                   	rex.RXB
    1981:	4c                   	rex.WR
    1982:	49                   	rex.WB
    1983:	42                   	rex.X
    1984:	43 5f                	rex.XB pop r15
    1986:	32 2e                	xor    ch,BYTE PTR [rsi]
    1988:	32 2e                	xor    ch,BYTE PTR [rsi]
    198a:	35 00 65 78 69       	xor    eax,0x69786500
    198f:	74 40                	je     0x19d1
    1991:	40                   	rex
    1992:	47                   	rex.RXB
    1993:	4c                   	rex.WR
    1994:	49                   	rex.WB
    1995:	42                   	rex.X
    1996:	43 5f                	rex.XB pop r15
    1998:	32 2e                	xor    ch,BYTE PTR [rsi]
    199a:	32 2e                	xor    ch,BYTE PTR [rsi]
    199c:	35 00 5f 5f 54       	xor    eax,0x545f5f00
    19a1:	4d                   	rex.WRB
    19a2:	43 5f                	rex.XB pop r15
    19a4:	45                   	rex.RB
    19a5:	4e                   	rex.WRX
    19a6:	44 5f                	rex.R pop rdi
    19a8:	5f                   	pop    rdi
    19a9:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
    19ac:	54                   	push   rsp
    19ad:	4d 5f                	rex.WRB pop r15
    19af:	72 65                	jb     0x1a16
    19b1:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
    19b8:	4d 
    19b9:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
    19bb:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    19bc:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    19bd:	65 54                	gs push rsp
    19bf:	61                   	(bad)
    19c0:	62 6c 65             	(bad)
    19c3:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
    19c6:	63 78 61             	movsxd edi,DWORD PTR [rax+0x61]
    19c9:	5f                   	pop    rdi
    19ca:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
    19d0:	7a 65                	jp     0x1a37
    19d2:	40                   	rex
    19d3:	40                   	rex
    19d4:	47                   	rex.RXB
    19d5:	4c                   	rex.WR
    19d6:	49                   	rex.WB
    19d7:	42                   	rex.X
    19d8:	43 5f                	rex.XB pop r15
    19da:	32 2e                	xor    ch,BYTE PTR [rsi]
    19dc:	32 2e                	xor    ch,BYTE PTR [rsi]
    19de:	35 00 00 2e 73       	xor    eax,0x732e0000
    19e3:	79 6d                	jns    0x1a52
    19e5:	74 61                	je     0x1a48
    19e7:	62                   	(bad)
    19e8:	00 2e                	add    BYTE PTR [rsi],ch
    19ea:	73 74                	jae    0x1a60
    19ec:	72 74                	jb     0x1a62
    19ee:	61                   	(bad)
    19ef:	62                   	(bad)
    19f0:	00 2e                	add    BYTE PTR [rsi],ch
    19f2:	73 68                	jae    0x1a5c
    19f4:	73 74                	jae    0x1a6a
    19f6:	72 74                	jb     0x1a6c
    19f8:	61                   	(bad)
    19f9:	62                   	(bad)
    19fa:	00 2e                	add    BYTE PTR [rsi],ch
    19fc:	69 6e 74 65 72 70 00 	imul   ebp,DWORD PTR [rsi+0x74],0x707265
    1a03:	2e 6e                	outs   dx,BYTE PTR ds:[rsi]
    1a05:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    1a06:	74 65                	je     0x1a6d
    1a08:	2e 41                	cs rex.B
    1a0a:	42                   	rex.X
    1a0b:	49 2d 74 61 67 00    	rex.WB sub rax,0x676174
    1a11:	2e 6e                	outs   dx,BYTE PTR ds:[rsi]
    1a13:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    1a14:	74 65                	je     0x1a7b
    1a16:	2e 67 6e             	outs   dx,BYTE PTR ds:[esi]
    1a19:	75 2e                	jne    0x1a49
    1a1b:	62 75 69 6c 64       	(bad)
    1a20:	2d 69 64 00 2e       	sub    eax,0x2e006469
    1a25:	67 6e                	outs   dx,BYTE PTR ds:[esi]
    1a27:	75 2e                	jne    0x1a57
    1a29:	68 61 73 68 00       	push   0x687361
    1a2e:	2e 64 79 6e          	cs fs jns 0x1aa0
    1a32:	73 79                	jae    0x1aad
    1a34:	6d                   	ins    DWORD PTR es:[rdi],dx
    1a35:	00 2e                	add    BYTE PTR [rsi],ch
    1a37:	64 79 6e             	fs jns 0x1aa8
    1a3a:	73 74                	jae    0x1ab0
    1a3c:	72 00                	jb     0x1a3e
    1a3e:	2e 67 6e             	outs   dx,BYTE PTR ds:[esi]
    1a41:	75 2e                	jne    0x1a71
    1a43:	76 65                	jbe    0x1aaa
    1a45:	72 73                	jb     0x1aba
    1a47:	69 6f 6e 00 2e 67 6e 	imul   ebp,DWORD PTR [rdi+0x6e],0x6e672e00
    1a4e:	75 2e                	jne    0x1a7e
    1a50:	76 65                	jbe    0x1ab7
    1a52:	72 73                	jb     0x1ac7
    1a54:	69 6f 6e 5f 72 00 2e 	imul   ebp,DWORD PTR [rdi+0x6e],0x2e00725f
    1a5b:	72 65                	jb     0x1ac2
    1a5d:	6c                   	ins    BYTE PTR es:[rdi],dx
    1a5e:	61                   	(bad)
    1a5f:	2e 64 79 6e          	cs fs jns 0x1ad1
    1a63:	00 2e                	add    BYTE PTR [rsi],ch
    1a65:	72 65                	jb     0x1acc
    1a67:	6c                   	ins    BYTE PTR es:[rdi],dx
    1a68:	61                   	(bad)
    1a69:	2e 70 6c             	cs jo  0x1ad8
    1a6c:	74 00                	je     0x1a6e
    1a6e:	2e 69 6e 69 74 00 2e 	cs imul ebp,DWORD PTR [rsi+0x69],0x702e0074
    1a75:	70 
    1a76:	6c                   	ins    BYTE PTR es:[rdi],dx
    1a77:	74 2e                	je     0x1aa7
    1a79:	67 6f                	outs   dx,DWORD PTR ds:[esi]
    1a7b:	74 00                	je     0x1a7d
    1a7d:	2e 74 65             	cs je  0x1ae5
    1a80:	78 74                	js     0x1af6
    1a82:	00 2e                	add    BYTE PTR [rsi],ch
    1a84:	66 69 6e 69 00 2e    	imul   bp,WORD PTR [rsi+0x69],0x2e00
    1a8a:	72 6f                	jb     0x1afb
    1a8c:	64 61                	fs (bad)
    1a8e:	74 61                	je     0x1af1
    1a90:	00 2e                	add    BYTE PTR [rsi],ch
    1a92:	65 68 5f 66 72 61    	gs push 0x6172665f
    1a98:	6d                   	ins    DWORD PTR es:[rdi],dx
    1a99:	65 5f                	gs pop rdi
    1a9b:	68 64 72 00 2e       	push   0x2e007264
    1aa0:	65 68 5f 66 72 61    	gs push 0x6172665f
    1aa6:	6d                   	ins    DWORD PTR es:[rdi],dx
    1aa7:	65 00 2e             	add    BYTE PTR gs:[rsi],ch
    1aaa:	69 6e 69 74 5f 61 72 	imul   ebp,DWORD PTR [rsi+0x69],0x72615f74
    1ab1:	72 61                	jb     0x1b14
    1ab3:	79 00                	jns    0x1ab5
    1ab5:	2e 66 69 6e 69 5f 61 	cs imul bp,WORD PTR [rsi+0x69],0x615f
    1abc:	72 72                	jb     0x1b30
    1abe:	61                   	(bad)
    1abf:	79 00                	jns    0x1ac1
    1ac1:	2e 64 79 6e          	cs fs jns 0x1b33
    1ac5:	61                   	(bad)
    1ac6:	6d                   	ins    DWORD PTR es:[rdi],dx
    1ac7:	69 63 00 2e 64 61 74 	imul   esp,DWORD PTR [rbx+0x0],0x7461642e
    1ace:	61                   	(bad)
    1acf:	00 2e                	add    BYTE PTR [rsi],ch
    1ad1:	62 73 73 00 2e       	(bad)
    1ad6:	63 6f 6d             	movsxd ebp,DWORD PTR [rdi+0x6d]
    1ad9:	6d                   	ins    DWORD PTR es:[rdi],dx
    1ada:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
    1adc:	74 00                	je     0x1ade
	...
    1b1e:	00 00                	add    BYTE PTR [rax],al
    1b20:	1b 00                	sbb    eax,DWORD PTR [rax]
    1b22:	00 00                	add    BYTE PTR [rax],al
    1b24:	01 00                	add    DWORD PTR [rax],eax
    1b26:	00 00                	add    BYTE PTR [rax],al
    1b28:	02 00                	add    al,BYTE PTR [rax]
    1b2a:	00 00                	add    BYTE PTR [rax],al
    1b2c:	00 00                	add    BYTE PTR [rax],al
    1b2e:	00 00                	add    BYTE PTR [rax],al
    1b30:	38 02                	cmp    BYTE PTR [rdx],al
    1b32:	00 00                	add    BYTE PTR [rax],al
    1b34:	00 00                	add    BYTE PTR [rax],al
    1b36:	00 00                	add    BYTE PTR [rax],al
    1b38:	38 02                	cmp    BYTE PTR [rdx],al
    1b3a:	00 00                	add    BYTE PTR [rax],al
    1b3c:	00 00                	add    BYTE PTR [rax],al
    1b3e:	00 00                	add    BYTE PTR [rax],al
    1b40:	1c 00                	sbb    al,0x0
	...
    1b4e:	00 00                	add    BYTE PTR [rax],al
    1b50:	01 00                	add    DWORD PTR [rax],eax
	...
    1b5e:	00 00                	add    BYTE PTR [rax],al
    1b60:	23 00                	and    eax,DWORD PTR [rax]
    1b62:	00 00                	add    BYTE PTR [rax],al
    1b64:	07                   	(bad)
    1b65:	00 00                	add    BYTE PTR [rax],al
    1b67:	00 02                	add    BYTE PTR [rdx],al
    1b69:	00 00                	add    BYTE PTR [rax],al
    1b6b:	00 00                	add    BYTE PTR [rax],al
    1b6d:	00 00                	add    BYTE PTR [rax],al
    1b6f:	00 54 02 00          	add    BYTE PTR [rdx+rax*1+0x0],dl
    1b73:	00 00                	add    BYTE PTR [rax],al
    1b75:	00 00                	add    BYTE PTR [rax],al
    1b77:	00 54 02 00          	add    BYTE PTR [rdx+rax*1+0x0],dl
    1b7b:	00 00                	add    BYTE PTR [rax],al
    1b7d:	00 00                	add    BYTE PTR [rax],al
    1b7f:	00 20                	add    BYTE PTR [rax],ah
	...
    1b8d:	00 00                	add    BYTE PTR [rax],al
    1b8f:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
    1b9e:	00 00                	add    BYTE PTR [rax],al
    1ba0:	31 00                	xor    DWORD PTR [rax],eax
    1ba2:	00 00                	add    BYTE PTR [rax],al
    1ba4:	07                   	(bad)
    1ba5:	00 00                	add    BYTE PTR [rax],al
    1ba7:	00 02                	add    BYTE PTR [rdx],al
    1ba9:	00 00                	add    BYTE PTR [rax],al
    1bab:	00 00                	add    BYTE PTR [rax],al
    1bad:	00 00                	add    BYTE PTR [rax],al
    1baf:	00 74 02 00          	add    BYTE PTR [rdx+rax*1+0x0],dh
    1bb3:	00 00                	add    BYTE PTR [rax],al
    1bb5:	00 00                	add    BYTE PTR [rax],al
    1bb7:	00 74 02 00          	add    BYTE PTR [rdx+rax*1+0x0],dh
    1bbb:	00 00                	add    BYTE PTR [rax],al
    1bbd:	00 00                	add    BYTE PTR [rax],al
    1bbf:	00 24 00             	add    BYTE PTR [rax+rax*1],ah
	...
    1bce:	00 00                	add    BYTE PTR [rax],al
    1bd0:	04 00                	add    al,0x0
	...
    1bde:	00 00                	add    BYTE PTR [rax],al
    1be0:	44 00 00             	add    BYTE PTR [rax],r8b
    1be3:	00 f6                	add    dh,dh
    1be5:	ff                   	(bad)
    1be6:	ff 6f 02             	jmp    FWORD PTR [rdi+0x2]
    1be9:	00 00                	add    BYTE PTR [rax],al
    1beb:	00 00                	add    BYTE PTR [rax],al
    1bed:	00 00                	add    BYTE PTR [rax],al
    1bef:	00 98 02 00 00 00    	add    BYTE PTR [rax+0x2],bl
    1bf5:	00 00                	add    BYTE PTR [rax],al
    1bf7:	00 98 02 00 00 00    	add    BYTE PTR [rax+0x2],bl
    1bfd:	00 00                	add    BYTE PTR [rax],al
    1bff:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    1c02:	00 00                	add    BYTE PTR [rax],al
    1c04:	00 00                	add    BYTE PTR [rax],al
    1c06:	00 00                	add    BYTE PTR [rax],al
    1c08:	05 00 00 00 00       	add    eax,0x0
    1c0d:	00 00                	add    BYTE PTR [rax],al
    1c0f:	00 08                	add    BYTE PTR [rax],cl
	...
    1c1d:	00 00                	add    BYTE PTR [rax],al
    1c1f:	00 4e 00             	add    BYTE PTR [rsi+0x0],cl
    1c22:	00 00                	add    BYTE PTR [rax],al
    1c24:	0b 00                	or     eax,DWORD PTR [rax]
    1c26:	00 00                	add    BYTE PTR [rax],al
    1c28:	02 00                	add    al,BYTE PTR [rax]
    1c2a:	00 00                	add    BYTE PTR [rax],al
    1c2c:	00 00                	add    BYTE PTR [rax],al
    1c2e:	00 00                	add    BYTE PTR [rax],al
    1c30:	b8 02 00 00 00       	mov    eax,0x2
    1c35:	00 00                	add    BYTE PTR [rax],al
    1c37:	00 b8 02 00 00 00    	add    BYTE PTR [rax+0x2],bh
    1c3d:	00 00                	add    BYTE PTR [rax],al
    1c3f:	00 68 01             	add    BYTE PTR [rax+0x1],ch
    1c42:	00 00                	add    BYTE PTR [rax],al
    1c44:	00 00                	add    BYTE PTR [rax],al
    1c46:	00 00                	add    BYTE PTR [rax],al
    1c48:	06                   	(bad)
    1c49:	00 00                	add    BYTE PTR [rax],al
    1c4b:	00 01                	add    BYTE PTR [rcx],al
    1c4d:	00 00                	add    BYTE PTR [rax],al
    1c4f:	00 08                	add    BYTE PTR [rax],cl
    1c51:	00 00                	add    BYTE PTR [rax],al
    1c53:	00 00                	add    BYTE PTR [rax],al
    1c55:	00 00                	add    BYTE PTR [rax],al
    1c57:	00 18                	add    BYTE PTR [rax],bl
    1c59:	00 00                	add    BYTE PTR [rax],al
    1c5b:	00 00                	add    BYTE PTR [rax],al
    1c5d:	00 00                	add    BYTE PTR [rax],al
    1c5f:	00 56 00             	add    BYTE PTR [rsi+0x0],dl
    1c62:	00 00                	add    BYTE PTR [rax],al
    1c64:	03 00                	add    eax,DWORD PTR [rax]
    1c66:	00 00                	add    BYTE PTR [rax],al
    1c68:	02 00                	add    al,BYTE PTR [rax]
    1c6a:	00 00                	add    BYTE PTR [rax],al
    1c6c:	00 00                	add    BYTE PTR [rax],al
    1c6e:	00 00                	add    BYTE PTR [rax],al
    1c70:	20 04 00             	and    BYTE PTR [rax+rax*1],al
    1c73:	00 00                	add    BYTE PTR [rax],al
    1c75:	00 00                	add    BYTE PTR [rax],al
    1c77:	00 20                	add    BYTE PTR [rax],ah
    1c79:	04 00                	add    al,0x0
    1c7b:	00 00                	add    BYTE PTR [rax],al
    1c7d:	00 00                	add    BYTE PTR [rax],al
    1c7f:	00 b7 00 00 00 00    	add    BYTE PTR [rdi+0x0],dh
	...
    1c8d:	00 00                	add    BYTE PTR [rax],al
    1c8f:	00 01                	add    BYTE PTR [rcx],al
	...
    1c9d:	00 00                	add    BYTE PTR [rax],al
    1c9f:	00 5e 00             	add    BYTE PTR [rsi+0x0],bl
    1ca2:	00 00                	add    BYTE PTR [rax],al
    1ca4:	ff                   	(bad)
    1ca5:	ff                   	(bad)
    1ca6:	ff 6f 02             	jmp    FWORD PTR [rdi+0x2]
    1ca9:	00 00                	add    BYTE PTR [rax],al
    1cab:	00 00                	add    BYTE PTR [rax],al
    1cad:	00 00                	add    BYTE PTR [rax],al
    1caf:	00 d8                	add    al,bl
    1cb1:	04 00                	add    al,0x0
    1cb3:	00 00                	add    BYTE PTR [rax],al
    1cb5:	00 00                	add    BYTE PTR [rax],al
    1cb7:	00 d8                	add    al,bl
    1cb9:	04 00                	add    al,0x0
    1cbb:	00 00                	add    BYTE PTR [rax],al
    1cbd:	00 00                	add    BYTE PTR [rax],al
    1cbf:	00 1e                	add    BYTE PTR [rsi],bl
    1cc1:	00 00                	add    BYTE PTR [rax],al
    1cc3:	00 00                	add    BYTE PTR [rax],al
    1cc5:	00 00                	add    BYTE PTR [rax],al
    1cc7:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 0x1ccd
    1ccd:	00 00                	add    BYTE PTR [rax],al
    1ccf:	00 02                	add    BYTE PTR [rdx],al
    1cd1:	00 00                	add    BYTE PTR [rax],al
    1cd3:	00 00                	add    BYTE PTR [rax],al
    1cd5:	00 00                	add    BYTE PTR [rax],al
    1cd7:	00 02                	add    BYTE PTR [rdx],al
    1cd9:	00 00                	add    BYTE PTR [rax],al
    1cdb:	00 00                	add    BYTE PTR [rax],al
    1cdd:	00 00                	add    BYTE PTR [rax],al
    1cdf:	00 6b 00             	add    BYTE PTR [rbx+0x0],ch
    1ce2:	00 00                	add    BYTE PTR [rax],al
    1ce4:	fe                   	(bad)
    1ce5:	ff                   	(bad)
    1ce6:	ff 6f 02             	jmp    FWORD PTR [rdi+0x2]
    1ce9:	00 00                	add    BYTE PTR [rax],al
    1ceb:	00 00                	add    BYTE PTR [rax],al
    1ced:	00 00                	add    BYTE PTR [rax],al
    1cef:	00 f8                	add    al,bh
    1cf1:	04 00                	add    al,0x0
    1cf3:	00 00                	add    BYTE PTR [rax],al
    1cf5:	00 00                	add    BYTE PTR [rax],al
    1cf7:	00 f8                	add    al,bh
    1cf9:	04 00                	add    al,0x0
    1cfb:	00 00                	add    BYTE PTR [rax],al
    1cfd:	00 00                	add    BYTE PTR [rax],al
    1cff:	00 20                	add    BYTE PTR [rax],ah
    1d01:	00 00                	add    BYTE PTR [rax],al
    1d03:	00 00                	add    BYTE PTR [rax],al
    1d05:	00 00                	add    BYTE PTR [rax],al
    1d07:	00 06                	add    BYTE PTR [rsi],al
    1d09:	00 00                	add    BYTE PTR [rax],al
    1d0b:	00 01                	add    BYTE PTR [rcx],al
    1d0d:	00 00                	add    BYTE PTR [rax],al
    1d0f:	00 08                	add    BYTE PTR [rax],cl
	...
    1d1d:	00 00                	add    BYTE PTR [rax],al
    1d1f:	00 7a 00             	add    BYTE PTR [rdx+0x0],bh
    1d22:	00 00                	add    BYTE PTR [rax],al
    1d24:	04 00                	add    al,0x0
    1d26:	00 00                	add    BYTE PTR [rax],al
    1d28:	02 00                	add    al,BYTE PTR [rax]
    1d2a:	00 00                	add    BYTE PTR [rax],al
    1d2c:	00 00                	add    BYTE PTR [rax],al
    1d2e:	00 00                	add    BYTE PTR [rax],al
    1d30:	18 05 00 00 00 00    	sbb    BYTE PTR [rip+0x0],al        # 0x1d36
    1d36:	00 00                	add    BYTE PTR [rax],al
    1d38:	18 05 00 00 00 00    	sbb    BYTE PTR [rip+0x0],al        # 0x1d3e
    1d3e:	00 00                	add    BYTE PTR [rax],al
    1d40:	c0 00 00             	rol    BYTE PTR [rax],0x0
    1d43:	00 00                	add    BYTE PTR [rax],al
    1d45:	00 00                	add    BYTE PTR [rax],al
    1d47:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 0x1d4d
    1d4d:	00 00                	add    BYTE PTR [rax],al
    1d4f:	00 08                	add    BYTE PTR [rax],cl
    1d51:	00 00                	add    BYTE PTR [rax],al
    1d53:	00 00                	add    BYTE PTR [rax],al
    1d55:	00 00                	add    BYTE PTR [rax],al
    1d57:	00 18                	add    BYTE PTR [rax],bl
    1d59:	00 00                	add    BYTE PTR [rax],al
    1d5b:	00 00                	add    BYTE PTR [rax],al
    1d5d:	00 00                	add    BYTE PTR [rax],al
    1d5f:	00 84 00 00 00 04 00 	add    BYTE PTR [rax+rax*1+0x40000],al
    1d66:	00 00                	add    BYTE PTR [rax],al
    1d68:	42 00 00             	rex.X add BYTE PTR [rax],al
    1d6b:	00 00                	add    BYTE PTR [rax],al
    1d6d:	00 00                	add    BYTE PTR [rax],al
    1d6f:	00 d8                	add    al,bl
    1d71:	05 00 00 00 00       	add    eax,0x0
    1d76:	00 00                	add    BYTE PTR [rax],al
    1d78:	d8 05 00 00 00 00    	fadd   DWORD PTR [rip+0x0]        # 0x1d7e
    1d7e:	00 00                	add    BYTE PTR [rax],al
    1d80:	d8 00                	fadd   DWORD PTR [rax]
    1d82:	00 00                	add    BYTE PTR [rax],al
    1d84:	00 00                	add    BYTE PTR [rax],al
    1d86:	00 00                	add    BYTE PTR [rax],al
    1d88:	05 00 00 00 16       	add    eax,0x16000000
    1d8d:	00 00                	add    BYTE PTR [rax],al
    1d8f:	00 08                	add    BYTE PTR [rax],cl
    1d91:	00 00                	add    BYTE PTR [rax],al
    1d93:	00 00                	add    BYTE PTR [rax],al
    1d95:	00 00                	add    BYTE PTR [rax],al
    1d97:	00 18                	add    BYTE PTR [rax],bl
    1d99:	00 00                	add    BYTE PTR [rax],al
    1d9b:	00 00                	add    BYTE PTR [rax],al
    1d9d:	00 00                	add    BYTE PTR [rax],al
    1d9f:	00 8e 00 00 00 01    	add    BYTE PTR [rsi+0x1000000],cl
    1da5:	00 00                	add    BYTE PTR [rax],al
    1da7:	00 06                	add    BYTE PTR [rsi],al
    1da9:	00 00                	add    BYTE PTR [rax],al
    1dab:	00 00                	add    BYTE PTR [rax],al
    1dad:	00 00                	add    BYTE PTR [rax],al
    1daf:	00 b0 06 00 00 00    	add    BYTE PTR [rax+0x6],dh
    1db5:	00 00                	add    BYTE PTR [rax],al
    1db7:	00 b0 06 00 00 00    	add    BYTE PTR [rax+0x6],dh
    1dbd:	00 00                	add    BYTE PTR [rax],al
    1dbf:	00 17                	add    BYTE PTR [rdi],dl
	...
    1dcd:	00 00                	add    BYTE PTR [rax],al
    1dcf:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
    1dde:	00 00                	add    BYTE PTR [rax],al
    1de0:	89 00                	mov    DWORD PTR [rax],eax
    1de2:	00 00                	add    BYTE PTR [rax],al
    1de4:	01 00                	add    DWORD PTR [rax],eax
    1de6:	00 00                	add    BYTE PTR [rax],al
    1de8:	06                   	(bad)
    1de9:	00 00                	add    BYTE PTR [rax],al
    1deb:	00 00                	add    BYTE PTR [rax],al
    1ded:	00 00                	add    BYTE PTR [rax],al
    1def:	00 d0                	add    al,dl
    1df1:	06                   	(bad)
    1df2:	00 00                	add    BYTE PTR [rax],al
    1df4:	00 00                	add    BYTE PTR [rax],al
    1df6:	00 00                	add    BYTE PTR [rax],al
    1df8:	d0 06                	rol    BYTE PTR [rsi],1
    1dfa:	00 00                	add    BYTE PTR [rax],al
    1dfc:	00 00                	add    BYTE PTR [rax],al
    1dfe:	00 00                	add    BYTE PTR [rax],al
    1e00:	a0 00 00 00 00 00 00 	movabs al,ds:0x0
    1e07:	00 00 
    1e09:	00 00                	add    BYTE PTR [rax],al
    1e0b:	00 00                	add    BYTE PTR [rax],al
    1e0d:	00 00                	add    BYTE PTR [rax],al
    1e0f:	00 10                	add    BYTE PTR [rax],dl
    1e11:	00 00                	add    BYTE PTR [rax],al
    1e13:	00 00                	add    BYTE PTR [rax],al
    1e15:	00 00                	add    BYTE PTR [rax],al
    1e17:	00 10                	add    BYTE PTR [rax],dl
    1e19:	00 00                	add    BYTE PTR [rax],al
    1e1b:	00 00                	add    BYTE PTR [rax],al
    1e1d:	00 00                	add    BYTE PTR [rax],al
    1e1f:	00 94 00 00 00 01 00 	add    BYTE PTR [rax+rax*1+0x10000],dl
    1e26:	00 00                	add    BYTE PTR [rax],al
    1e28:	06                   	(bad)
    1e29:	00 00                	add    BYTE PTR [rax],al
    1e2b:	00 00                	add    BYTE PTR [rax],al
    1e2d:	00 00                	add    BYTE PTR [rax],al
    1e2f:	00 70 07             	add    BYTE PTR [rax+0x7],dh
    1e32:	00 00                	add    BYTE PTR [rax],al
    1e34:	00 00                	add    BYTE PTR [rax],al
    1e36:	00 00                	add    BYTE PTR [rax],al
    1e38:	70 07                	jo     0x1e41
    1e3a:	00 00                	add    BYTE PTR [rax],al
    1e3c:	00 00                	add    BYTE PTR [rax],al
    1e3e:	00 00                	add    BYTE PTR [rax],al
    1e40:	08 00                	or     BYTE PTR [rax],al
	...
    1e4e:	00 00                	add    BYTE PTR [rax],al
    1e50:	08 00                	or     BYTE PTR [rax],al
    1e52:	00 00                	add    BYTE PTR [rax],al
    1e54:	00 00                	add    BYTE PTR [rax],al
    1e56:	00 00                	add    BYTE PTR [rax],al
    1e58:	08 00                	or     BYTE PTR [rax],al
    1e5a:	00 00                	add    BYTE PTR [rax],al
    1e5c:	00 00                	add    BYTE PTR [rax],al
    1e5e:	00 00                	add    BYTE PTR [rax],al
    1e60:	9d                   	popf
    1e61:	00 00                	add    BYTE PTR [rax],al
    1e63:	00 01                	add    BYTE PTR [rcx],al
    1e65:	00 00                	add    BYTE PTR [rax],al
    1e67:	00 06                	add    BYTE PTR [rsi],al
    1e69:	00 00                	add    BYTE PTR [rax],al
    1e6b:	00 00                	add    BYTE PTR [rax],al
    1e6d:	00 00                	add    BYTE PTR [rax],al
    1e6f:	00 80 07 00 00 00    	add    BYTE PTR [rax+0x7],al
    1e75:	00 00                	add    BYTE PTR [rax],al
    1e77:	00 80 07 00 00 00    	add    BYTE PTR [rax+0x7],al
    1e7d:	00 00                	add    BYTE PTR [rax],al
    1e7f:	00 ff                	add    bh,bh
    1e81:	03 00                	add    eax,DWORD PTR [rax]
	...
    1e8f:	00 10                	add    BYTE PTR [rax],dl
	...
    1e9d:	00 00                	add    BYTE PTR [rax],al
    1e9f:	00 a3 00 00 00 01    	add    BYTE PTR [rbx+0x1000000],ah
    1ea5:	00 00                	add    BYTE PTR [rax],al
    1ea7:	00 06                	add    BYTE PTR [rsi],al
    1ea9:	00 00                	add    BYTE PTR [rax],al
    1eab:	00 00                	add    BYTE PTR [rax],al
    1ead:	00 00                	add    BYTE PTR [rax],al
    1eaf:	00 80 0b 00 00 00    	add    BYTE PTR [rax+0xb],al
    1eb5:	00 00                	add    BYTE PTR [rax],al
    1eb7:	00 80 0b 00 00 00    	add    BYTE PTR [rax+0xb],al
    1ebd:	00 00                	add    BYTE PTR [rax],al
    1ebf:	00 09                	add    BYTE PTR [rcx],cl
	...
    1ecd:	00 00                	add    BYTE PTR [rax],al
    1ecf:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
    1ede:	00 00                	add    BYTE PTR [rax],al
    1ee0:	a9 00 00 00 01       	test   eax,0x1000000
    1ee5:	00 00                	add    BYTE PTR [rax],al
    1ee7:	00 02                	add    BYTE PTR [rdx],al
    1ee9:	00 00                	add    BYTE PTR [rax],al
    1eeb:	00 00                	add    BYTE PTR [rax],al
    1eed:	00 00                	add    BYTE PTR [rax],al
    1eef:	00 8c 0b 00 00 00 00 	add    BYTE PTR [rbx+rcx*1+0x0],cl
    1ef6:	00 00                	add    BYTE PTR [rax],al
    1ef8:	8c 0b                	mov    WORD PTR [rbx],cs
    1efa:	00 00                	add    BYTE PTR [rax],al
    1efc:	00 00                	add    BYTE PTR [rax],al
    1efe:	00 00                	add    BYTE PTR [rax],al
    1f00:	48 00 00             	rex.W add BYTE PTR [rax],al
	...
    1f0f:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
    1f1e:	00 00                	add    BYTE PTR [rax],al
    1f20:	b1 00                	mov    cl,0x0
    1f22:	00 00                	add    BYTE PTR [rax],al
    1f24:	01 00                	add    DWORD PTR [rax],eax
    1f26:	00 00                	add    BYTE PTR [rax],al
    1f28:	02 00                	add    al,BYTE PTR [rax]
    1f2a:	00 00                	add    BYTE PTR [rax],al
    1f2c:	00 00                	add    BYTE PTR [rax],al
    1f2e:	00 00                	add    BYTE PTR [rax],al
    1f30:	d4                   	(bad)
    1f31:	0b 00                	or     eax,DWORD PTR [rax]
    1f33:	00 00                	add    BYTE PTR [rax],al
    1f35:	00 00                	add    BYTE PTR [rax],al
    1f37:	00 d4                	add    ah,dl
    1f39:	0b 00                	or     eax,DWORD PTR [rax]
    1f3b:	00 00                	add    BYTE PTR [rax],al
    1f3d:	00 00                	add    BYTE PTR [rax],al
    1f3f:	00 4c 00 00          	add    BYTE PTR [rax+rax*1+0x0],cl
	...
    1f4f:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
    1f5e:	00 00                	add    BYTE PTR [rax],al
    1f60:	bf 00 00 00 01       	mov    edi,0x1000000
    1f65:	00 00                	add    BYTE PTR [rax],al
    1f67:	00 02                	add    BYTE PTR [rdx],al
    1f69:	00 00                	add    BYTE PTR [rax],al
    1f6b:	00 00                	add    BYTE PTR [rax],al
    1f6d:	00 00                	add    BYTE PTR [rax],al
    1f6f:	00 20                	add    BYTE PTR [rax],ah
    1f71:	0c 00                	or     al,0x0
    1f73:	00 00                	add    BYTE PTR [rax],al
    1f75:	00 00                	add    BYTE PTR [rax],al
    1f77:	00 20                	add    BYTE PTR [rax],ah
    1f79:	0c 00                	or     al,0x0
    1f7b:	00 00                	add    BYTE PTR [rax],al
    1f7d:	00 00                	add    BYTE PTR [rax],al
    1f7f:	00 40 01             	add    BYTE PTR [rax+0x1],al
	...
    1f8e:	00 00                	add    BYTE PTR [rax],al
    1f90:	08 00                	or     BYTE PTR [rax],al
	...
    1f9e:	00 00                	add    BYTE PTR [rax],al
    1fa0:	c9                   	leave
    1fa1:	00 00                	add    BYTE PTR [rax],al
    1fa3:	00 0e                	add    BYTE PTR [rsi],cl
    1fa5:	00 00                	add    BYTE PTR [rax],al
    1fa7:	00 03                	add    BYTE PTR [rbx],al
    1fa9:	00 00                	add    BYTE PTR [rax],al
    1fab:	00 00                	add    BYTE PTR [rax],al
    1fad:	00 00                	add    BYTE PTR [rax],al
    1faf:	00 78 0d             	add    BYTE PTR [rax+0xd],bh
    1fb2:	20 00                	and    BYTE PTR [rax],al
    1fb4:	00 00                	add    BYTE PTR [rax],al
    1fb6:	00 00                	add    BYTE PTR [rax],al
    1fb8:	78 0d                	js     0x1fc7
    1fba:	00 00                	add    BYTE PTR [rax],al
    1fbc:	00 00                	add    BYTE PTR [rax],al
    1fbe:	00 00                	add    BYTE PTR [rax],al
    1fc0:	08 00                	or     BYTE PTR [rax],al
	...
    1fce:	00 00                	add    BYTE PTR [rax],al
    1fd0:	08 00                	or     BYTE PTR [rax],al
    1fd2:	00 00                	add    BYTE PTR [rax],al
    1fd4:	00 00                	add    BYTE PTR [rax],al
    1fd6:	00 00                	add    BYTE PTR [rax],al
    1fd8:	08 00                	or     BYTE PTR [rax],al
    1fda:	00 00                	add    BYTE PTR [rax],al
    1fdc:	00 00                	add    BYTE PTR [rax],al
    1fde:	00 00                	add    BYTE PTR [rax],al
    1fe0:	d5 00 00 00          	{rex2 0x0} add BYTE PTR [rax],al
    1fe4:	0f 00 00             	sldt   WORD PTR [rax]
    1fe7:	00 03                	add    BYTE PTR [rbx],al
    1fe9:	00 00                	add    BYTE PTR [rax],al
    1feb:	00 00                	add    BYTE PTR [rax],al
    1fed:	00 00                	add    BYTE PTR [rax],al
    1fef:	00 80 0d 20 00 00    	add    BYTE PTR [rax+0x200d],al
    1ff5:	00 00                	add    BYTE PTR [rax],al
    1ff7:	00 80 0d 00 00 00    	add    BYTE PTR [rax+0xd],al
    1ffd:	00 00                	add    BYTE PTR [rax],al
    1fff:	00 08                	add    BYTE PTR [rax],cl
	...
    200d:	00 00                	add    BYTE PTR [rax],al
    200f:	00 08                	add    BYTE PTR [rax],cl
    2011:	00 00                	add    BYTE PTR [rax],al
    2013:	00 00                	add    BYTE PTR [rax],al
    2015:	00 00                	add    BYTE PTR [rax],al
    2017:	00 08                	add    BYTE PTR [rax],cl
    2019:	00 00                	add    BYTE PTR [rax],al
    201b:	00 00                	add    BYTE PTR [rax],al
    201d:	00 00                	add    BYTE PTR [rax],al
    201f:	00 e1                	add    cl,ah
    2021:	00 00                	add    BYTE PTR [rax],al
    2023:	00 06                	add    BYTE PTR [rsi],al
    2025:	00 00                	add    BYTE PTR [rax],al
    2027:	00 03                	add    BYTE PTR [rbx],al
    2029:	00 00                	add    BYTE PTR [rax],al
    202b:	00 00                	add    BYTE PTR [rax],al
    202d:	00 00                	add    BYTE PTR [rax],al
    202f:	00 88 0d 20 00 00    	add    BYTE PTR [rax+0x200d],cl
    2035:	00 00                	add    BYTE PTR [rax],al
    2037:	00 88 0d 00 00 00    	add    BYTE PTR [rax+0xd],cl
    203d:	00 00                	add    BYTE PTR [rax],al
    203f:	00 f0                	add    al,dh
    2041:	01 00                	add    DWORD PTR [rax],eax
    2043:	00 00                	add    BYTE PTR [rax],al
    2045:	00 00                	add    BYTE PTR [rax],al
    2047:	00 06                	add    BYTE PTR [rsi],al
    2049:	00 00                	add    BYTE PTR [rax],al
    204b:	00 00                	add    BYTE PTR [rax],al
    204d:	00 00                	add    BYTE PTR [rax],al
    204f:	00 08                	add    BYTE PTR [rax],cl
    2051:	00 00                	add    BYTE PTR [rax],al
    2053:	00 00                	add    BYTE PTR [rax],al
    2055:	00 00                	add    BYTE PTR [rax],al
    2057:	00 10                	add    BYTE PTR [rax],dl
    2059:	00 00                	add    BYTE PTR [rax],al
    205b:	00 00                	add    BYTE PTR [rax],al
    205d:	00 00                	add    BYTE PTR [rax],al
    205f:	00 98 00 00 00 01    	add    BYTE PTR [rax+0x1000000],bl
    2065:	00 00                	add    BYTE PTR [rax],al
    2067:	00 03                	add    BYTE PTR [rbx],al
    2069:	00 00                	add    BYTE PTR [rax],al
    206b:	00 00                	add    BYTE PTR [rax],al
    206d:	00 00                	add    BYTE PTR [rax],al
    206f:	00 78 0f             	add    BYTE PTR [rax+0xf],bh
    2072:	20 00                	and    BYTE PTR [rax],al
    2074:	00 00                	add    BYTE PTR [rax],al
    2076:	00 00                	add    BYTE PTR [rax],al
    2078:	78 0f                	js     0x2089
    207a:	00 00                	add    BYTE PTR [rax],al
    207c:	00 00                	add    BYTE PTR [rax],al
    207e:	00 00                	add    BYTE PTR [rax],al
    2080:	88 00                	mov    BYTE PTR [rax],al
	...
    208e:	00 00                	add    BYTE PTR [rax],al
    2090:	08 00                	or     BYTE PTR [rax],al
    2092:	00 00                	add    BYTE PTR [rax],al
    2094:	00 00                	add    BYTE PTR [rax],al
    2096:	00 00                	add    BYTE PTR [rax],al
    2098:	08 00                	or     BYTE PTR [rax],al
    209a:	00 00                	add    BYTE PTR [rax],al
    209c:	00 00                	add    BYTE PTR [rax],al
    209e:	00 00                	add    BYTE PTR [rax],al
    20a0:	ea                   	(bad)
    20a1:	00 00                	add    BYTE PTR [rax],al
    20a3:	00 01                	add    BYTE PTR [rcx],al
    20a5:	00 00                	add    BYTE PTR [rax],al
    20a7:	00 03                	add    BYTE PTR [rbx],al
	...
    20b1:	10 20                	adc    BYTE PTR [rax],ah
    20b3:	00 00                	add    BYTE PTR [rax],al
    20b5:	00 00                	add    BYTE PTR [rax],al
    20b7:	00 00                	add    BYTE PTR [rax],al
    20b9:	10 00                	adc    BYTE PTR [rax],al
    20bb:	00 00                	add    BYTE PTR [rax],al
    20bd:	00 00                	add    BYTE PTR [rax],al
    20bf:	00 10                	add    BYTE PTR [rax],dl
	...
    20cd:	00 00                	add    BYTE PTR [rax],al
    20cf:	00 08                	add    BYTE PTR [rax],cl
	...
    20dd:	00 00                	add    BYTE PTR [rax],al
    20df:	00 f0                	add    al,dh
    20e1:	00 00                	add    BYTE PTR [rax],al
    20e3:	00 08                	add    BYTE PTR [rax],cl
    20e5:	00 00                	add    BYTE PTR [rax],al
    20e7:	00 03                	add    BYTE PTR [rbx],al
    20e9:	00 00                	add    BYTE PTR [rax],al
    20eb:	00 00                	add    BYTE PTR [rax],al
    20ed:	00 00                	add    BYTE PTR [rax],al
    20ef:	00 10                	add    BYTE PTR [rax],dl
    20f1:	10 20                	adc    BYTE PTR [rax],ah
    20f3:	00 00                	add    BYTE PTR [rax],al
    20f5:	00 00                	add    BYTE PTR [rax],al
    20f7:	00 10                	add    BYTE PTR [rax],dl
    20f9:	10 00                	adc    BYTE PTR [rax],al
    20fb:	00 00                	add    BYTE PTR [rax],al
    20fd:	00 00                	add    BYTE PTR [rax],al
    20ff:	00 08                	add    BYTE PTR [rax],cl
	...
    210d:	00 00                	add    BYTE PTR [rax],al
    210f:	00 01                	add    BYTE PTR [rcx],al
	...
    211d:	00 00                	add    BYTE PTR [rax],al
    211f:	00 f5                	add    ch,dh
    2121:	00 00                	add    BYTE PTR [rax],al
    2123:	00 01                	add    BYTE PTR [rcx],al
    2125:	00 00                	add    BYTE PTR [rax],al
    2127:	00 30                	add    BYTE PTR [rax],dh
	...
    2135:	00 00                	add    BYTE PTR [rax],al
    2137:	00 10                	add    BYTE PTR [rax],dl
    2139:	10 00                	adc    BYTE PTR [rax],al
    213b:	00 00                	add    BYTE PTR [rax],al
    213d:	00 00                	add    BYTE PTR [rax],al
    213f:	00 29                	add    BYTE PTR [rcx],ch
	...
    214d:	00 00                	add    BYTE PTR [rax],al
    214f:	00 01                	add    BYTE PTR [rcx],al
    2151:	00 00                	add    BYTE PTR [rax],al
    2153:	00 00                	add    BYTE PTR [rax],al
    2155:	00 00                	add    BYTE PTR [rax],al
    2157:	00 01                	add    BYTE PTR [rcx],al
    2159:	00 00                	add    BYTE PTR [rax],al
    215b:	00 00                	add    BYTE PTR [rax],al
    215d:	00 00                	add    BYTE PTR [rax],al
    215f:	00 01                	add    BYTE PTR [rcx],al
    2161:	00 00                	add    BYTE PTR [rax],al
    2163:	00 02                	add    BYTE PTR [rdx],al
	...
    2175:	00 00                	add    BYTE PTR [rax],al
    2177:	00 40 10             	add    BYTE PTR [rax+0x10],al
    217a:	00 00                	add    BYTE PTR [rax],al
    217c:	00 00                	add    BYTE PTR [rax],al
    217e:	00 00                	add    BYTE PTR [rax],al
    2180:	f0 06                	lock (bad)
    2182:	00 00                	add    BYTE PTR [rax],al
    2184:	00 00                	add    BYTE PTR [rax],al
    2186:	00 00                	add    BYTE PTR [rax],al
    2188:	1b 00                	sbb    eax,DWORD PTR [rax]
    218a:	00 00                	add    BYTE PTR [rax],al
    218c:	2d 00 00 00 08       	sub    eax,0x8000000
    2191:	00 00                	add    BYTE PTR [rax],al
    2193:	00 00                	add    BYTE PTR [rax],al
    2195:	00 00                	add    BYTE PTR [rax],al
    2197:	00 18                	add    BYTE PTR [rax],bl
    2199:	00 00                	add    BYTE PTR [rax],al
    219b:	00 00                	add    BYTE PTR [rax],al
    219d:	00 00                	add    BYTE PTR [rax],al
    219f:	00 09                	add    BYTE PTR [rcx],cl
    21a1:	00 00                	add    BYTE PTR [rax],al
    21a3:	00 03                	add    BYTE PTR [rbx],al
	...
    21b5:	00 00                	add    BYTE PTR [rax],al
    21b7:	00 30                	add    BYTE PTR [rax],dh
    21b9:	17                   	(bad)
    21ba:	00 00                	add    BYTE PTR [rax],al
    21bc:	00 00                	add    BYTE PTR [rax],al
    21be:	00 00                	add    BYTE PTR [rax],al
    21c0:	b0 02                	mov    al,0x2
	...
    21ce:	00 00                	add    BYTE PTR [rax],al
    21d0:	01 00                	add    DWORD PTR [rax],eax
	...
    21de:	00 00                	add    BYTE PTR [rax],al
    21e0:	11 00                	adc    DWORD PTR [rax],eax
    21e2:	00 00                	add    BYTE PTR [rax],al
    21e4:	03 00                	add    eax,DWORD PTR [rax]
	...
    21f6:	00 00                	add    BYTE PTR [rax],al
    21f8:	e0 19                	loopne 0x2213
    21fa:	00 00                	add    BYTE PTR [rax],al
    21fc:	00 00                	add    BYTE PTR [rax],al
    21fe:	00 00                	add    BYTE PTR [rax],al
    2200:	fe 00                	inc    BYTE PTR [rax]
	...
    220e:	00 00                	add    BYTE PTR [rax],al
    2210:	01 00                	add    DWORD PTR [rax],eax
	...
