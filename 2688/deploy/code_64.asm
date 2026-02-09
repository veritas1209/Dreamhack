
code_dump.bin:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
       0:	53                   	push   %rbx
       1:	83 ec 08             	sub    $0x8,%esp
       4:	e8 b7 00 00 00       	call   0xc0
       9:	81 c3 eb 3f 00 00    	add    $0x3feb,%ebx
       f:	8b 83 f8 ff ff ff    	mov    -0x8(%rbx),%eax
      15:	85 c0                	test   %eax,%eax
      17:	74 02                	je     0x1b
      19:	ff d0                	call   *%rax
      1b:	83 c4 08             	add    $0x8,%esp
      1e:	5b                   	pop    %rbx
      1f:	c3                   	ret
      20:	ff 35 f8 cf 04 08    	push   0x804cff8(%rip)        # 0x804d01e
      26:	ff 25 fc cf 04 08    	jmp    *0x804cffc(%rip)        # 0x804d028
      2c:	00 00                	add    %al,(%rax)
      2e:	00 00                	add    %al,(%rax)
      30:	ff 25 00 d0 04 08    	jmp    *0x804d000(%rip)        # 0x804d036
      36:	68 00 00 00 00       	push   $0x0
      3b:	e9 e0 ff ff ff       	jmp    0x20
      40:	ff 25 04 d0 04 08    	jmp    *0x804d004(%rip)        # 0x804d04a
      46:	68 08 00 00 00       	push   $0x8
      4b:	e9 d0 ff ff ff       	jmp    0x20
      50:	ff 25 08 d0 04 08    	jmp    *0x804d008(%rip)        # 0x804d05e
      56:	68 10 00 00 00       	push   $0x10
      5b:	e9 c0 ff ff ff       	jmp    0x20
      60:	ff 25 0c d0 04 08    	jmp    *0x804d00c(%rip)        # 0x804d072
      66:	68 18 00 00 00       	push   $0x18
      6b:	e9 b0 ff ff ff       	jmp    0x20
      70:	31 ed                	xor    %ebp,%ebp
      72:	5e                   	pop    %rsi
      73:	89 e1                	mov    %esp,%ecx
      75:	83 e4 f0             	and    $0xfffffff0,%esp
      78:	50                   	push   %rax
      79:	54                   	push   %rsp
      7a:	52                   	push   %rdx
      7b:	e8 19 00 00 00       	call   0x99
      80:	81 c3 74 3f 00 00    	add    $0x3f74,%ebx
      86:	6a 00                	push   $0x0
      88:	6a 00                	push   $0x0
      8a:	51                   	push   %rcx
      8b:	56                   	push   %rsi
      8c:	8d 83 a9 c0 ff ff    	lea    -0x3f57(%rbx),%eax
      92:	50                   	push   %rax
      93:	e8 98 ff ff ff       	call   0x30
      98:	f4                   	hlt
      99:	8b 1c 24             	mov    (%rsp),%ebx
      9c:	c3                   	ret
      9d:	e9 45 04 00 00       	jmp    0x4e7
      a2:	66 90                	xchg   %ax,%ax
      a4:	66 90                	xchg   %ax,%ax
      a6:	66 90                	xchg   %ax,%ax
      a8:	66 90                	xchg   %ax,%ax
      aa:	66 90                	xchg   %ax,%ax
      ac:	66 90                	xchg   %ax,%ax
      ae:	66 90                	xchg   %ax,%ax
      b0:	c3                   	ret
      b1:	66 90                	xchg   %ax,%ax
      b3:	66 90                	xchg   %ax,%ax
      b5:	66 90                	xchg   %ax,%ax
      b7:	66 90                	xchg   %ax,%ax
      b9:	66 90                	xchg   %ax,%ax
      bb:	66 90                	xchg   %ax,%ax
      bd:	66 90                	xchg   %ax,%ax
      bf:	90                   	nop
      c0:	8b 1c 24             	mov    (%rsp),%ebx
      c3:	c3                   	ret
      c4:	66 90                	xchg   %ax,%ax
      c6:	66 90                	xchg   %ax,%ax
      c8:	66 90                	xchg   %ax,%ax
      ca:	66 90                	xchg   %ax,%ax
      cc:	66 90                	xchg   %ax,%ax
      ce:	66 90                	xchg   %ax,%ax
      d0:	b8 18 d0 04 08       	mov    $0x804d018,%eax
      d5:	3d 18 d0 04 08       	cmp    $0x804d018,%eax
      da:	74 24                	je     0x100
      dc:	b8 00 00 00 00       	mov    $0x0,%eax
      e1:	85 c0                	test   %eax,%eax
      e3:	74 1b                	je     0x100
      e5:	55                   	push   %rbp
      e6:	89 e5                	mov    %esp,%ebp
      e8:	83 ec 14             	sub    $0x14,%esp
      eb:	68 18 d0 04 08       	push   $0x804d018
      f0:	ff d0                	call   *%rax
      f2:	83 c4 10             	add    $0x10,%esp
      f5:	c9                   	leave
      f6:	c3                   	ret
      f7:	2e 8d b4 26 00 00 00 	cs lea 0x0(%rsi,%riz,1),%esi
      fe:	00 
      ff:	90                   	nop
     100:	c3                   	ret
     101:	2e 8d b4 26 00 00 00 	cs lea 0x0(%rsi,%riz,1),%esi
     108:	00 
     109:	8d b4 26 00 00 00 00 	lea    0x0(%rsi,%riz,1),%esi
     110:	b8 18 d0 04 08       	mov    $0x804d018,%eax
     115:	2d 18 d0 04 08       	sub    $0x804d018,%eax
     11a:	89 c2                	mov    %eax,%edx
     11c:	c1 e8 1f             	shr    $0x1f,%eax
     11f:	c1 fa 02             	sar    $0x2,%edx
     122:	01 d0                	add    %edx,%eax
     124:	d1 f8                	sar    $1,%eax
     126:	74 20                	je     0x148
     128:	ba 00 00 00 00       	mov    $0x0,%edx
     12d:	85 d2                	test   %edx,%edx
     12f:	74 17                	je     0x148
     131:	55                   	push   %rbp
     132:	89 e5                	mov    %esp,%ebp
     134:	83 ec 10             	sub    $0x10,%esp
     137:	50                   	push   %rax
     138:	68 18 d0 04 08       	push   $0x804d018
     13d:	ff d2                	call   *%rdx
     13f:	83 c4 10             	add    $0x10,%esp
     142:	c9                   	leave
     143:	c3                   	ret
     144:	8d 74 26 00          	lea    0x0(%rsi,%riz,1),%esi
     148:	c3                   	ret
     149:	8d b4 26 00 00 00 00 	lea    0x0(%rsi,%riz,1),%esi
     150:	f3 0f 1e fb          	endbr32
     154:	80 3d 18 d0 04 08 00 	cmpb   $0x0,0x804d018(%rip)        # 0x804d173
     15b:	75 1b                	jne    0x178
     15d:	55                   	push   %rbp
     15e:	89 e5                	mov    %esp,%ebp
     160:	83 ec 08             	sub    $0x8,%esp
     163:	e8 68 ff ff ff       	call   0xd0
     168:	c6 05 18 d0 04 08 01 	movb   $0x1,0x804d018(%rip)        # 0x804d187
     16f:	c9                   	leave
     170:	c3                   	ret
     171:	8d b4 26 00 00 00 00 	lea    0x0(%rsi,%riz,1),%esi
     178:	c3                   	ret
     179:	8d b4 26 00 00 00 00 	lea    0x0(%rsi,%riz,1),%esi
     180:	f3 0f 1e fb          	endbr32
     184:	eb 8a                	jmp    0x110
     186:	e8 90 1c 00 00       	call   0x1e1b
     18b:	05 69 3e 00 00       	add    $0x3e69,%eax
     190:	48 83 ec 60          	sub    $0x60,%rsp
     194:	48 8b 02             	mov    (%rdx),%rax
     197:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     19c:	48 8b 01             	mov    (%rcx),%rax
     19f:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     1a4:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     1a9:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
     1ae:	48 8d 14 18          	lea    (%rax,%rbx,1),%rdx
     1b2:	48 89 54 24 18       	mov    %rdx,0x18(%rsp)
     1b7:	48 31 c0             	xor    %rax,%rax
     1ba:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
     1bf:	48 89 c2             	mov    %rax,%rdx
     1c2:	48 83 c2 00          	add    $0x0,%rdx
     1c6:	48 31 c9             	xor    %rcx,%rcx
     1c9:	48 8d 0a             	lea    (%rdx),%rcx
     1cc:	48 89 c8             	mov    %rcx,%rax
     1cf:	48 89 06             	mov    %rax,(%rsi)
     1d2:	48 83 c4 60          	add    $0x60,%rsp
     1d6:	ff e7                	jmp    *%rdi
     1d8:	90                   	nop
     1d9:	0f 0b                	ud2
     1db:	e8 3b 1c 00 00       	call   0x1e1b
     1e0:	05 14 3e 00 00       	add    $0x3e14,%eax
     1e5:	48 83 ec 60          	sub    $0x60,%rsp
     1e9:	48 8b 02             	mov    (%rdx),%rax
     1ec:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     1f1:	48 8b 01             	mov    (%rcx),%rax
     1f4:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     1f9:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     1fe:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
     203:	48 0f af c3          	imul   %rbx,%rax
     207:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
     20c:	48 8b 4c 24 18       	mov    0x18(%rsp),%rcx
     211:	48 8d 11             	lea    (%rcx),%rdx
     214:	48 89 d0             	mov    %rdx,%rax
     217:	48 89 06             	mov    %rax,(%rsi)
     21a:	48 83 c4 60          	add    $0x60,%rsp
     21e:	ff e7                	jmp    *%rdi
     220:	90                   	nop
     221:	0f 0b                	ud2
     223:	e8 f3 1b 00 00       	call   0x1e1b
     228:	05 cc 3d 00 00       	add    $0x3dcc,%eax
     22d:	48 83 ec 60          	sub    $0x60,%rsp
     231:	48 8b 02             	mov    (%rdx),%rax
     234:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     239:	48 8b 01             	mov    (%rcx),%rax
     23c:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     241:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     246:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
     24b:	48 89 c1             	mov    %rax,%rcx
     24e:	48 31 d9             	xor    %rbx,%rcx
     251:	48 89 4c 24 18       	mov    %rcx,0x18(%rsp)
     256:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
     25b:	48 89 06             	mov    %rax,(%rsi)
     25e:	48 83 c4 60          	add    $0x60,%rsp
     262:	ff e7                	jmp    *%rdi
     264:	90                   	nop
     265:	0f 0b                	ud2
     267:	e8 af 1b 00 00       	call   0x1e1b
     26c:	05 88 3d 00 00       	add    $0x3d88,%eax
     271:	48 83 ec 60          	sub    $0x60,%rsp
     275:	48 8b 02             	mov    (%rdx),%rax
     278:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     27d:	48 8b 01             	mov    (%rcx),%rax
     280:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     285:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     28a:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
     28f:	48 21 d8             	and    %rbx,%rax
     292:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
     297:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
     29c:	48 89 06             	mov    %rax,(%rsi)
     29f:	48 83 c4 60          	add    $0x60,%rsp
     2a3:	ff e7                	jmp    *%rdi
     2a5:	90                   	nop
     2a6:	0f 0b                	ud2
     2a8:	e8 6e 1b 00 00       	call   0x1e1b
     2ad:	05 47 3d 00 00       	add    $0x3d47,%eax
     2b2:	48 83 ec 60          	sub    $0x60,%rsp
     2b6:	48 8b 02             	mov    (%rdx),%rax
     2b9:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     2be:	48 8b 01             	mov    (%rcx),%rax
     2c1:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     2c6:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     2cb:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
     2d0:	48 09 d8             	or     %rbx,%rax
     2d3:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
     2d8:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
     2dd:	48 89 06             	mov    %rax,(%rsi)
     2e0:	48 83 c4 60          	add    $0x60,%rsp
     2e4:	ff e7                	jmp    *%rdi
     2e6:	90                   	nop
     2e7:	0f 0b                	ud2
     2e9:	e8 2d 1b 00 00       	call   0x1e1b
     2ee:	05 06 3d 00 00       	add    $0x3d06,%eax
     2f3:	48 83 ec 60          	sub    $0x60,%rsp
     2f7:	48 8b 02             	mov    (%rdx),%rax
     2fa:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     2ff:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     304:	48 89 06             	mov    %rax,(%rsi)
     307:	48 83 c4 60          	add    $0x60,%rsp
     30b:	ff e7                	jmp    *%rdi
     30d:	90                   	nop
     30e:	0f 0b                	ud2
     310:	e8 06 1b 00 00       	call   0x1e1b
     315:	05 df 3c 00 00       	add    $0x3cdf,%eax
     31a:	48 83 ec 60          	sub    $0x60,%rsp
     31e:	48 8b 02             	mov    (%rdx),%rax
     321:	48 f7 d0             	not    %rax
     324:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     329:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     32e:	48 89 06             	mov    %rax,(%rsi)
     331:	48 83 c4 60          	add    $0x60,%rsp
     335:	ff e7                	jmp    *%rdi
     337:	90                   	nop
     338:	0f 0b                	ud2
     33a:	e8 dc 1a 00 00       	call   0x1e1b
     33f:	05 b5 3c 00 00       	add    $0x3cb5,%eax
     344:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
     34b:	48 8b 02             	mov    (%rdx),%rax
     34e:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     353:	8a 09                	mov    (%rcx),%cl
     355:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     35a:	48 d3 e0             	shl    %cl,%rax
     35d:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     362:	48 8b 44 24 10       	mov    0x10(%rsp),%rax
     367:	48 89 06             	mov    %rax,(%rsi)
     36a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
     371:	ff e7                	jmp    *%rdi
     373:	90                   	nop
     374:	0f 0b                	ud2
     376:	e8 a0 1a 00 00       	call   0x1e1b
     37b:	05 79 3c 00 00       	add    $0x3c79,%eax
     380:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
     387:	48 8b 02             	mov    (%rdx),%rax
     38a:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     38f:	8a 09                	mov    (%rcx),%cl
     391:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     396:	48 d3 e8             	shr    %cl,%rax
     399:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     39e:	48 8b 44 24 10       	mov    0x10(%rsp),%rax
     3a3:	48 89 06             	mov    %rax,(%rsi)
     3a6:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
     3ad:	ff e7                	jmp    *%rdi
     3af:	90                   	nop
     3b0:	0f 0b                	ud2
     3b2:	e8 64 1a 00 00       	call   0x1e1b
     3b7:	05 3d 3c 00 00       	add    $0x3c3d,%eax
     3bc:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
     3c3:	48 8b 02             	mov    (%rdx),%rax
     3c6:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     3cb:	8a 09                	mov    (%rcx),%cl
     3cd:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     3d2:	48 d3 c0             	rol    %cl,%rax
     3d5:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     3da:	48 8b 44 24 10       	mov    0x10(%rsp),%rax
     3df:	48 89 06             	mov    %rax,(%rsi)
     3e2:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
     3e9:	ff e7                	jmp    *%rdi
     3eb:	90                   	nop
     3ec:	0f 0b                	ud2
     3ee:	e8 28 1a 00 00       	call   0x1e1b
     3f3:	05 01 3c 00 00       	add    $0x3c01,%eax
     3f8:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
     3ff:	48 8b 02             	mov    (%rdx),%rax
     402:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     407:	8a 09                	mov    (%rcx),%cl
     409:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     40e:	48 d3 c8             	ror    %cl,%rax
     411:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     416:	48 8b 44 24 10       	mov    0x10(%rsp),%rax
     41b:	48 89 06             	mov    %rax,(%rsi)
     41e:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
     425:	ff e7                	jmp    *%rdi
     427:	90                   	nop
     428:	0f 0b                	ud2
     42a:	e8 ec 19 00 00       	call   0x1e1b
     42f:	05 c5 3b 00 00       	add    $0x3bc5,%eax
     434:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
     43b:	48 8b 02             	mov    (%rdx),%rax
     43e:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     443:	48 8b 19             	mov    (%rcx),%rbx
     446:	48 31 d2             	xor    %rdx,%rdx
     449:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     44e:	48 f7 f3             	div    %rbx
     451:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     456:	48 8b 44 24 10       	mov    0x10(%rsp),%rax
     45b:	48 89 06             	mov    %rax,(%rsi)
     45e:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
     465:	ff e7                	jmp    *%rdi
     467:	90                   	nop
     468:	0f 0b                	ud2
     46a:	e8 ac 19 00 00       	call   0x1e1b
     46f:	05 85 3b 00 00       	add    $0x3b85,%eax
     474:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
     47b:	48 8b 02             	mov    (%rdx),%rax
     47e:	48 8b 19             	mov    (%rcx),%rbx
     481:	48 31 d2             	xor    %rdx,%rdx
     484:	48 f7 f3             	div    %rbx
     487:	48 89 54 24 08       	mov    %rdx,0x8(%rsp)
     48c:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     491:	48 89 06             	mov    %rax,(%rsi)
     494:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
     49b:	ff e7                	jmp    *%rdi
     49d:	90                   	nop
     49e:	0f 0b                	ud2
     4a0:	e8 76 19 00 00       	call   0x1e1b
     4a5:	05 4f 3b 00 00       	add    $0x3b4f,%eax
     4aa:	48 83 ec 60          	sub    $0x60,%rsp
     4ae:	48 8b 02             	mov    (%rdx),%rax
     4b1:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
     4b6:	48 8b 01             	mov    (%rcx),%rax
     4b9:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
     4be:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
     4c3:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
     4c8:	48 f7 d3             	not    %rbx
     4cb:	48 01 d8             	add    %rbx,%rax
     4ce:	48 ff c0             	inc    %rax
     4d1:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
     4d6:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
     4db:	48 89 06             	mov    %rax,(%rsi)
     4de:	48 83 c4 60          	add    $0x60,%rsp
     4e2:	ff e7                	jmp    *%rdi
     4e4:	90                   	nop
     4e5:	0f 0b                	ud2
     4e7:	8d 4c 24 04          	lea    0x4(%rsp),%ecx
     4eb:	83 e4 f0             	and    $0xfffffff0,%esp
     4ee:	ff 71 fc             	push   -0x4(%rcx)
     4f1:	55                   	push   %rbp
     4f2:	89 e5                	mov    %esp,%ebp
     4f4:	57                   	push   %rdi
     4f5:	56                   	push   %rsi
     4f6:	53                   	push   %rbx
     4f7:	51                   	push   %rcx
     4f8:	81 ec 38 08 00 00    	sub    $0x838,%esp
     4fe:	e8 bd fb ff ff       	call   0xc0
     503:	81 c3 f1 3a 00 00    	add    $0x3af1,%ebx
     509:	8b 83 fc ff ff ff    	mov    -0x4(%rbx),%eax
     50f:	8b 00                	mov    (%rax),%eax
     511:	50                   	push   %rax
     512:	6a 40                	push   $0x40
     514:	6a 01                	push   $0x1
     516:	8d 85 80 fd ff ff    	lea    -0x280(%rbp),%eax
     51c:	50                   	push   %rax
     51d:	e8 2e fb ff ff       	call   0x50
     522:	83 c4 10             	add    $0x10,%esp
     525:	83 f8 40             	cmp    $0x40,%eax
     528:	74 0a                	je     0x534
     52a:	b8 01 00 00 00       	mov    $0x1,%eax
     52f:	e9 db 18 00 00       	jmp    0x1e0f
     534:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
     53b:	eb 31                	jmp    0x56e
     53d:	8b 45 e4             	mov    -0x1c(%rbp),%eax
     540:	c1 e0 03             	shl    $0x3,%eax
     543:	89 c2                	mov    %eax,%edx
     545:	8d 85 80 fd ff ff    	lea    -0x280(%rbp),%eax
     54b:	01 c2                	add    %eax,%edx
     54d:	8d 85 40 fd ff ff    	lea    -0x2c0(%rbp),%eax
     553:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
     556:	c1 e1 03             	shl    $0x3,%ecx
     559:	01 c8                	add    %ecx,%eax
     55b:	83 ec 04             	sub    $0x4,%esp
     55e:	6a 08                	push   $0x8
     560:	52                   	push   %rdx
     561:	50                   	push   %rax
     562:	e8 d9 fa ff ff       	call   0x40
     567:	83 c4 10             	add    $0x10,%esp
     56a:	83 45 e4 01          	addl   $0x1,-0x1c(%rbp)
     56e:	83 7d e4 07          	cmpl   $0x7,-0x1c(%rbp)
     572:	7e c9                	jle    0x53d
     574:	c7 85 00 fd ff ff ef 	movl   $0x89abcdef,-0x300(%rbp)
     57b:	cd ab 89 
     57e:	c7 85 04 fd ff ff 67 	movl   $0x1234567,-0x2fc(%rbp)
     585:	45 23 01 
     588:	c7 85 08 fd ff ff 08 	movl   $0xb0a0908,-0x2f8(%rbp)
     58f:	09 0a 0b 
     592:	c7 85 0c fd ff ff 0c 	movl   $0xf0e0d0c,-0x2f4(%rbp)
     599:	0d 0e 0f 
     59c:	c7 85 10 fd ff ff 11 	movl   $0x11111111,-0x2f0(%rbp)
     5a3:	11 11 11 
     5a6:	c7 85 14 fd ff ff 11 	movl   $0x11111111,-0x2ec(%rbp)
     5ad:	11 11 11 
     5b0:	c7 85 18 fd ff ff 22 	movl   $0x22222222,-0x2e8(%rbp)
     5b7:	22 22 22 
     5ba:	c7 85 1c fd ff ff 22 	movl   $0x22222222,-0x2e4(%rbp)
     5c1:	22 22 22 
     5c4:	c7 85 20 fd ff ff 33 	movl   $0x33333333,-0x2e0(%rbp)
     5cb:	33 33 33 
     5ce:	c7 85 24 fd ff ff 33 	movl   $0x33333333,-0x2dc(%rbp)
     5d5:	33 33 33 
     5d8:	c7 85 28 fd ff ff 44 	movl   $0x44444444,-0x2d8(%rbp)
     5df:	44 44 44 
     5e2:	c7 85 2c fd ff ff 44 	movl   $0x44444444,-0x2d4(%rbp)
     5e9:	44 44 44 
     5ec:	c7 85 30 fd ff ff 55 	movl   $0x55555555,-0x2d0(%rbp)
     5f3:	55 55 55 
     5f6:	c7 85 34 fd ff ff 55 	movl   $0x55555555,-0x2cc(%rbp)
     5fd:	55 55 55 
     600:	c7 85 38 fd ff ff 66 	movl   $0x66666666,-0x2c8(%rbp)
     607:	66 66 66 
     60a:	c7 85 3c fd ff ff 66 	movl   $0x66666666,-0x2c4(%rbp)
     611:	66 66 66 
     614:	c7 85 c0 fc ff ff 21 	movl   $0x87654321,-0x340(%rbp)
     61b:	43 65 87 
     61e:	c7 85 c4 fc ff ff 09 	movl   $0xfedcba09,-0x33c(%rbp)
     625:	ba dc fe 
     628:	c7 85 c8 fc ff ff 67 	movl   $0x1234567,-0x338(%rbp)
     62f:	45 23 01 
     632:	c7 85 cc fc ff ff ef 	movl   $0x89abcdef,-0x334(%rbp)
     639:	cd ab 89 
     63c:	c7 85 d0 fc ff ff ef 	movl   $0xdeadbeef,-0x330(%rbp)
     643:	be ad de 
     646:	c7 85 d4 fc ff ff be 	movl   $0xcafebabe,-0x32c(%rbp)
     64d:	ba fe ca 
     650:	c7 85 d8 fc ff ff de 	movl   $0xdeadc0de,-0x328(%rbp)
     657:	c0 ad de 
     65a:	c7 85 dc fc ff ff 0d 	movl   $0xbadf00d,-0x324(%rbp)
     661:	f0 ad 0b 
     664:	c7 85 e0 fc ff ff e0 	movl   $0x2468ace0,-0x320(%rbp)
     66b:	ac 68 24 
     66e:	c7 85 e4 fc ff ff df 	movl   $0x13579bdf,-0x31c(%rbp)
     675:	9b 57 13 
     678:	c7 85 e8 fc ff ff 78 	movl   $0x12345678,-0x318(%rbp)
     67f:	56 34 12 
     682:	c7 85 ec fc ff ff ce 	movl   $0xcafeface,-0x314(%rbp)
     689:	fa fe ca 
     68c:	c7 85 f0 fc ff ff 0f 	movl   $0xf0f0f0f,-0x310(%rbp)
     693:	0f 0f 0f 
     696:	c7 85 f4 fc ff ff 0f 	movl   $0xf0f0f0f,-0x30c(%rbp)
     69d:	0f 0f 0f 
     6a0:	c7 85 f8 fc ff ff f0 	movl   $0xf0f0f0f0,-0x308(%rbp)
     6a7:	f0 f0 f0 
     6aa:	c7 85 fc fc ff ff f0 	movl   $0xf0f0f0f0,-0x304(%rbp)
     6b1:	f0 f0 f0 
     6b4:	c7 85 80 fc ff ff 0a 	movl   $0xa0a0a0a,-0x380(%rbp)
     6bb:	0a 0a 0a 
     6be:	c7 85 84 fc ff ff 0a 	movl   $0xa0a0a0a,-0x37c(%rbp)
     6c5:	0a 0a 0a 
     6c8:	c7 85 88 fc ff ff 1b 	movl   $0x1b1b1b1b,-0x378(%rbp)
     6cf:	1b 1b 1b 
     6d2:	c7 85 8c fc ff ff 1b 	movl   $0x1b1b1b1b,-0x374(%rbp)
     6d9:	1b 1b 1b 
     6dc:	c7 85 90 fc ff ff 2c 	movl   $0x2c2c2c2c,-0x370(%rbp)
     6e3:	2c 2c 2c 
     6e6:	c7 85 94 fc ff ff 2c 	movl   $0x2c2c2c2c,-0x36c(%rbp)
     6ed:	2c 2c 2c 
     6f0:	c7 85 98 fc ff ff 3d 	movl   $0x3d3d3d3d,-0x368(%rbp)
     6f7:	3d 3d 3d 
     6fa:	c7 85 9c fc ff ff 3d 	movl   $0x3d3d3d3d,-0x364(%rbp)
     701:	3d 3d 3d 
     704:	c7 85 a0 fc ff ff 4e 	movl   $0x4e4e4e4e,-0x360(%rbp)
     70b:	4e 4e 4e 
     70e:	c7 85 a4 fc ff ff 4e 	movl   $0x4e4e4e4e,-0x35c(%rbp)
     715:	4e 4e 4e 
     718:	c7 85 a8 fc ff ff 5f 	movl   $0x5f5f5f5f,-0x358(%rbp)
     71f:	5f 5f 5f 
     722:	c7 85 ac fc ff ff 5f 	movl   $0x5f5f5f5f,-0x354(%rbp)
     729:	5f 5f 5f 
     72c:	c7 85 b0 fc ff ff 60 	movl   $0x60606060,-0x350(%rbp)
     733:	60 60 60 
     736:	c7 85 b4 fc ff ff 60 	movl   $0x60606060,-0x34c(%rbp)
     73d:	60 60 60 
     740:	c7 85 b8 fc ff ff 71 	movl   $0x71717171,-0x348(%rbp)
     747:	71 71 71 
     74a:	c7 85 bc fc ff ff 71 	movl   $0x71717171,-0x344(%rbp)
     751:	71 71 71 
     754:	c7 85 40 fc ff ff 13 	movl   $0x13,-0x3c0(%rbp)
     75b:	00 00 00 
     75e:	c7 85 44 fc ff ff 00 	movl   $0x0,-0x3bc(%rbp)
     765:	00 00 00 
     768:	c7 85 48 fc ff ff 15 	movl   $0x15,-0x3b8(%rbp)
     76f:	00 00 00 
     772:	c7 85 4c fc ff ff 00 	movl   $0x0,-0x3b4(%rbp)
     779:	00 00 00 
     77c:	c7 85 50 fc ff ff 17 	movl   $0x17,-0x3b0(%rbp)
     783:	00 00 00 
     786:	c7 85 54 fc ff ff 00 	movl   $0x0,-0x3ac(%rbp)
     78d:	00 00 00 
     790:	c7 85 58 fc ff ff 19 	movl   $0x19,-0x3a8(%rbp)
     797:	00 00 00 
     79a:	c7 85 5c fc ff ff 00 	movl   $0x0,-0x3a4(%rbp)
     7a1:	00 00 00 
     7a4:	c7 85 60 fc ff ff 1b 	movl   $0x1b,-0x3a0(%rbp)
     7ab:	00 00 00 
     7ae:	c7 85 64 fc ff ff 00 	movl   $0x0,-0x39c(%rbp)
     7b5:	00 00 00 
     7b8:	c7 85 68 fc ff ff 1d 	movl   $0x1d,-0x398(%rbp)
     7bf:	00 00 00 
     7c2:	c7 85 6c fc ff ff 00 	movl   $0x0,-0x394(%rbp)
     7c9:	00 00 00 
     7cc:	c7 85 70 fc ff ff 1f 	movl   $0x1f,-0x390(%rbp)
     7d3:	00 00 00 
     7d6:	c7 85 74 fc ff ff 00 	movl   $0x0,-0x38c(%rbp)
     7dd:	00 00 00 
     7e0:	c7 85 78 fc ff ff 21 	movl   $0x21,-0x388(%rbp)
     7e7:	00 00 00 
     7ea:	c7 85 7c fc ff ff 00 	movl   $0x0,-0x384(%rbp)
     7f1:	00 00 00 
     7f4:	c7 85 00 fc ff ff 31 	movl   $0x31,-0x400(%rbp)
     7fb:	00 00 00 
     7fe:	c7 85 04 fc ff ff 00 	movl   $0x0,-0x3fc(%rbp)
     805:	00 00 00 
     808:	c7 85 08 fc ff ff 33 	movl   $0x33,-0x3f8(%rbp)
     80f:	00 00 00 
     812:	c7 85 0c fc ff ff 00 	movl   $0x0,-0x3f4(%rbp)
     819:	00 00 00 
     81c:	c7 85 10 fc ff ff 35 	movl   $0x35,-0x3f0(%rbp)
     823:	00 00 00 
     826:	c7 85 14 fc ff ff 00 	movl   $0x0,-0x3ec(%rbp)
     82d:	00 00 00 
     830:	c7 85 18 fc ff ff 37 	movl   $0x37,-0x3e8(%rbp)
     837:	00 00 00 
     83a:	c7 85 1c fc ff ff 00 	movl   $0x0,-0x3e4(%rbp)
     841:	00 00 00 
     844:	c7 85 20 fc ff ff 39 	movl   $0x39,-0x3e0(%rbp)
     84b:	00 00 00 
     84e:	c7 85 24 fc ff ff 00 	movl   $0x0,-0x3dc(%rbp)
     855:	00 00 00 
     858:	c7 85 28 fc ff ff 3b 	movl   $0x3b,-0x3d8(%rbp)
     85f:	00 00 00 
     862:	c7 85 2c fc ff ff 00 	movl   $0x0,-0x3d4(%rbp)
     869:	00 00 00 
     86c:	c7 85 30 fc ff ff 3d 	movl   $0x3d,-0x3d0(%rbp)
     873:	00 00 00 
     876:	c7 85 34 fc ff ff 00 	movl   $0x0,-0x3cc(%rbp)
     87d:	00 00 00 
     880:	c7 85 38 fc ff ff 3f 	movl   $0x3f,-0x3c8(%rbp)
     887:	00 00 00 
     88a:	c7 85 3c fc ff ff 00 	movl   $0x0,-0x3c4(%rbp)
     891:	00 00 00 
     894:	c7 85 e0 fb ff ff 05 	movl   $0x5,-0x420(%rbp)
     89b:	00 00 00 
     89e:	c7 85 e4 fb ff ff 0b 	movl   $0xb,-0x41c(%rbp)
     8a5:	00 00 00 
     8a8:	c7 85 e8 fb ff ff 11 	movl   $0x11,-0x418(%rbp)
     8af:	00 00 00 
     8b2:	c7 85 ec fb ff ff 17 	movl   $0x17,-0x414(%rbp)
     8b9:	00 00 00 
     8bc:	c7 85 f0 fb ff ff 1d 	movl   $0x1d,-0x410(%rbp)
     8c3:	00 00 00 
     8c6:	c7 85 f4 fb ff ff 03 	movl   $0x3,-0x40c(%rbp)
     8cd:	00 00 00 
     8d0:	c7 85 f8 fb ff ff 07 	movl   $0x7,-0x408(%rbp)
     8d7:	00 00 00 
     8da:	c7 85 fc fb ff ff 0d 	movl   $0xd,-0x404(%rbp)
     8e1:	00 00 00 
     8e4:	c7 85 c0 fb ff ff 08 	movl   $0x8,-0x440(%rbp)
     8eb:	00 00 00 
     8ee:	c7 85 c4 fb ff ff 10 	movl   $0x10,-0x43c(%rbp)
     8f5:	00 00 00 
     8f8:	c7 85 c8 fb ff ff 18 	movl   $0x18,-0x438(%rbp)
     8ff:	00 00 00 
     902:	c7 85 cc fb ff ff 20 	movl   $0x20,-0x434(%rbp)
     909:	00 00 00 
     90c:	c7 85 d0 fb ff ff 04 	movl   $0x4,-0x430(%rbp)
     913:	00 00 00 
     916:	c7 85 d4 fb ff ff 0c 	movl   $0xc,-0x42c(%rbp)
     91d:	00 00 00 
     920:	c7 85 d8 fb ff ff 14 	movl   $0x14,-0x428(%rbp)
     927:	00 00 00 
     92a:	c7 85 dc fb ff ff 1c 	movl   $0x1c,-0x424(%rbp)
     931:	00 00 00 
     934:	c7 85 80 fb ff ff 11 	movl   $0x11,-0x480(%rbp)
     93b:	00 00 00 
     93e:	c7 85 84 fb ff ff 00 	movl   $0x0,-0x47c(%rbp)
     945:	00 00 00 
     948:	c7 85 88 fb ff ff 13 	movl   $0x13,-0x478(%rbp)
     94f:	00 00 00 
     952:	c7 85 8c fb ff ff 00 	movl   $0x0,-0x474(%rbp)
     959:	00 00 00 
     95c:	c7 85 90 fb ff ff 17 	movl   $0x17,-0x470(%rbp)
     963:	00 00 00 
     966:	c7 85 94 fb ff ff 00 	movl   $0x0,-0x46c(%rbp)
     96d:	00 00 00 
     970:	c7 85 98 fb ff ff 1d 	movl   $0x1d,-0x468(%rbp)
     977:	00 00 00 
     97a:	c7 85 9c fb ff ff 00 	movl   $0x0,-0x464(%rbp)
     981:	00 00 00 
     984:	c7 85 a0 fb ff ff 21 	movl   $0x21,-0x460(%rbp)
     98b:	00 00 00 
     98e:	c7 85 a4 fb ff ff 00 	movl   $0x0,-0x45c(%rbp)
     995:	00 00 00 
     998:	c7 85 a8 fb ff ff 27 	movl   $0x27,-0x458(%rbp)
     99f:	00 00 00 
     9a2:	c7 85 ac fb ff ff 00 	movl   $0x0,-0x454(%rbp)
     9a9:	00 00 00 
     9ac:	c7 85 b0 fb ff ff 2b 	movl   $0x2b,-0x450(%rbp)
     9b3:	00 00 00 
     9b6:	c7 85 b4 fb ff ff 00 	movl   $0x0,-0x44c(%rbp)
     9bd:	00 00 00 
     9c0:	c7 85 b8 fb ff ff 2f 	movl   $0x2f,-0x448(%rbp)
     9c7:	00 00 00 
     9ca:	c7 85 bc fb ff ff 00 	movl   $0x0,-0x444(%rbp)
     9d1:	00 00 00 
     9d4:	c7 85 40 fb ff ff 0a 	movl   $0xa0a0a0a,-0x4c0(%rbp)
     9db:	0a 0a 0a 
     9de:	c7 85 44 fb ff ff 0a 	movl   $0xa0a0a0a,-0x4bc(%rbp)
     9e5:	0a 0a 0a 
     9e8:	c7 85 48 fb ff ff 1b 	movl   $0x1b1b1b1b,-0x4b8(%rbp)
     9ef:	1b 1b 1b 
     9f2:	c7 85 4c fb ff ff 1b 	movl   $0x1b1b1b1b,-0x4b4(%rbp)
     9f9:	1b 1b 1b 
     9fc:	c7 85 50 fb ff ff 2c 	movl   $0x2c2c2c2c,-0x4b0(%rbp)
     a03:	2c 2c 2c 
     a06:	c7 85 54 fb ff ff 2c 	movl   $0x2c2c2c2c,-0x4ac(%rbp)
     a0d:	2c 2c 2c 
     a10:	c7 85 58 fb ff ff 3d 	movl   $0x3d3d3d3d,-0x4a8(%rbp)
     a17:	3d 3d 3d 
     a1a:	c7 85 5c fb ff ff 3d 	movl   $0x3d3d3d3d,-0x4a4(%rbp)
     a21:	3d 3d 3d 
     a24:	c7 85 60 fb ff ff 4e 	movl   $0x4e4e4e4e,-0x4a0(%rbp)
     a2b:	4e 4e 4e 
     a2e:	c7 85 64 fb ff ff 4e 	movl   $0x4e4e4e4e,-0x49c(%rbp)
     a35:	4e 4e 4e 
     a38:	c7 85 68 fb ff ff 5f 	movl   $0x5f5f5f5f,-0x498(%rbp)
     a3f:	5f 5f 5f 
     a42:	c7 85 6c fb ff ff 5f 	movl   $0x5f5f5f5f,-0x494(%rbp)
     a49:	5f 5f 5f 
     a4c:	c7 85 70 fb ff ff 60 	movl   $0x60606060,-0x490(%rbp)
     a53:	60 60 60 
     a56:	c7 85 74 fb ff ff 60 	movl   $0x60606060,-0x48c(%rbp)
     a5d:	60 60 60 
     a60:	c7 85 78 fb ff ff 71 	movl   $0x71717171,-0x488(%rbp)
     a67:	71 71 71 
     a6a:	c7 85 7c fb ff ff 71 	movl   $0x71717171,-0x484(%rbp)
     a71:	71 71 71 
     a74:	c7 85 00 fb ff ff 0f 	movl   $0xf0f0f0f,-0x500(%rbp)
     a7b:	0f 0f 0f 
     a7e:	c7 85 04 fb ff ff 0f 	movl   $0xf0f0f0f,-0x4fc(%rbp)
     a85:	0f 0f 0f 
     a88:	c7 85 08 fb ff ff f0 	movl   $0xf0f0f0f0,-0x4f8(%rbp)
     a8f:	f0 f0 f0 
     a92:	c7 85 0c fb ff ff f0 	movl   $0xf0f0f0f0,-0x4f4(%rbp)
     a99:	f0 f0 f0 
     a9c:	c7 85 10 fb ff ff 55 	movl   $0x55555555,-0x4f0(%rbp)
     aa3:	55 55 55 
     aa6:	c7 85 14 fb ff ff aa 	movl   $0xaaaaaaaa,-0x4ec(%rbp)
     aad:	aa aa aa 
     ab0:	c7 85 18 fb ff ff aa 	movl   $0xaaaaaaaa,-0x4e8(%rbp)
     ab7:	aa aa aa 
     aba:	c7 85 1c fb ff ff 55 	movl   $0x55555555,-0x4e4(%rbp)
     ac1:	55 55 55 
     ac4:	c7 85 20 fb ff ff ef 	movl   $0x90abcdef,-0x4e0(%rbp)
     acb:	cd ab 90 
     ace:	c7 85 24 fb ff ff 78 	movl   $0x12345678,-0x4dc(%rbp)
     ad5:	56 34 12 
     ad8:	c7 85 28 fb ff ff 10 	movl   $0x76543210,-0x4d8(%rbp)
     adf:	32 54 76 
     ae2:	c7 85 2c fb ff ff 98 	movl   $0xfedcba98,-0x4d4(%rbp)
     ae9:	ba dc fe 
     aec:	c7 85 30 fb ff ff 78 	movl   $0x4b5a6978,-0x4d0(%rbp)
     af3:	69 5a 4b 
     af6:	c7 85 34 fb ff ff 3c 	movl   $0xf1e2d3c,-0x4cc(%rbp)
     afd:	2d 1e 0f 
     b00:	c7 85 38 fb ff ff 67 	movl   $0x1234567,-0x4c8(%rbp)
     b07:	45 23 01 
     b0a:	c7 85 3c fb ff ff ef 	movl   $0x89abcdef,-0x4c4(%rbp)
     b11:	cd ab 89 
     b14:	c7 85 c0 fa ff ff a4 	movl   $0xe5b71ca4,-0x540(%rbp)
     b1b:	1c b7 e5 
     b1e:	c7 85 c4 fa ff ff 56 	movl   $0x35ee0f56,-0x53c(%rbp)
     b25:	0f ee 35 
     b28:	c7 85 c8 fa ff ff fd 	movl   $0x6a1056fd,-0x538(%rbp)
     b2f:	56 10 6a 
     b32:	c7 85 cc fa ff ff a1 	movl   $0x3ffd40a1,-0x534(%rbp)
     b39:	40 fd 3f 
     b3c:	c7 85 d0 fa ff ff 1a 	movl   $0x2c5ba31a,-0x530(%rbp)
     b43:	a3 5b 2c 
     b46:	c7 85 d4 fa ff ff e5 	movl   $0xca5272e5,-0x52c(%rbp)
     b4d:	72 52 ca 
     b50:	c7 85 d8 fa ff ff 25 	movl   $0x92a71b25,-0x528(%rbp)
     b57:	1b a7 92 
     b5a:	c7 85 dc fa ff ff 0b 	movl   $0x6bc3120b,-0x524(%rbp)
     b61:	12 c3 6b 
     b64:	c7 85 e0 fa ff ff a3 	movl   $0xc2b935a3,-0x520(%rbp)
     b6b:	35 b9 c2 
     b6e:	c7 85 e4 fa ff ff f6 	movl   $0x104fd2f6,-0x51c(%rbp)
     b75:	d2 4f 10 
     b78:	c7 85 e8 fa ff ff d6 	movl   $0x63b1b1d6,-0x518(%rbp)
     b7f:	b1 b1 63 
     b82:	c7 85 ec fa ff ff 36 	movl   $0xf1b5ca36,-0x514(%rbp)
     b89:	ca b5 f1 
     b8c:	c7 85 f0 fa ff ff 08 	movl   $0xdad2aa08,-0x510(%rbp)
     b93:	aa d2 da 
     b96:	c7 85 f4 fa ff ff 30 	movl   $0xcae30b30,-0x50c(%rbp)
     b9d:	0b e3 ca 
     ba0:	c7 85 f8 fa ff ff be 	movl   $0xc13d6ebe,-0x508(%rbp)
     ba7:	6e 3d c1 
     baa:	c7 85 fc fa ff ff 8d 	movl   $0x7586bb8d,-0x504(%rbp)
     bb1:	bb 86 75 
     bb4:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
     bbb:	eb 36                	jmp    0xbf3
     bbd:	8b 45 e0             	mov    -0x20(%rbp),%eax
     bc0:	8b 84 85 e0 fb ff ff 	mov    -0x420(%rbp,%rax,4),%eax
     bc7:	89 c1                	mov    %eax,%ecx
     bc9:	8d 95 f8 f7 ff ff    	lea    -0x808(%rbp),%edx
     bcf:	8b 45 e0             	mov    -0x20(%rbp),%eax
     bd2:	01 d0                	add    %edx,%eax
     bd4:	88 08                	mov    %cl,(%rax)
     bd6:	8b 45 e0             	mov    -0x20(%rbp),%eax
     bd9:	8b 84 85 c0 fb ff ff 	mov    -0x440(%rbp,%rax,4),%eax
     be0:	89 c1                	mov    %eax,%ecx
     be2:	8d 95 f0 f7 ff ff    	lea    -0x810(%rbp),%edx
     be8:	8b 45 e0             	mov    -0x20(%rbp),%eax
     beb:	01 d0                	add    %edx,%eax
     bed:	88 08                	mov    %cl,(%rax)
     bef:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
     bf3:	83 7d e0 07          	cmpl   $0x7,-0x20(%rbp)
     bf7:	7e c4                	jle    0xbbd
     bf9:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
     c00:	e9 f1 04 00 00       	jmp    0x10f6
     c05:	8d 85 00 fd ff ff    	lea    -0x300(%rbp),%eax
     c0b:	8b 55 dc             	mov    -0x24(%rbp),%edx
     c0e:	c1 e2 03             	shl    $0x3,%edx
     c11:	01 d0                	add    %edx,%eax
     c13:	89 c1                	mov    %eax,%ecx
     c15:	8d 85 40 fd ff ff    	lea    -0x2c0(%rbp),%eax
     c1b:	8b 55 dc             	mov    -0x24(%rbp),%edx
     c1e:	c1 e2 03             	shl    $0x3,%edx
     c21:	01 d0                	add    %edx,%eax
     c23:	89 c6                	mov    %eax,%esi
     c25:	8d 85 80 fa ff ff    	lea    -0x580(%rbp),%eax
     c2b:	8b 55 dc             	mov    -0x24(%rbp),%edx
     c2e:	c1 e2 03             	shl    $0x3,%edx
     c31:	01 d0                	add    %edx,%eax
     c33:	89 c2                	mov    %eax,%edx
     c35:	8d 83 92 c1 ff ff    	lea    -0x3e6e(%rbx),%eax
     c3b:	89 85 3c ff ff ff    	mov    %eax,-0xc4(%rbp)
     c41:	89 95 38 ff ff ff    	mov    %edx,-0xc8(%rbp)
     c47:	89 b5 34 ff ff ff    	mov    %esi,-0xcc(%rbp)
     c4d:	89 8d 30 ff ff ff    	mov    %ecx,-0xd0(%rbp)
     c53:	50                   	push   %rax
     c54:	53                   	push   %rbx
     c55:	51                   	push   %rcx
     c56:	52                   	push   %rdx
     c57:	56                   	push   %rsi
     c58:	57                   	push   %rdi
     c59:	55                   	push   %rbp
     c5a:	90                   	nop
     c5b:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
     c61:	89 85 2c ff ff ff    	mov    %eax,-0xd4(%rbp)
     c67:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
     c6d:	89 85 28 ff ff ff    	mov    %eax,-0xd8(%rbp)
     c73:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
     c79:	89 85 24 ff ff ff    	mov    %eax,-0xdc(%rbp)
     c7f:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
     c85:	89 85 20 ff ff ff    	mov    %eax,-0xe0(%rbp)
     c8b:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
     c91:	8b b5 28 ff ff ff    	mov    -0xd8(%rbp),%esi
     c97:	8b 95 24 ff ff ff    	mov    -0xdc(%rbp),%edx
     c9d:	8b 8d 20 ff ff ff    	mov    -0xe0(%rbp),%ecx
     ca3:	83 ec 08             	sub    $0x8,%esp
     ca6:	31 db                	xor    %ebx,%ebx
     ca8:	b3 03                	mov    $0x3,%bl
     caa:	d1 e3                	shl    $1,%ebx
     cac:	c1 e3 02             	shl    $0x2,%ebx
     caf:	83 c3 1a             	add    $0x1a,%ebx
     cb2:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
     cb7:	83 cb 00             	or     $0x0,%ebx
     cba:	90                   	nop
     cbb:	85 db                	test   %ebx,%ebx
     cbd:	90                   	nop
     cbe:	89 1f                	mov    %ebx,(%rdi)
     cc0:	89 04 24             	mov    %eax,(%rsp)
     cc3:	bf c9 9c 04 08       	mov    $0x8049cc9,%edi
     cc8:	cb                   	lret
     cc9:	48 83 ec 08          	sub    $0x8,%rsp
     ccd:	4d 31 c9             	xor    %r9,%r9
     cd0:	41 b1 23             	mov    $0x23,%r9b
     cd3:	49 c1 e1 00          	shl    $0x0,%r9
     cd7:	49 83 c1 00          	add    $0x0,%r9
     cdb:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
     ce0:	4d 89 ca             	mov    %r9,%r10
     ce3:	49 d1 e2             	shl    $1,%r10
     ce6:	49 d1 ea             	shr    $1,%r10
     ce9:	4d 31 db             	xor    %r11,%r11
     cec:	49 ff c3             	inc    %r11
     cef:	49 ff cb             	dec    %r11
     cf2:	4d 87 e4             	xchg   %r12,%r12
     cf5:	45 89 08             	mov    %r9d,(%r8)
     cf8:	c7 04 24 00 9d 04 08 	movl   $0x8049d00,(%rsp)
     cff:	cb                   	lret
     d00:	90                   	nop
     d01:	5d                   	pop    %rbp
     d02:	5f                   	pop    %rdi
     d03:	5e                   	pop    %rsi
     d04:	5a                   	pop    %rdx
     d05:	59                   	pop    %rcx
     d06:	5b                   	pop    %rbx
     d07:	58                   	pop    %rax
     d08:	90                   	nop
     d09:	90                   	nop
     d0a:	8b 45 dc             	mov    -0x24(%rbp),%eax
     d0d:	8b b4 c5 80 fa ff ff 	mov    -0x580(%rbp,%rax,8),%esi
     d14:	8b bc c5 84 fa ff ff 	mov    -0x57c(%rbp,%rax,8),%edi
     d1b:	8b 45 dc             	mov    -0x24(%rbp),%eax
     d1e:	8b 94 c5 c4 fc ff ff 	mov    -0x33c(%rbp,%rax,8),%edx
     d25:	8b 84 c5 c0 fc ff ff 	mov    -0x340(%rbp,%rax,8),%eax
     d2c:	31 f0                	xor    %esi,%eax
     d2e:	31 fa                	xor    %edi,%edx
     d30:	8b 4d dc             	mov    -0x24(%rbp),%ecx
     d33:	89 84 cd 40 fa ff ff 	mov    %eax,-0x5c0(%rbp,%rcx,8)
     d3a:	89 94 cd 44 fa ff ff 	mov    %edx,-0x5bc(%rbp,%rcx,8)
     d41:	8d 95 f8 f7 ff ff    	lea    -0x808(%rbp),%edx
     d47:	8b 45 dc             	mov    -0x24(%rbp),%eax
     d4a:	01 d0                	add    %edx,%eax
     d4c:	89 c1                	mov    %eax,%ecx
     d4e:	8d 85 40 fa ff ff    	lea    -0x5c0(%rbp),%eax
     d54:	8b 55 dc             	mov    -0x24(%rbp),%edx
     d57:	c1 e2 03             	shl    $0x3,%edx
     d5a:	01 d0                	add    %edx,%eax
     d5c:	89 c6                	mov    %eax,%esi
     d5e:	8d 85 00 fa ff ff    	lea    -0x600(%rbp),%eax
     d64:	8b 55 dc             	mov    -0x24(%rbp),%edx
     d67:	c1 e2 03             	shl    $0x3,%edx
     d6a:	01 d0                	add    %edx,%eax
     d6c:	89 c2                	mov    %eax,%edx
     d6e:	8d 83 be c3 ff ff    	lea    -0x3c42(%rbx),%eax
     d74:	89 85 5c ff ff ff    	mov    %eax,-0xa4(%rbp)
     d7a:	89 95 58 ff ff ff    	mov    %edx,-0xa8(%rbp)
     d80:	89 b5 54 ff ff ff    	mov    %esi,-0xac(%rbp)
     d86:	89 8d 50 ff ff ff    	mov    %ecx,-0xb0(%rbp)
     d8c:	50                   	push   %rax
     d8d:	53                   	push   %rbx
     d8e:	51                   	push   %rcx
     d8f:	52                   	push   %rdx
     d90:	56                   	push   %rsi
     d91:	57                   	push   %rdi
     d92:	55                   	push   %rbp
     d93:	90                   	nop
     d94:	8b 85 5c ff ff ff    	mov    -0xa4(%rbp),%eax
     d9a:	89 85 4c ff ff ff    	mov    %eax,-0xb4(%rbp)
     da0:	8b 85 58 ff ff ff    	mov    -0xa8(%rbp),%eax
     da6:	89 85 48 ff ff ff    	mov    %eax,-0xb8(%rbp)
     dac:	8b 85 54 ff ff ff    	mov    -0xac(%rbp),%eax
     db2:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
     db8:	8b 85 50 ff ff ff    	mov    -0xb0(%rbp),%eax
     dbe:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
     dc4:	8b 85 4c ff ff ff    	mov    -0xb4(%rbp),%eax
     dca:	8b b5 48 ff ff ff    	mov    -0xb8(%rbp),%esi
     dd0:	8b 95 44 ff ff ff    	mov    -0xbc(%rbp),%edx
     dd6:	8b 8d 40 ff ff ff    	mov    -0xc0(%rbp),%ecx
     ddc:	83 ec 08             	sub    $0x8,%esp
     ddf:	31 db                	xor    %ebx,%ebx
     de1:	b3 03                	mov    $0x3,%bl
     de3:	d1 e3                	shl    $1,%ebx
     de5:	c1 e3 02             	shl    $0x2,%ebx
     de8:	83 c3 1a             	add    $0x1a,%ebx
     deb:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
     df0:	83 cb 00             	or     $0x0,%ebx
     df3:	90                   	nop
     df4:	85 db                	test   %ebx,%ebx
     df6:	90                   	nop
     df7:	89 1f                	mov    %ebx,(%rdi)
     df9:	89 04 24             	mov    %eax,(%rsp)
     dfc:	bf 02 9e 04 08       	mov    $0x8049e02,%edi
     e01:	cb                   	lret
     e02:	48 83 ec 08          	sub    $0x8,%rsp
     e06:	4d 31 c9             	xor    %r9,%r9
     e09:	41 b1 23             	mov    $0x23,%r9b
     e0c:	49 c1 e1 00          	shl    $0x0,%r9
     e10:	49 83 c1 00          	add    $0x0,%r9
     e14:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
     e19:	4d 89 ca             	mov    %r9,%r10
     e1c:	49 d1 e2             	shl    $1,%r10
     e1f:	49 d1 ea             	shr    $1,%r10
     e22:	4d 31 db             	xor    %r11,%r11
     e25:	49 ff c3             	inc    %r11
     e28:	49 ff cb             	dec    %r11
     e2b:	4d 87 e4             	xchg   %r12,%r12
     e2e:	45 89 08             	mov    %r9d,(%r8)
     e31:	c7 04 24 39 9e 04 08 	movl   $0x8049e39,(%rsp)
     e38:	cb                   	lret
     e39:	90                   	nop
     e3a:	5d                   	pop    %rbp
     e3b:	5f                   	pop    %rdi
     e3c:	5e                   	pop    %rsi
     e3d:	5a                   	pop    %rdx
     e3e:	59                   	pop    %rcx
     e3f:	5b                   	pop    %rbx
     e40:	58                   	pop    %rax
     e41:	90                   	nop
     e42:	90                   	nop
     e43:	8d 85 40 fc ff ff    	lea    -0x3c0(%rbp),%eax
     e49:	8b 55 dc             	mov    -0x24(%rbp),%edx
     e4c:	c1 e2 03             	shl    $0x3,%edx
     e4f:	01 d0                	add    %edx,%eax
     e51:	89 c1                	mov    %eax,%ecx
     e53:	8d 85 00 fa ff ff    	lea    -0x600(%rbp),%eax
     e59:	8b 55 dc             	mov    -0x24(%rbp),%edx
     e5c:	c1 e2 03             	shl    $0x3,%edx
     e5f:	01 d0                	add    %edx,%eax
     e61:	89 c6                	mov    %eax,%esi
     e63:	8d 85 c0 f9 ff ff    	lea    -0x640(%rbp),%eax
     e69:	8b 55 dc             	mov    -0x24(%rbp),%edx
     e6c:	c1 e2 03             	shl    $0x3,%edx
     e6f:	01 d0                	add    %edx,%eax
     e71:	89 c2                	mov    %eax,%edx
     e73:	8d 83 e7 c1 ff ff    	lea    -0x3e19(%rbx),%eax
     e79:	89 85 7c ff ff ff    	mov    %eax,-0x84(%rbp)
     e7f:	89 95 78 ff ff ff    	mov    %edx,-0x88(%rbp)
     e85:	89 b5 74 ff ff ff    	mov    %esi,-0x8c(%rbp)
     e8b:	89 8d 70 ff ff ff    	mov    %ecx,-0x90(%rbp)
     e91:	50                   	push   %rax
     e92:	53                   	push   %rbx
     e93:	51                   	push   %rcx
     e94:	52                   	push   %rdx
     e95:	56                   	push   %rsi
     e96:	57                   	push   %rdi
     e97:	55                   	push   %rbp
     e98:	90                   	nop
     e99:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
     e9f:	89 85 6c ff ff ff    	mov    %eax,-0x94(%rbp)
     ea5:	8b 85 78 ff ff ff    	mov    -0x88(%rbp),%eax
     eab:	89 85 68 ff ff ff    	mov    %eax,-0x98(%rbp)
     eb1:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
     eb7:	89 85 64 ff ff ff    	mov    %eax,-0x9c(%rbp)
     ebd:	8b 85 70 ff ff ff    	mov    -0x90(%rbp),%eax
     ec3:	89 85 60 ff ff ff    	mov    %eax,-0xa0(%rbp)
     ec9:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
     ecf:	8b b5 68 ff ff ff    	mov    -0x98(%rbp),%esi
     ed5:	8b 95 64 ff ff ff    	mov    -0x9c(%rbp),%edx
     edb:	8b 8d 60 ff ff ff    	mov    -0xa0(%rbp),%ecx
     ee1:	83 ec 08             	sub    $0x8,%esp
     ee4:	31 db                	xor    %ebx,%ebx
     ee6:	b3 03                	mov    $0x3,%bl
     ee8:	d1 e3                	shl    $1,%ebx
     eea:	c1 e3 02             	shl    $0x2,%ebx
     eed:	83 c3 1a             	add    $0x1a,%ebx
     ef0:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
     ef5:	83 cb 00             	or     $0x0,%ebx
     ef8:	90                   	nop
     ef9:	85 db                	test   %ebx,%ebx
     efb:	90                   	nop
     efc:	89 1f                	mov    %ebx,(%rdi)
     efe:	89 04 24             	mov    %eax,(%rsp)
     f01:	bf 07 9f 04 08       	mov    $0x8049f07,%edi
     f06:	cb                   	lret
     f07:	48 83 ec 08          	sub    $0x8,%rsp
     f0b:	4d 31 c9             	xor    %r9,%r9
     f0e:	41 b1 23             	mov    $0x23,%r9b
     f11:	49 c1 e1 00          	shl    $0x0,%r9
     f15:	49 83 c1 00          	add    $0x0,%r9
     f19:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
     f1e:	4d 89 ca             	mov    %r9,%r10
     f21:	49 d1 e2             	shl    $1,%r10
     f24:	49 d1 ea             	shr    $1,%r10
     f27:	4d 31 db             	xor    %r11,%r11
     f2a:	49 ff c3             	inc    %r11
     f2d:	49 ff cb             	dec    %r11
     f30:	4d 87 e4             	xchg   %r12,%r12
     f33:	45 89 08             	mov    %r9d,(%r8)
     f36:	c7 04 24 3e 9f 04 08 	movl   $0x8049f3e,(%rsp)
     f3d:	cb                   	lret
     f3e:	90                   	nop
     f3f:	5d                   	pop    %rbp
     f40:	5f                   	pop    %rdi
     f41:	5e                   	pop    %rsi
     f42:	5a                   	pop    %rdx
     f43:	59                   	pop    %rcx
     f44:	5b                   	pop    %rbx
     f45:	58                   	pop    %rax
     f46:	90                   	nop
     f47:	90                   	nop
     f48:	8d 85 c0 f9 ff ff    	lea    -0x640(%rbp),%eax
     f4e:	8b 55 dc             	mov    -0x24(%rbp),%edx
     f51:	c1 e2 03             	shl    $0x3,%edx
     f54:	01 d0                	add    %edx,%eax
     f56:	89 c1                	mov    %eax,%ecx
     f58:	8d 85 c0 f9 ff ff    	lea    -0x640(%rbp),%eax
     f5e:	8b 55 dc             	mov    -0x24(%rbp),%edx
     f61:	c1 e2 03             	shl    $0x3,%edx
     f64:	01 d0                	add    %edx,%eax
     f66:	89 c6                	mov    %eax,%esi
     f68:	8d 85 80 f9 ff ff    	lea    -0x680(%rbp),%eax
     f6e:	8b 55 dc             	mov    -0x24(%rbp),%edx
     f71:	c1 e2 03             	shl    $0x3,%edx
     f74:	01 d0                	add    %edx,%eax
     f76:	89 c2                	mov    %eax,%edx
     f78:	8d 83 1c c3 ff ff    	lea    -0x3ce4(%rbx),%eax
     f7e:	89 45 9c             	mov    %eax,-0x64(%rbp)
     f81:	89 55 98             	mov    %edx,-0x68(%rbp)
     f84:	89 75 94             	mov    %esi,-0x6c(%rbp)
     f87:	89 4d 90             	mov    %ecx,-0x70(%rbp)
     f8a:	50                   	push   %rax
     f8b:	53                   	push   %rbx
     f8c:	51                   	push   %rcx
     f8d:	52                   	push   %rdx
     f8e:	56                   	push   %rsi
     f8f:	57                   	push   %rdi
     f90:	55                   	push   %rbp
     f91:	90                   	nop
     f92:	8b 45 9c             	mov    -0x64(%rbp),%eax
     f95:	89 45 8c             	mov    %eax,-0x74(%rbp)
     f98:	8b 45 98             	mov    -0x68(%rbp),%eax
     f9b:	89 45 88             	mov    %eax,-0x78(%rbp)
     f9e:	8b 45 94             	mov    -0x6c(%rbp),%eax
     fa1:	89 45 84             	mov    %eax,-0x7c(%rbp)
     fa4:	8b 45 90             	mov    -0x70(%rbp),%eax
     fa7:	89 45 80             	mov    %eax,-0x80(%rbp)
     faa:	8b 45 8c             	mov    -0x74(%rbp),%eax
     fad:	8b 75 88             	mov    -0x78(%rbp),%esi
     fb0:	8b 55 84             	mov    -0x7c(%rbp),%edx
     fb3:	8b 4d 80             	mov    -0x80(%rbp),%ecx
     fb6:	83 ec 08             	sub    $0x8,%esp
     fb9:	31 db                	xor    %ebx,%ebx
     fbb:	b3 03                	mov    $0x3,%bl
     fbd:	d1 e3                	shl    $1,%ebx
     fbf:	c1 e3 02             	shl    $0x2,%ebx
     fc2:	83 c3 1a             	add    $0x1a,%ebx
     fc5:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
     fca:	83 cb 00             	or     $0x0,%ebx
     fcd:	90                   	nop
     fce:	85 db                	test   %ebx,%ebx
     fd0:	90                   	nop
     fd1:	89 1f                	mov    %ebx,(%rdi)
     fd3:	89 04 24             	mov    %eax,(%rsp)
     fd6:	bf dc 9f 04 08       	mov    $0x8049fdc,%edi
     fdb:	cb                   	lret
     fdc:	48 83 ec 08          	sub    $0x8,%rsp
     fe0:	4d 31 c9             	xor    %r9,%r9
     fe3:	41 b1 23             	mov    $0x23,%r9b
     fe6:	49 c1 e1 00          	shl    $0x0,%r9
     fea:	49 83 c1 00          	add    $0x0,%r9
     fee:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
     ff3:	4d 89 ca             	mov    %r9,%r10
     ff6:	49 d1 e2             	shl    $1,%r10
     ff9:	49 d1 ea             	shr    $1,%r10
     ffc:	4d 31 db             	xor    %r11,%r11
     fff:	49 ff c3             	inc    %r11
    1002:	49 ff cb             	dec    %r11
    1005:	4d 87 e4             	xchg   %r12,%r12
    1008:	45 89 08             	mov    %r9d,(%r8)
    100b:	c7 04 24 13 a0 04 08 	movl   $0x804a013,(%rsp)
    1012:	cb                   	lret
    1013:	90                   	nop
    1014:	5d                   	pop    %rbp
    1015:	5f                   	pop    %rdi
    1016:	5e                   	pop    %rsi
    1017:	5a                   	pop    %rdx
    1018:	59                   	pop    %rcx
    1019:	5b                   	pop    %rbx
    101a:	58                   	pop    %rax
    101b:	90                   	nop
    101c:	90                   	nop
    101d:	8d 85 80 f9 ff ff    	lea    -0x680(%rbp),%eax
    1023:	8b 55 dc             	mov    -0x24(%rbp),%edx
    1026:	c1 e2 03             	shl    $0x3,%edx
    1029:	01 d0                	add    %edx,%eax
    102b:	89 c1                	mov    %eax,%ecx
    102d:	8d 85 80 f9 ff ff    	lea    -0x680(%rbp),%eax
    1033:	8b 55 dc             	mov    -0x24(%rbp),%edx
    1036:	c1 e2 03             	shl    $0x3,%edx
    1039:	01 d0                	add    %edx,%eax
    103b:	89 c6                	mov    %eax,%esi
    103d:	8d 85 40 f9 ff ff    	lea    -0x6c0(%rbp),%eax
    1043:	8b 55 dc             	mov    -0x24(%rbp),%edx
    1046:	c1 e2 03             	shl    $0x3,%edx
    1049:	01 d0                	add    %edx,%eax
    104b:	89 c2                	mov    %eax,%edx
    104d:	8d 83 f5 c2 ff ff    	lea    -0x3d0b(%rbx),%eax
    1053:	89 45 bc             	mov    %eax,-0x44(%rbp)
    1056:	89 55 b8             	mov    %edx,-0x48(%rbp)
    1059:	89 75 b4             	mov    %esi,-0x4c(%rbp)
    105c:	89 4d b0             	mov    %ecx,-0x50(%rbp)
    105f:	50                   	push   %rax
    1060:	53                   	push   %rbx
    1061:	51                   	push   %rcx
    1062:	52                   	push   %rdx
    1063:	56                   	push   %rsi
    1064:	57                   	push   %rdi
    1065:	55                   	push   %rbp
    1066:	90                   	nop
    1067:	8b 45 bc             	mov    -0x44(%rbp),%eax
    106a:	89 45 ac             	mov    %eax,-0x54(%rbp)
    106d:	8b 45 b8             	mov    -0x48(%rbp),%eax
    1070:	89 45 a8             	mov    %eax,-0x58(%rbp)
    1073:	8b 45 b4             	mov    -0x4c(%rbp),%eax
    1076:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    1079:	8b 45 b0             	mov    -0x50(%rbp),%eax
    107c:	89 45 a0             	mov    %eax,-0x60(%rbp)
    107f:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1082:	8b 75 a8             	mov    -0x58(%rbp),%esi
    1085:	8b 55 a4             	mov    -0x5c(%rbp),%edx
    1088:	8b 4d a0             	mov    -0x60(%rbp),%ecx
    108b:	83 ec 08             	sub    $0x8,%esp
    108e:	31 db                	xor    %ebx,%ebx
    1090:	b3 03                	mov    $0x3,%bl
    1092:	d1 e3                	shl    $1,%ebx
    1094:	c1 e3 02             	shl    $0x2,%ebx
    1097:	83 c3 1a             	add    $0x1a,%ebx
    109a:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    109f:	83 cb 00             	or     $0x0,%ebx
    10a2:	90                   	nop
    10a3:	85 db                	test   %ebx,%ebx
    10a5:	90                   	nop
    10a6:	89 1f                	mov    %ebx,(%rdi)
    10a8:	89 04 24             	mov    %eax,(%rsp)
    10ab:	bf b1 a0 04 08       	mov    $0x804a0b1,%edi
    10b0:	cb                   	lret
    10b1:	48 83 ec 08          	sub    $0x8,%rsp
    10b5:	4d 31 c9             	xor    %r9,%r9
    10b8:	41 b1 23             	mov    $0x23,%r9b
    10bb:	49 c1 e1 00          	shl    $0x0,%r9
    10bf:	49 83 c1 00          	add    $0x0,%r9
    10c3:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    10c8:	4d 89 ca             	mov    %r9,%r10
    10cb:	49 d1 e2             	shl    $1,%r10
    10ce:	49 d1 ea             	shr    $1,%r10
    10d1:	4d 31 db             	xor    %r11,%r11
    10d4:	49 ff c3             	inc    %r11
    10d7:	49 ff cb             	dec    %r11
    10da:	4d 87 e4             	xchg   %r12,%r12
    10dd:	45 89 08             	mov    %r9d,(%r8)
    10e0:	c7 04 24 e8 a0 04 08 	movl   $0x804a0e8,(%rsp)
    10e7:	cb                   	lret
    10e8:	90                   	nop
    10e9:	5d                   	pop    %rbp
    10ea:	5f                   	pop    %rdi
    10eb:	5e                   	pop    %rsi
    10ec:	5a                   	pop    %rdx
    10ed:	59                   	pop    %rcx
    10ee:	5b                   	pop    %rbx
    10ef:	58                   	pop    %rax
    10f0:	90                   	nop
    10f1:	90                   	nop
    10f2:	83 45 dc 01          	addl   $0x1,-0x24(%rbp)
    10f6:	83 7d dc 07          	cmpl   $0x7,-0x24(%rbp)
    10fa:	0f 8e 05 fb ff ff    	jle    0xc05
    1100:	c7 85 e8 f7 ff ff aa 	movl   $0xaaaaaaaa,-0x818(%rbp)
    1107:	aa aa aa 
    110a:	c7 85 ec f7 ff ff aa 	movl   $0xaaaaaaaa,-0x814(%rbp)
    1111:	aa aa aa 
    1114:	8b 85 e8 f7 ff ff    	mov    -0x818(%rbp),%eax
    111a:	8b 95 ec f7 ff ff    	mov    -0x814(%rbp),%edx
    1120:	f7 d0                	not    %eax
    1122:	f7 d2                	not    %edx
    1124:	89 45 c0             	mov    %eax,-0x40(%rbp)
    1127:	89 55 c4             	mov    %edx,-0x3c(%rbp)
    112a:	c7 45 d8 00 00 00 00 	movl   $0x0,-0x28(%rbp)
    1131:	e9 67 04 00 00       	jmp    0x159d
    1136:	c7 85 e0 f7 ff ff 00 	movl   $0x0,-0x820(%rbp)
    113d:	00 00 00 
    1140:	c7 85 e4 f7 ff ff 00 	movl   $0x0,-0x81c(%rbp)
    1147:	00 00 00 
    114a:	c7 85 d8 f7 ff ff 00 	movl   $0x0,-0x828(%rbp)
    1151:	00 00 00 
    1154:	c7 85 dc f7 ff ff 00 	movl   $0x0,-0x824(%rbp)
    115b:	00 00 00 
    115e:	c7 85 d0 f7 ff ff 00 	movl   $0x0,-0x830(%rbp)
    1165:	00 00 00 
    1168:	c7 85 d4 f7 ff ff 00 	movl   $0x0,-0x82c(%rbp)
    116f:	00 00 00 
    1172:	c7 85 c8 f7 ff ff 00 	movl   $0x0,-0x838(%rbp)
    1179:	00 00 00 
    117c:	c7 85 cc f7 ff ff 00 	movl   $0x0,-0x834(%rbp)
    1183:	00 00 00 
    1186:	8d 85 e8 f7 ff ff    	lea    -0x818(%rbp),%eax
    118c:	8d 95 40 f9 ff ff    	lea    -0x6c0(%rbp),%edx
    1192:	8b 4d d8             	mov    -0x28(%rbp),%ecx
    1195:	c1 e1 03             	shl    $0x3,%ecx
    1198:	01 ca                	add    %ecx,%edx
    119a:	89 d6                	mov    %edx,%esi
    119c:	8d 95 e0 f7 ff ff    	lea    -0x820(%rbp),%edx
    11a2:	8d 8b 73 c2 ff ff    	lea    -0x3d8d(%rbx),%ecx
    11a8:	89 8d bc fe ff ff    	mov    %ecx,-0x144(%rbp)
    11ae:	89 95 b8 fe ff ff    	mov    %edx,-0x148(%rbp)
    11b4:	89 b5 b4 fe ff ff    	mov    %esi,-0x14c(%rbp)
    11ba:	89 85 b0 fe ff ff    	mov    %eax,-0x150(%rbp)
    11c0:	50                   	push   %rax
    11c1:	53                   	push   %rbx
    11c2:	51                   	push   %rcx
    11c3:	52                   	push   %rdx
    11c4:	56                   	push   %rsi
    11c5:	57                   	push   %rdi
    11c6:	55                   	push   %rbp
    11c7:	90                   	nop
    11c8:	8b 85 bc fe ff ff    	mov    -0x144(%rbp),%eax
    11ce:	89 85 ac fe ff ff    	mov    %eax,-0x154(%rbp)
    11d4:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    11da:	89 85 a8 fe ff ff    	mov    %eax,-0x158(%rbp)
    11e0:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    11e6:	89 85 a4 fe ff ff    	mov    %eax,-0x15c(%rbp)
    11ec:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    11f2:	89 85 a0 fe ff ff    	mov    %eax,-0x160(%rbp)
    11f8:	8b 85 ac fe ff ff    	mov    -0x154(%rbp),%eax
    11fe:	8b b5 a8 fe ff ff    	mov    -0x158(%rbp),%esi
    1204:	8b 95 a4 fe ff ff    	mov    -0x15c(%rbp),%edx
    120a:	8b 8d a0 fe ff ff    	mov    -0x160(%rbp),%ecx
    1210:	83 ec 08             	sub    $0x8,%esp
    1213:	31 db                	xor    %ebx,%ebx
    1215:	b3 03                	mov    $0x3,%bl
    1217:	d1 e3                	shl    $1,%ebx
    1219:	c1 e3 02             	shl    $0x2,%ebx
    121c:	83 c3 1a             	add    $0x1a,%ebx
    121f:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    1224:	83 cb 00             	or     $0x0,%ebx
    1227:	90                   	nop
    1228:	85 db                	test   %ebx,%ebx
    122a:	90                   	nop
    122b:	89 1f                	mov    %ebx,(%rdi)
    122d:	89 04 24             	mov    %eax,(%rsp)
    1230:	bf 36 a2 04 08       	mov    $0x804a236,%edi
    1235:	cb                   	lret
    1236:	48 83 ec 08          	sub    $0x8,%rsp
    123a:	4d 31 c9             	xor    %r9,%r9
    123d:	41 b1 23             	mov    $0x23,%r9b
    1240:	49 c1 e1 00          	shl    $0x0,%r9
    1244:	49 83 c1 00          	add    $0x0,%r9
    1248:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    124d:	4d 89 ca             	mov    %r9,%r10
    1250:	49 d1 e2             	shl    $1,%r10
    1253:	49 d1 ea             	shr    $1,%r10
    1256:	4d 31 db             	xor    %r11,%r11
    1259:	49 ff c3             	inc    %r11
    125c:	49 ff cb             	dec    %r11
    125f:	4d 87 e4             	xchg   %r12,%r12
    1262:	45 89 08             	mov    %r9d,(%r8)
    1265:	c7 04 24 6d a2 04 08 	movl   $0x804a26d,(%rsp)
    126c:	cb                   	lret
    126d:	90                   	nop
    126e:	5d                   	pop    %rbp
    126f:	5f                   	pop    %rdi
    1270:	5e                   	pop    %rsi
    1271:	5a                   	pop    %rdx
    1272:	59                   	pop    %rcx
    1273:	5b                   	pop    %rbx
    1274:	58                   	pop    %rax
    1275:	90                   	nop
    1276:	90                   	nop
    1277:	8b 45 d8             	mov    -0x28(%rbp),%eax
    127a:	83 c0 01             	add    $0x1,%eax
    127d:	8b 94 c5 44 f9 ff ff 	mov    -0x6bc(%rbp,%rax,8),%edx
    1284:	8b 84 c5 40 f9 ff ff 	mov    -0x6c0(%rbp,%rax,8),%eax
    128b:	23 45 c0             	and    -0x40(%rbp),%eax
    128e:	23 55 c4             	and    -0x3c(%rbp),%edx
    1291:	89 85 d8 f7 ff ff    	mov    %eax,-0x828(%rbp)
    1297:	89 95 dc f7 ff ff    	mov    %edx,-0x824(%rbp)
    129d:	8d 85 d8 f7 ff ff    	lea    -0x828(%rbp),%eax
    12a3:	8d 95 e0 f7 ff ff    	lea    -0x820(%rbp),%edx
    12a9:	8d 8d 40 f9 ff ff    	lea    -0x6c0(%rbp),%ecx
    12af:	8b 75 d8             	mov    -0x28(%rbp),%esi
    12b2:	c1 e6 03             	shl    $0x3,%esi
    12b5:	01 f1                	add    %esi,%ecx
    12b7:	89 ce                	mov    %ecx,%esi
    12b9:	8d 8b b4 c2 ff ff    	lea    -0x3d4c(%rbx),%ecx
    12bf:	89 8d dc fe ff ff    	mov    %ecx,-0x124(%rbp)
    12c5:	89 b5 d8 fe ff ff    	mov    %esi,-0x128(%rbp)
    12cb:	89 95 d4 fe ff ff    	mov    %edx,-0x12c(%rbp)
    12d1:	89 85 d0 fe ff ff    	mov    %eax,-0x130(%rbp)
    12d7:	50                   	push   %rax
    12d8:	53                   	push   %rbx
    12d9:	51                   	push   %rcx
    12da:	52                   	push   %rdx
    12db:	56                   	push   %rsi
    12dc:	57                   	push   %rdi
    12dd:	55                   	push   %rbp
    12de:	90                   	nop
    12df:	8b 85 dc fe ff ff    	mov    -0x124(%rbp),%eax
    12e5:	89 85 cc fe ff ff    	mov    %eax,-0x134(%rbp)
    12eb:	8b 85 d8 fe ff ff    	mov    -0x128(%rbp),%eax
    12f1:	89 85 c8 fe ff ff    	mov    %eax,-0x138(%rbp)
    12f7:	8b 85 d4 fe ff ff    	mov    -0x12c(%rbp),%eax
    12fd:	89 85 c4 fe ff ff    	mov    %eax,-0x13c(%rbp)
    1303:	8b 85 d0 fe ff ff    	mov    -0x130(%rbp),%eax
    1309:	89 85 c0 fe ff ff    	mov    %eax,-0x140(%rbp)
    130f:	8b 85 cc fe ff ff    	mov    -0x134(%rbp),%eax
    1315:	8b b5 c8 fe ff ff    	mov    -0x138(%rbp),%esi
    131b:	8b 95 c4 fe ff ff    	mov    -0x13c(%rbp),%edx
    1321:	8b 8d c0 fe ff ff    	mov    -0x140(%rbp),%ecx
    1327:	83 ec 08             	sub    $0x8,%esp
    132a:	31 db                	xor    %ebx,%ebx
    132c:	b3 03                	mov    $0x3,%bl
    132e:	d1 e3                	shl    $1,%ebx
    1330:	c1 e3 02             	shl    $0x2,%ebx
    1333:	83 c3 1a             	add    $0x1a,%ebx
    1336:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    133b:	83 cb 00             	or     $0x0,%ebx
    133e:	90                   	nop
    133f:	85 db                	test   %ebx,%ebx
    1341:	90                   	nop
    1342:	89 1f                	mov    %ebx,(%rdi)
    1344:	89 04 24             	mov    %eax,(%rsp)
    1347:	bf 4d a3 04 08       	mov    $0x804a34d,%edi
    134c:	cb                   	lret
    134d:	48 83 ec 08          	sub    $0x8,%rsp
    1351:	4d 31 c9             	xor    %r9,%r9
    1354:	41 b1 23             	mov    $0x23,%r9b
    1357:	49 c1 e1 00          	shl    $0x0,%r9
    135b:	49 83 c1 00          	add    $0x0,%r9
    135f:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    1364:	4d 89 ca             	mov    %r9,%r10
    1367:	49 d1 e2             	shl    $1,%r10
    136a:	49 d1 ea             	shr    $1,%r10
    136d:	4d 31 db             	xor    %r11,%r11
    1370:	49 ff c3             	inc    %r11
    1373:	49 ff cb             	dec    %r11
    1376:	4d 87 e4             	xchg   %r12,%r12
    1379:	45 89 08             	mov    %r9d,(%r8)
    137c:	c7 04 24 84 a3 04 08 	movl   $0x804a384,(%rsp)
    1383:	cb                   	lret
    1384:	90                   	nop
    1385:	5d                   	pop    %rbp
    1386:	5f                   	pop    %rdi
    1387:	5e                   	pop    %rsi
    1388:	5a                   	pop    %rdx
    1389:	59                   	pop    %rcx
    138a:	5b                   	pop    %rbx
    138b:	58                   	pop    %rax
    138c:	90                   	nop
    138d:	90                   	nop
    138e:	8b 45 d8             	mov    -0x28(%rbp),%eax
    1391:	8b 94 c5 84 f9 ff ff 	mov    -0x67c(%rbp,%rax,8),%edx
    1398:	8b 84 c5 80 f9 ff ff 	mov    -0x680(%rbp,%rax,8),%eax
    139f:	23 45 c0             	and    -0x40(%rbp),%eax
    13a2:	23 55 c4             	and    -0x3c(%rbp),%edx
    13a5:	89 85 d0 f7 ff ff    	mov    %eax,-0x830(%rbp)
    13ab:	89 95 d4 f7 ff ff    	mov    %edx,-0x82c(%rbp)
    13b1:	8d 85 e8 f7 ff ff    	lea    -0x818(%rbp),%eax
    13b7:	8b 55 d8             	mov    -0x28(%rbp),%edx
    13ba:	8d 4a 01             	lea    0x1(%rdx),%ecx
    13bd:	8d 95 80 f9 ff ff    	lea    -0x680(%rbp),%edx
    13c3:	c1 e1 03             	shl    $0x3,%ecx
    13c6:	01 ca                	add    %ecx,%edx
    13c8:	89 d6                	mov    %edx,%esi
    13ca:	8d 95 c8 f7 ff ff    	lea    -0x838(%rbp),%edx
    13d0:	8d 8b 73 c2 ff ff    	lea    -0x3d8d(%rbx),%ecx
    13d6:	89 8d fc fe ff ff    	mov    %ecx,-0x104(%rbp)
    13dc:	89 95 f8 fe ff ff    	mov    %edx,-0x108(%rbp)
    13e2:	89 b5 f4 fe ff ff    	mov    %esi,-0x10c(%rbp)
    13e8:	89 85 f0 fe ff ff    	mov    %eax,-0x110(%rbp)
    13ee:	50                   	push   %rax
    13ef:	53                   	push   %rbx
    13f0:	51                   	push   %rcx
    13f1:	52                   	push   %rdx
    13f2:	56                   	push   %rsi
    13f3:	57                   	push   %rdi
    13f4:	55                   	push   %rbp
    13f5:	90                   	nop
    13f6:	8b 85 fc fe ff ff    	mov    -0x104(%rbp),%eax
    13fc:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
    1402:	8b 85 f8 fe ff ff    	mov    -0x108(%rbp),%eax
    1408:	89 85 e8 fe ff ff    	mov    %eax,-0x118(%rbp)
    140e:	8b 85 f4 fe ff ff    	mov    -0x10c(%rbp),%eax
    1414:	89 85 e4 fe ff ff    	mov    %eax,-0x11c(%rbp)
    141a:	8b 85 f0 fe ff ff    	mov    -0x110(%rbp),%eax
    1420:	89 85 e0 fe ff ff    	mov    %eax,-0x120(%rbp)
    1426:	8b 85 ec fe ff ff    	mov    -0x114(%rbp),%eax
    142c:	8b b5 e8 fe ff ff    	mov    -0x118(%rbp),%esi
    1432:	8b 95 e4 fe ff ff    	mov    -0x11c(%rbp),%edx
    1438:	8b 8d e0 fe ff ff    	mov    -0x120(%rbp),%ecx
    143e:	83 ec 08             	sub    $0x8,%esp
    1441:	31 db                	xor    %ebx,%ebx
    1443:	b3 03                	mov    $0x3,%bl
    1445:	d1 e3                	shl    $1,%ebx
    1447:	c1 e3 02             	shl    $0x2,%ebx
    144a:	83 c3 1a             	add    $0x1a,%ebx
    144d:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    1452:	83 cb 00             	or     $0x0,%ebx
    1455:	90                   	nop
    1456:	85 db                	test   %ebx,%ebx
    1458:	90                   	nop
    1459:	89 1f                	mov    %ebx,(%rdi)
    145b:	89 04 24             	mov    %eax,(%rsp)
    145e:	bf 64 a4 04 08       	mov    $0x804a464,%edi
    1463:	cb                   	lret
    1464:	48 83 ec 08          	sub    $0x8,%rsp
    1468:	4d 31 c9             	xor    %r9,%r9
    146b:	41 b1 23             	mov    $0x23,%r9b
    146e:	49 c1 e1 00          	shl    $0x0,%r9
    1472:	49 83 c1 00          	add    $0x0,%r9
    1476:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    147b:	4d 89 ca             	mov    %r9,%r10
    147e:	49 d1 e2             	shl    $1,%r10
    1481:	49 d1 ea             	shr    $1,%r10
    1484:	4d 31 db             	xor    %r11,%r11
    1487:	49 ff c3             	inc    %r11
    148a:	49 ff cb             	dec    %r11
    148d:	4d 87 e4             	xchg   %r12,%r12
    1490:	45 89 08             	mov    %r9d,(%r8)
    1493:	c7 04 24 9b a4 04 08 	movl   $0x804a49b,(%rsp)
    149a:	cb                   	lret
    149b:	90                   	nop
    149c:	5d                   	pop    %rbp
    149d:	5f                   	pop    %rdi
    149e:	5e                   	pop    %rsi
    149f:	5a                   	pop    %rdx
    14a0:	59                   	pop    %rcx
    14a1:	5b                   	pop    %rbx
    14a2:	58                   	pop    %rax
    14a3:	90                   	nop
    14a4:	90                   	nop
    14a5:	8d 85 c8 f7 ff ff    	lea    -0x838(%rbp),%eax
    14ab:	8d 95 d0 f7 ff ff    	lea    -0x830(%rbp),%edx
    14b1:	8b 4d d8             	mov    -0x28(%rbp),%ecx
    14b4:	8d 71 01             	lea    0x1(%rcx),%esi
    14b7:	8d 8d 40 f9 ff ff    	lea    -0x6c0(%rbp),%ecx
    14bd:	c1 e6 03             	shl    $0x3,%esi
    14c0:	01 f1                	add    %esi,%ecx
    14c2:	89 ce                	mov    %ecx,%esi
    14c4:	8d 8b b4 c2 ff ff    	lea    -0x3d4c(%rbx),%ecx
    14ca:	89 8d 1c ff ff ff    	mov    %ecx,-0xe4(%rbp)
    14d0:	89 b5 18 ff ff ff    	mov    %esi,-0xe8(%rbp)
    14d6:	89 95 14 ff ff ff    	mov    %edx,-0xec(%rbp)
    14dc:	89 85 10 ff ff ff    	mov    %eax,-0xf0(%rbp)
    14e2:	50                   	push   %rax
    14e3:	53                   	push   %rbx
    14e4:	51                   	push   %rcx
    14e5:	52                   	push   %rdx
    14e6:	56                   	push   %rsi
    14e7:	57                   	push   %rdi
    14e8:	55                   	push   %rbp
    14e9:	90                   	nop
    14ea:	8b 85 1c ff ff ff    	mov    -0xe4(%rbp),%eax
    14f0:	89 85 0c ff ff ff    	mov    %eax,-0xf4(%rbp)
    14f6:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    14fc:	89 85 08 ff ff ff    	mov    %eax,-0xf8(%rbp)
    1502:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    1508:	89 85 04 ff ff ff    	mov    %eax,-0xfc(%rbp)
    150e:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    1514:	89 85 00 ff ff ff    	mov    %eax,-0x100(%rbp)
    151a:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    1520:	8b b5 08 ff ff ff    	mov    -0xf8(%rbp),%esi
    1526:	8b 95 04 ff ff ff    	mov    -0xfc(%rbp),%edx
    152c:	8b 8d 00 ff ff ff    	mov    -0x100(%rbp),%ecx
    1532:	83 ec 08             	sub    $0x8,%esp
    1535:	31 db                	xor    %ebx,%ebx
    1537:	b3 03                	mov    $0x3,%bl
    1539:	d1 e3                	shl    $1,%ebx
    153b:	c1 e3 02             	shl    $0x2,%ebx
    153e:	83 c3 1a             	add    $0x1a,%ebx
    1541:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    1546:	83 cb 00             	or     $0x0,%ebx
    1549:	90                   	nop
    154a:	85 db                	test   %ebx,%ebx
    154c:	90                   	nop
    154d:	89 1f                	mov    %ebx,(%rdi)
    154f:	89 04 24             	mov    %eax,(%rsp)
    1552:	bf 58 a5 04 08       	mov    $0x804a558,%edi
    1557:	cb                   	lret
    1558:	48 83 ec 08          	sub    $0x8,%rsp
    155c:	4d 31 c9             	xor    %r9,%r9
    155f:	41 b1 23             	mov    $0x23,%r9b
    1562:	49 c1 e1 00          	shl    $0x0,%r9
    1566:	49 83 c1 00          	add    $0x0,%r9
    156a:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    156f:	4d 89 ca             	mov    %r9,%r10
    1572:	49 d1 e2             	shl    $1,%r10
    1575:	49 d1 ea             	shr    $1,%r10
    1578:	4d 31 db             	xor    %r11,%r11
    157b:	49 ff c3             	inc    %r11
    157e:	49 ff cb             	dec    %r11
    1581:	4d 87 e4             	xchg   %r12,%r12
    1584:	45 89 08             	mov    %r9d,(%r8)
    1587:	c7 04 24 8f a5 04 08 	movl   $0x804a58f,(%rsp)
    158e:	cb                   	lret
    158f:	90                   	nop
    1590:	5d                   	pop    %rbp
    1591:	5f                   	pop    %rdi
    1592:	5e                   	pop    %rsi
    1593:	5a                   	pop    %rdx
    1594:	59                   	pop    %rcx
    1595:	5b                   	pop    %rbx
    1596:	58                   	pop    %rax
    1597:	90                   	nop
    1598:	90                   	nop
    1599:	83 45 d8 02          	addl   $0x2,-0x28(%rbp)
    159d:	83 7d d8 07          	cmpl   $0x7,-0x28(%rbp)
    15a1:	0f 8e 8f fb ff ff    	jle    0x1136
    15a7:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    15ae:	e9 ba 07 00 00       	jmp    0x1d6d
    15b3:	8d 85 80 fc ff ff    	lea    -0x380(%rbp),%eax
    15b9:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    15bc:	c1 e2 03             	shl    $0x3,%edx
    15bf:	01 d0                	add    %edx,%eax
    15c1:	89 c1                	mov    %eax,%ecx
    15c3:	8d 85 40 f9 ff ff    	lea    -0x6c0(%rbp),%eax
    15c9:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    15cc:	c1 e2 03             	shl    $0x3,%edx
    15cf:	01 d0                	add    %edx,%eax
    15d1:	89 c6                	mov    %eax,%esi
    15d3:	8d 85 40 f8 ff ff    	lea    -0x7c0(%rbp),%eax
    15d9:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    15dc:	c1 e2 03             	shl    $0x3,%edx
    15df:	01 d0                	add    %edx,%eax
    15e1:	89 c2                	mov    %eax,%edx
    15e3:	8d 83 92 c1 ff ff    	lea    -0x3e6e(%rbx),%eax
    15e9:	89 85 dc fd ff ff    	mov    %eax,-0x224(%rbp)
    15ef:	89 95 d8 fd ff ff    	mov    %edx,-0x228(%rbp)
    15f5:	89 b5 d4 fd ff ff    	mov    %esi,-0x22c(%rbp)
    15fb:	89 8d d0 fd ff ff    	mov    %ecx,-0x230(%rbp)
    1601:	50                   	push   %rax
    1602:	53                   	push   %rbx
    1603:	51                   	push   %rcx
    1604:	52                   	push   %rdx
    1605:	56                   	push   %rsi
    1606:	57                   	push   %rdi
    1607:	55                   	push   %rbp
    1608:	90                   	nop
    1609:	8b 85 dc fd ff ff    	mov    -0x224(%rbp),%eax
    160f:	89 85 cc fd ff ff    	mov    %eax,-0x234(%rbp)
    1615:	8b 85 d8 fd ff ff    	mov    -0x228(%rbp),%eax
    161b:	89 85 c8 fd ff ff    	mov    %eax,-0x238(%rbp)
    1621:	8b 85 d4 fd ff ff    	mov    -0x22c(%rbp),%eax
    1627:	89 85 c4 fd ff ff    	mov    %eax,-0x23c(%rbp)
    162d:	8b 85 d0 fd ff ff    	mov    -0x230(%rbp),%eax
    1633:	89 85 c0 fd ff ff    	mov    %eax,-0x240(%rbp)
    1639:	8b 85 cc fd ff ff    	mov    -0x234(%rbp),%eax
    163f:	8b b5 c8 fd ff ff    	mov    -0x238(%rbp),%esi
    1645:	8b 95 c4 fd ff ff    	mov    -0x23c(%rbp),%edx
    164b:	8b 8d c0 fd ff ff    	mov    -0x240(%rbp),%ecx
    1651:	83 ec 08             	sub    $0x8,%esp
    1654:	31 db                	xor    %ebx,%ebx
    1656:	b3 03                	mov    $0x3,%bl
    1658:	d1 e3                	shl    $1,%ebx
    165a:	c1 e3 02             	shl    $0x2,%ebx
    165d:	83 c3 1a             	add    $0x1a,%ebx
    1660:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    1665:	83 cb 00             	or     $0x0,%ebx
    1668:	90                   	nop
    1669:	85 db                	test   %ebx,%ebx
    166b:	90                   	nop
    166c:	89 1f                	mov    %ebx,(%rdi)
    166e:	89 04 24             	mov    %eax,(%rsp)
    1671:	bf 77 a6 04 08       	mov    $0x804a677,%edi
    1676:	cb                   	lret
    1677:	48 83 ec 08          	sub    $0x8,%rsp
    167b:	4d 31 c9             	xor    %r9,%r9
    167e:	41 b1 23             	mov    $0x23,%r9b
    1681:	49 c1 e1 00          	shl    $0x0,%r9
    1685:	49 83 c1 00          	add    $0x0,%r9
    1689:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    168e:	4d 89 ca             	mov    %r9,%r10
    1691:	49 d1 e2             	shl    $1,%r10
    1694:	49 d1 ea             	shr    $1,%r10
    1697:	4d 31 db             	xor    %r11,%r11
    169a:	49 ff c3             	inc    %r11
    169d:	49 ff cb             	dec    %r11
    16a0:	4d 87 e4             	xchg   %r12,%r12
    16a3:	45 89 08             	mov    %r9d,(%r8)
    16a6:	c7 04 24 ae a6 04 08 	movl   $0x804a6ae,(%rsp)
    16ad:	cb                   	lret
    16ae:	90                   	nop
    16af:	5d                   	pop    %rbp
    16b0:	5f                   	pop    %rdi
    16b1:	5e                   	pop    %rsi
    16b2:	5a                   	pop    %rdx
    16b3:	59                   	pop    %rcx
    16b4:	5b                   	pop    %rbx
    16b5:	58                   	pop    %rax
    16b6:	90                   	nop
    16b7:	90                   	nop
    16b8:	8d 85 80 fb ff ff    	lea    -0x480(%rbp),%eax
    16be:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    16c1:	c1 e2 03             	shl    $0x3,%edx
    16c4:	01 d0                	add    %edx,%eax
    16c6:	89 c1                	mov    %eax,%ecx
    16c8:	8d 85 40 f8 ff ff    	lea    -0x7c0(%rbp),%eax
    16ce:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    16d1:	c1 e2 03             	shl    $0x3,%edx
    16d4:	01 d0                	add    %edx,%eax
    16d6:	89 c6                	mov    %eax,%esi
    16d8:	8d 85 00 f9 ff ff    	lea    -0x700(%rbp),%eax
    16de:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    16e1:	c1 e2 03             	shl    $0x3,%edx
    16e4:	01 d0                	add    %edx,%eax
    16e6:	89 c2                	mov    %eax,%edx
    16e8:	8d 83 36 c4 ff ff    	lea    -0x3bca(%rbx),%eax
    16ee:	89 85 fc fd ff ff    	mov    %eax,-0x204(%rbp)
    16f4:	89 95 f8 fd ff ff    	mov    %edx,-0x208(%rbp)
    16fa:	89 b5 f4 fd ff ff    	mov    %esi,-0x20c(%rbp)
    1700:	89 8d f0 fd ff ff    	mov    %ecx,-0x210(%rbp)
    1706:	50                   	push   %rax
    1707:	53                   	push   %rbx
    1708:	51                   	push   %rcx
    1709:	52                   	push   %rdx
    170a:	56                   	push   %rsi
    170b:	57                   	push   %rdi
    170c:	55                   	push   %rbp
    170d:	90                   	nop
    170e:	8b 85 fc fd ff ff    	mov    -0x204(%rbp),%eax
    1714:	89 85 ec fd ff ff    	mov    %eax,-0x214(%rbp)
    171a:	8b 85 f8 fd ff ff    	mov    -0x208(%rbp),%eax
    1720:	89 85 e8 fd ff ff    	mov    %eax,-0x218(%rbp)
    1726:	8b 85 f4 fd ff ff    	mov    -0x20c(%rbp),%eax
    172c:	89 85 e4 fd ff ff    	mov    %eax,-0x21c(%rbp)
    1732:	8b 85 f0 fd ff ff    	mov    -0x210(%rbp),%eax
    1738:	89 85 e0 fd ff ff    	mov    %eax,-0x220(%rbp)
    173e:	8b 85 ec fd ff ff    	mov    -0x214(%rbp),%eax
    1744:	8b b5 e8 fd ff ff    	mov    -0x218(%rbp),%esi
    174a:	8b 95 e4 fd ff ff    	mov    -0x21c(%rbp),%edx
    1750:	8b 8d e0 fd ff ff    	mov    -0x220(%rbp),%ecx
    1756:	83 ec 08             	sub    $0x8,%esp
    1759:	31 db                	xor    %ebx,%ebx
    175b:	b3 03                	mov    $0x3,%bl
    175d:	d1 e3                	shl    $1,%ebx
    175f:	c1 e3 02             	shl    $0x2,%ebx
    1762:	83 c3 1a             	add    $0x1a,%ebx
    1765:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    176a:	83 cb 00             	or     $0x0,%ebx
    176d:	90                   	nop
    176e:	85 db                	test   %ebx,%ebx
    1770:	90                   	nop
    1771:	89 1f                	mov    %ebx,(%rdi)
    1773:	89 04 24             	mov    %eax,(%rsp)
    1776:	bf 7c a7 04 08       	mov    $0x804a77c,%edi
    177b:	cb                   	lret
    177c:	48 83 ec 08          	sub    $0x8,%rsp
    1780:	4d 31 c9             	xor    %r9,%r9
    1783:	41 b1 23             	mov    $0x23,%r9b
    1786:	49 c1 e1 00          	shl    $0x0,%r9
    178a:	49 83 c1 00          	add    $0x0,%r9
    178e:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    1793:	4d 89 ca             	mov    %r9,%r10
    1796:	49 d1 e2             	shl    $1,%r10
    1799:	49 d1 ea             	shr    $1,%r10
    179c:	4d 31 db             	xor    %r11,%r11
    179f:	49 ff c3             	inc    %r11
    17a2:	49 ff cb             	dec    %r11
    17a5:	4d 87 e4             	xchg   %r12,%r12
    17a8:	45 89 08             	mov    %r9d,(%r8)
    17ab:	c7 04 24 b3 a7 04 08 	movl   $0x804a7b3,(%rsp)
    17b2:	cb                   	lret
    17b3:	90                   	nop
    17b4:	5d                   	pop    %rbp
    17b5:	5f                   	pop    %rdi
    17b6:	5e                   	pop    %rsi
    17b7:	5a                   	pop    %rdx
    17b8:	59                   	pop    %rcx
    17b9:	5b                   	pop    %rbx
    17ba:	58                   	pop    %rax
    17bb:	90                   	nop
    17bc:	90                   	nop
    17bd:	8d 85 80 fb ff ff    	lea    -0x480(%rbp),%eax
    17c3:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    17c6:	c1 e2 03             	shl    $0x3,%edx
    17c9:	01 d0                	add    %edx,%eax
    17cb:	89 c1                	mov    %eax,%ecx
    17cd:	8d 85 40 f8 ff ff    	lea    -0x7c0(%rbp),%eax
    17d3:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    17d6:	c1 e2 03             	shl    $0x3,%edx
    17d9:	01 d0                	add    %edx,%eax
    17db:	89 c6                	mov    %eax,%esi
    17dd:	8d 85 c0 f8 ff ff    	lea    -0x740(%rbp),%eax
    17e3:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    17e6:	c1 e2 03             	shl    $0x3,%edx
    17e9:	01 d0                	add    %edx,%eax
    17eb:	89 c2                	mov    %eax,%edx
    17ed:	8d 83 76 c4 ff ff    	lea    -0x3b8a(%rbx),%eax
    17f3:	89 85 1c fe ff ff    	mov    %eax,-0x1e4(%rbp)
    17f9:	89 95 18 fe ff ff    	mov    %edx,-0x1e8(%rbp)
    17ff:	89 b5 14 fe ff ff    	mov    %esi,-0x1ec(%rbp)
    1805:	89 8d 10 fe ff ff    	mov    %ecx,-0x1f0(%rbp)
    180b:	50                   	push   %rax
    180c:	53                   	push   %rbx
    180d:	51                   	push   %rcx
    180e:	52                   	push   %rdx
    180f:	56                   	push   %rsi
    1810:	57                   	push   %rdi
    1811:	55                   	push   %rbp
    1812:	90                   	nop
    1813:	8b 85 1c fe ff ff    	mov    -0x1e4(%rbp),%eax
    1819:	89 85 0c fe ff ff    	mov    %eax,-0x1f4(%rbp)
    181f:	8b 85 18 fe ff ff    	mov    -0x1e8(%rbp),%eax
    1825:	89 85 08 fe ff ff    	mov    %eax,-0x1f8(%rbp)
    182b:	8b 85 14 fe ff ff    	mov    -0x1ec(%rbp),%eax
    1831:	89 85 04 fe ff ff    	mov    %eax,-0x1fc(%rbp)
    1837:	8b 85 10 fe ff ff    	mov    -0x1f0(%rbp),%eax
    183d:	89 85 00 fe ff ff    	mov    %eax,-0x200(%rbp)
    1843:	8b 85 0c fe ff ff    	mov    -0x1f4(%rbp),%eax
    1849:	8b b5 08 fe ff ff    	mov    -0x1f8(%rbp),%esi
    184f:	8b 95 04 fe ff ff    	mov    -0x1fc(%rbp),%edx
    1855:	8b 8d 00 fe ff ff    	mov    -0x200(%rbp),%ecx
    185b:	83 ec 08             	sub    $0x8,%esp
    185e:	31 db                	xor    %ebx,%ebx
    1860:	b3 03                	mov    $0x3,%bl
    1862:	d1 e3                	shl    $1,%ebx
    1864:	c1 e3 02             	shl    $0x2,%ebx
    1867:	83 c3 1a             	add    $0x1a,%ebx
    186a:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    186f:	83 cb 00             	or     $0x0,%ebx
    1872:	90                   	nop
    1873:	85 db                	test   %ebx,%ebx
    1875:	90                   	nop
    1876:	89 1f                	mov    %ebx,(%rdi)
    1878:	89 04 24             	mov    %eax,(%rsp)
    187b:	bf 81 a8 04 08       	mov    $0x804a881,%edi
    1880:	cb                   	lret
    1881:	48 83 ec 08          	sub    $0x8,%rsp
    1885:	4d 31 c9             	xor    %r9,%r9
    1888:	41 b1 23             	mov    $0x23,%r9b
    188b:	49 c1 e1 00          	shl    $0x0,%r9
    188f:	49 83 c1 00          	add    $0x0,%r9
    1893:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    1898:	4d 89 ca             	mov    %r9,%r10
    189b:	49 d1 e2             	shl    $1,%r10
    189e:	49 d1 ea             	shr    $1,%r10
    18a1:	4d 31 db             	xor    %r11,%r11
    18a4:	49 ff c3             	inc    %r11
    18a7:	49 ff cb             	dec    %r11
    18aa:	4d 87 e4             	xchg   %r12,%r12
    18ad:	45 89 08             	mov    %r9d,(%r8)
    18b0:	c7 04 24 b8 a8 04 08 	movl   $0x804a8b8,(%rsp)
    18b7:	cb                   	lret
    18b8:	90                   	nop
    18b9:	5d                   	pop    %rbp
    18ba:	5f                   	pop    %rdi
    18bb:	5e                   	pop    %rsi
    18bc:	5a                   	pop    %rdx
    18bd:	59                   	pop    %rcx
    18be:	5b                   	pop    %rbx
    18bf:	58                   	pop    %rax
    18c0:	90                   	nop
    18c1:	90                   	nop
    18c2:	8d 85 80 fb ff ff    	lea    -0x480(%rbp),%eax
    18c8:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    18cb:	c1 e2 03             	shl    $0x3,%edx
    18ce:	01 d0                	add    %edx,%eax
    18d0:	89 c1                	mov    %eax,%ecx
    18d2:	8d 85 00 f9 ff ff    	lea    -0x700(%rbp),%eax
    18d8:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    18db:	c1 e2 03             	shl    $0x3,%edx
    18de:	01 d0                	add    %edx,%eax
    18e0:	89 c6                	mov    %eax,%esi
    18e2:	8d 85 80 f8 ff ff    	lea    -0x780(%rbp),%eax
    18e8:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    18eb:	c1 e2 03             	shl    $0x3,%edx
    18ee:	01 d0                	add    %edx,%eax
    18f0:	89 c2                	mov    %eax,%edx
    18f2:	8d 83 e7 c1 ff ff    	lea    -0x3e19(%rbx),%eax
    18f8:	89 85 3c fe ff ff    	mov    %eax,-0x1c4(%rbp)
    18fe:	89 95 38 fe ff ff    	mov    %edx,-0x1c8(%rbp)
    1904:	89 b5 34 fe ff ff    	mov    %esi,-0x1cc(%rbp)
    190a:	89 8d 30 fe ff ff    	mov    %ecx,-0x1d0(%rbp)
    1910:	50                   	push   %rax
    1911:	53                   	push   %rbx
    1912:	51                   	push   %rcx
    1913:	52                   	push   %rdx
    1914:	56                   	push   %rsi
    1915:	57                   	push   %rdi
    1916:	55                   	push   %rbp
    1917:	90                   	nop
    1918:	8b 85 3c fe ff ff    	mov    -0x1c4(%rbp),%eax
    191e:	89 85 2c fe ff ff    	mov    %eax,-0x1d4(%rbp)
    1924:	8b 85 38 fe ff ff    	mov    -0x1c8(%rbp),%eax
    192a:	89 85 28 fe ff ff    	mov    %eax,-0x1d8(%rbp)
    1930:	8b 85 34 fe ff ff    	mov    -0x1cc(%rbp),%eax
    1936:	89 85 24 fe ff ff    	mov    %eax,-0x1dc(%rbp)
    193c:	8b 85 30 fe ff ff    	mov    -0x1d0(%rbp),%eax
    1942:	89 85 20 fe ff ff    	mov    %eax,-0x1e0(%rbp)
    1948:	8b 85 2c fe ff ff    	mov    -0x1d4(%rbp),%eax
    194e:	8b b5 28 fe ff ff    	mov    -0x1d8(%rbp),%esi
    1954:	8b 95 24 fe ff ff    	mov    -0x1dc(%rbp),%edx
    195a:	8b 8d 20 fe ff ff    	mov    -0x1e0(%rbp),%ecx
    1960:	83 ec 08             	sub    $0x8,%esp
    1963:	31 db                	xor    %ebx,%ebx
    1965:	b3 03                	mov    $0x3,%bl
    1967:	d1 e3                	shl    $1,%ebx
    1969:	c1 e3 02             	shl    $0x2,%ebx
    196c:	83 c3 1a             	add    $0x1a,%ebx
    196f:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    1974:	83 cb 00             	or     $0x0,%ebx
    1977:	90                   	nop
    1978:	85 db                	test   %ebx,%ebx
    197a:	90                   	nop
    197b:	89 1f                	mov    %ebx,(%rdi)
    197d:	89 04 24             	mov    %eax,(%rsp)
    1980:	bf 86 a9 04 08       	mov    $0x804a986,%edi
    1985:	cb                   	lret
    1986:	48 83 ec 08          	sub    $0x8,%rsp
    198a:	4d 31 c9             	xor    %r9,%r9
    198d:	41 b1 23             	mov    $0x23,%r9b
    1990:	49 c1 e1 00          	shl    $0x0,%r9
    1994:	49 83 c1 00          	add    $0x0,%r9
    1998:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    199d:	4d 89 ca             	mov    %r9,%r10
    19a0:	49 d1 e2             	shl    $1,%r10
    19a3:	49 d1 ea             	shr    $1,%r10
    19a6:	4d 31 db             	xor    %r11,%r11
    19a9:	49 ff c3             	inc    %r11
    19ac:	49 ff cb             	dec    %r11
    19af:	4d 87 e4             	xchg   %r12,%r12
    19b2:	45 89 08             	mov    %r9d,(%r8)
    19b5:	c7 04 24 bd a9 04 08 	movl   $0x804a9bd,(%rsp)
    19bc:	cb                   	lret
    19bd:	90                   	nop
    19be:	5d                   	pop    %rbp
    19bf:	5f                   	pop    %rdi
    19c0:	5e                   	pop    %rsi
    19c1:	5a                   	pop    %rdx
    19c2:	59                   	pop    %rcx
    19c3:	5b                   	pop    %rbx
    19c4:	58                   	pop    %rax
    19c5:	90                   	nop
    19c6:	90                   	nop
    19c7:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    19ca:	8b b4 c5 80 f8 ff ff 	mov    -0x780(%rbp,%rax,8),%esi
    19d1:	8b bc c5 84 f8 ff ff 	mov    -0x77c(%rbp,%rax,8),%edi
    19d8:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    19db:	8b 94 c5 c4 f8 ff ff 	mov    -0x73c(%rbp,%rax,8),%edx
    19e2:	8b 84 c5 c0 f8 ff ff 	mov    -0x740(%rbp,%rax,8),%eax
    19e9:	01 f0                	add    %esi,%eax
    19eb:	11 fa                	adc    %edi,%edx
    19ed:	8b 4d d4             	mov    -0x2c(%rbp),%ecx
    19f0:	89 84 cd 40 f8 ff ff 	mov    %eax,-0x7c0(%rbp,%rcx,8)
    19f7:	89 94 cd 44 f8 ff ff 	mov    %edx,-0x7bc(%rbp,%rcx,8)
    19fe:	8d 95 f0 f7 ff ff    	lea    -0x810(%rbp),%edx
    1a04:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    1a07:	01 d0                	add    %edx,%eax
    1a09:	89 c1                	mov    %eax,%ecx
    1a0b:	8d 85 40 f8 ff ff    	lea    -0x7c0(%rbp),%eax
    1a11:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1a14:	c1 e2 03             	shl    $0x3,%edx
    1a17:	01 d0                	add    %edx,%eax
    1a19:	89 c6                	mov    %eax,%esi
    1a1b:	8d 85 80 fa ff ff    	lea    -0x580(%rbp),%eax
    1a21:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1a24:	c1 e2 03             	shl    $0x3,%edx
    1a27:	01 d0                	add    %edx,%eax
    1a29:	89 c2                	mov    %eax,%edx
    1a2b:	8d 83 fa c3 ff ff    	lea    -0x3c06(%rbx),%eax
    1a31:	89 85 5c fe ff ff    	mov    %eax,-0x1a4(%rbp)
    1a37:	89 95 58 fe ff ff    	mov    %edx,-0x1a8(%rbp)
    1a3d:	89 b5 54 fe ff ff    	mov    %esi,-0x1ac(%rbp)
    1a43:	89 8d 50 fe ff ff    	mov    %ecx,-0x1b0(%rbp)
    1a49:	50                   	push   %rax
    1a4a:	53                   	push   %rbx
    1a4b:	51                   	push   %rcx
    1a4c:	52                   	push   %rdx
    1a4d:	56                   	push   %rsi
    1a4e:	57                   	push   %rdi
    1a4f:	55                   	push   %rbp
    1a50:	90                   	nop
    1a51:	8b 85 5c fe ff ff    	mov    -0x1a4(%rbp),%eax
    1a57:	89 85 4c fe ff ff    	mov    %eax,-0x1b4(%rbp)
    1a5d:	8b 85 58 fe ff ff    	mov    -0x1a8(%rbp),%eax
    1a63:	89 85 48 fe ff ff    	mov    %eax,-0x1b8(%rbp)
    1a69:	8b 85 54 fe ff ff    	mov    -0x1ac(%rbp),%eax
    1a6f:	89 85 44 fe ff ff    	mov    %eax,-0x1bc(%rbp)
    1a75:	8b 85 50 fe ff ff    	mov    -0x1b0(%rbp),%eax
    1a7b:	89 85 40 fe ff ff    	mov    %eax,-0x1c0(%rbp)
    1a81:	8b 85 4c fe ff ff    	mov    -0x1b4(%rbp),%eax
    1a87:	8b b5 48 fe ff ff    	mov    -0x1b8(%rbp),%esi
    1a8d:	8b 95 44 fe ff ff    	mov    -0x1bc(%rbp),%edx
    1a93:	8b 8d 40 fe ff ff    	mov    -0x1c0(%rbp),%ecx
    1a99:	83 ec 08             	sub    $0x8,%esp
    1a9c:	31 db                	xor    %ebx,%ebx
    1a9e:	b3 03                	mov    $0x3,%bl
    1aa0:	d1 e3                	shl    $1,%ebx
    1aa2:	c1 e3 02             	shl    $0x2,%ebx
    1aa5:	83 c3 1a             	add    $0x1a,%ebx
    1aa8:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    1aad:	83 cb 00             	or     $0x0,%ebx
    1ab0:	90                   	nop
    1ab1:	85 db                	test   %ebx,%ebx
    1ab3:	90                   	nop
    1ab4:	89 1f                	mov    %ebx,(%rdi)
    1ab6:	89 04 24             	mov    %eax,(%rsp)
    1ab9:	bf bf aa 04 08       	mov    $0x804aabf,%edi
    1abe:	cb                   	lret
    1abf:	48 83 ec 08          	sub    $0x8,%rsp
    1ac3:	4d 31 c9             	xor    %r9,%r9
    1ac6:	41 b1 23             	mov    $0x23,%r9b
    1ac9:	49 c1 e1 00          	shl    $0x0,%r9
    1acd:	49 83 c1 00          	add    $0x0,%r9
    1ad1:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    1ad6:	4d 89 ca             	mov    %r9,%r10
    1ad9:	49 d1 e2             	shl    $1,%r10
    1adc:	49 d1 ea             	shr    $1,%r10
    1adf:	4d 31 db             	xor    %r11,%r11
    1ae2:	49 ff c3             	inc    %r11
    1ae5:	49 ff cb             	dec    %r11
    1ae8:	4d 87 e4             	xchg   %r12,%r12
    1aeb:	45 89 08             	mov    %r9d,(%r8)
    1aee:	c7 04 24 f6 aa 04 08 	movl   $0x804aaf6,(%rsp)
    1af5:	cb                   	lret
    1af6:	90                   	nop
    1af7:	5d                   	pop    %rbp
    1af8:	5f                   	pop    %rdi
    1af9:	5e                   	pop    %rsi
    1afa:	5a                   	pop    %rdx
    1afb:	59                   	pop    %rcx
    1afc:	5b                   	pop    %rbx
    1afd:	58                   	pop    %rax
    1afe:	90                   	nop
    1aff:	90                   	nop
    1b00:	8d 85 00 fb ff ff    	lea    -0x500(%rbp),%eax
    1b06:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1b09:	c1 e2 03             	shl    $0x3,%edx
    1b0c:	01 d0                	add    %edx,%eax
    1b0e:	89 c1                	mov    %eax,%ecx
    1b10:	8d 85 80 fa ff ff    	lea    -0x580(%rbp),%eax
    1b16:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1b19:	c1 e2 03             	shl    $0x3,%edx
    1b1c:	01 d0                	add    %edx,%eax
    1b1e:	89 c6                	mov    %eax,%esi
    1b20:	8d 85 40 fa ff ff    	lea    -0x5c0(%rbp),%eax
    1b26:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1b29:	c1 e2 03             	shl    $0x3,%edx
    1b2c:	01 d0                	add    %edx,%eax
    1b2e:	89 c2                	mov    %eax,%edx
    1b30:	8d 83 2f c2 ff ff    	lea    -0x3dd1(%rbx),%eax
    1b36:	89 85 7c fe ff ff    	mov    %eax,-0x184(%rbp)
    1b3c:	89 95 78 fe ff ff    	mov    %edx,-0x188(%rbp)
    1b42:	89 b5 74 fe ff ff    	mov    %esi,-0x18c(%rbp)
    1b48:	89 8d 70 fe ff ff    	mov    %ecx,-0x190(%rbp)
    1b4e:	50                   	push   %rax
    1b4f:	53                   	push   %rbx
    1b50:	51                   	push   %rcx
    1b51:	52                   	push   %rdx
    1b52:	56                   	push   %rsi
    1b53:	57                   	push   %rdi
    1b54:	55                   	push   %rbp
    1b55:	90                   	nop
    1b56:	8b 85 7c fe ff ff    	mov    -0x184(%rbp),%eax
    1b5c:	89 85 6c fe ff ff    	mov    %eax,-0x194(%rbp)
    1b62:	8b 85 78 fe ff ff    	mov    -0x188(%rbp),%eax
    1b68:	89 85 68 fe ff ff    	mov    %eax,-0x198(%rbp)
    1b6e:	8b 85 74 fe ff ff    	mov    -0x18c(%rbp),%eax
    1b74:	89 85 64 fe ff ff    	mov    %eax,-0x19c(%rbp)
    1b7a:	8b 85 70 fe ff ff    	mov    -0x190(%rbp),%eax
    1b80:	89 85 60 fe ff ff    	mov    %eax,-0x1a0(%rbp)
    1b86:	8b 85 6c fe ff ff    	mov    -0x194(%rbp),%eax
    1b8c:	8b b5 68 fe ff ff    	mov    -0x198(%rbp),%esi
    1b92:	8b 95 64 fe ff ff    	mov    -0x19c(%rbp),%edx
    1b98:	8b 8d 60 fe ff ff    	mov    -0x1a0(%rbp),%ecx
    1b9e:	83 ec 08             	sub    $0x8,%esp
    1ba1:	31 db                	xor    %ebx,%ebx
    1ba3:	b3 03                	mov    $0x3,%bl
    1ba5:	d1 e3                	shl    $1,%ebx
    1ba7:	c1 e3 02             	shl    $0x2,%ebx
    1baa:	83 c3 1a             	add    $0x1a,%ebx
    1bad:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    1bb2:	83 cb 00             	or     $0x0,%ebx
    1bb5:	90                   	nop
    1bb6:	85 db                	test   %ebx,%ebx
    1bb8:	90                   	nop
    1bb9:	89 1f                	mov    %ebx,(%rdi)
    1bbb:	89 04 24             	mov    %eax,(%rsp)
    1bbe:	bf c4 ab 04 08       	mov    $0x804abc4,%edi
    1bc3:	cb                   	lret
    1bc4:	48 83 ec 08          	sub    $0x8,%rsp
    1bc8:	4d 31 c9             	xor    %r9,%r9
    1bcb:	41 b1 23             	mov    $0x23,%r9b
    1bce:	49 c1 e1 00          	shl    $0x0,%r9
    1bd2:	49 83 c1 00          	add    $0x0,%r9
    1bd6:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    1bdb:	4d 89 ca             	mov    %r9,%r10
    1bde:	49 d1 e2             	shl    $1,%r10
    1be1:	49 d1 ea             	shr    $1,%r10
    1be4:	4d 31 db             	xor    %r11,%r11
    1be7:	49 ff c3             	inc    %r11
    1bea:	49 ff cb             	dec    %r11
    1bed:	4d 87 e4             	xchg   %r12,%r12
    1bf0:	45 89 08             	mov    %r9d,(%r8)
    1bf3:	c7 04 24 fb ab 04 08 	movl   $0x804abfb,(%rsp)
    1bfa:	cb                   	lret
    1bfb:	90                   	nop
    1bfc:	5d                   	pop    %rbp
    1bfd:	5f                   	pop    %rdi
    1bfe:	5e                   	pop    %rsi
    1bff:	5a                   	pop    %rdx
    1c00:	59                   	pop    %rcx
    1c01:	5b                   	pop    %rbx
    1c02:	58                   	pop    %rax
    1c03:	90                   	nop
    1c04:	90                   	nop
    1c05:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    1c08:	8b b4 c5 40 fa ff ff 	mov    -0x5c0(%rbp,%rax,8),%esi
    1c0f:	8b bc c5 44 fa ff ff 	mov    -0x5bc(%rbp,%rax,8),%edi
    1c16:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    1c19:	8b 94 c5 04 fc ff ff 	mov    -0x3fc(%rbp,%rax,8),%edx
    1c20:	8b 84 c5 00 fc ff ff 	mov    -0x400(%rbp,%rax,8),%eax
    1c27:	89 f9                	mov    %edi,%ecx
    1c29:	89 85 c0 f7 ff ff    	mov    %eax,-0x840(%rbp)
    1c2f:	89 95 c4 f7 ff ff    	mov    %edx,-0x83c(%rbp)
    1c35:	89 c2                	mov    %eax,%edx
    1c37:	0f af ca             	imul   %edx,%ecx
    1c3a:	89 c8                	mov    %ecx,%eax
    1c3c:	8b 8d c4 f7 ff ff    	mov    -0x83c(%rbp),%ecx
    1c42:	0f af ce             	imul   %esi,%ecx
    1c45:	01 c1                	add    %eax,%ecx
    1c47:	8b 85 c0 f7 ff ff    	mov    -0x840(%rbp),%eax
    1c4d:	f7 e6                	mul    %esi
    1c4f:	01 d1                	add    %edx,%ecx
    1c51:	89 ca                	mov    %ecx,%edx
    1c53:	8b 4d d4             	mov    -0x2c(%rbp),%ecx
    1c56:	89 84 cd 00 fa ff ff 	mov    %eax,-0x600(%rbp,%rcx,8)
    1c5d:	89 94 cd 04 fa ff ff 	mov    %edx,-0x5fc(%rbp,%rcx,8)
    1c64:	8d 85 40 fb ff ff    	lea    -0x4c0(%rbp),%eax
    1c6a:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1c6d:	c1 e2 03             	shl    $0x3,%edx
    1c70:	01 d0                	add    %edx,%eax
    1c72:	89 c1                	mov    %eax,%ecx
    1c74:	8d 85 00 fa ff ff    	lea    -0x600(%rbp),%eax
    1c7a:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1c7d:	c1 e2 03             	shl    $0x3,%edx
    1c80:	01 d0                	add    %edx,%eax
    1c82:	89 c6                	mov    %eax,%esi
    1c84:	8d 85 00 f8 ff ff    	lea    -0x800(%rbp),%eax
    1c8a:	8b 55 d4             	mov    -0x2c(%rbp),%edx
    1c8d:	c1 e2 03             	shl    $0x3,%edx
    1c90:	01 d0                	add    %edx,%eax
    1c92:	89 c2                	mov    %eax,%edx
    1c94:	8d 83 ac c4 ff ff    	lea    -0x3b54(%rbx),%eax
    1c9a:	89 85 9c fe ff ff    	mov    %eax,-0x164(%rbp)
    1ca0:	89 95 98 fe ff ff    	mov    %edx,-0x168(%rbp)
    1ca6:	89 b5 94 fe ff ff    	mov    %esi,-0x16c(%rbp)
    1cac:	89 8d 90 fe ff ff    	mov    %ecx,-0x170(%rbp)
    1cb2:	50                   	push   %rax
    1cb3:	53                   	push   %rbx
    1cb4:	51                   	push   %rcx
    1cb5:	52                   	push   %rdx
    1cb6:	56                   	push   %rsi
    1cb7:	57                   	push   %rdi
    1cb8:	55                   	push   %rbp
    1cb9:	90                   	nop
    1cba:	8b 85 9c fe ff ff    	mov    -0x164(%rbp),%eax
    1cc0:	89 85 8c fe ff ff    	mov    %eax,-0x174(%rbp)
    1cc6:	8b 85 98 fe ff ff    	mov    -0x168(%rbp),%eax
    1ccc:	89 85 88 fe ff ff    	mov    %eax,-0x178(%rbp)
    1cd2:	8b 85 94 fe ff ff    	mov    -0x16c(%rbp),%eax
    1cd8:	89 85 84 fe ff ff    	mov    %eax,-0x17c(%rbp)
    1cde:	8b 85 90 fe ff ff    	mov    -0x170(%rbp),%eax
    1ce4:	89 85 80 fe ff ff    	mov    %eax,-0x180(%rbp)
    1cea:	8b 85 8c fe ff ff    	mov    -0x174(%rbp),%eax
    1cf0:	8b b5 88 fe ff ff    	mov    -0x178(%rbp),%esi
    1cf6:	8b 95 84 fe ff ff    	mov    -0x17c(%rbp),%edx
    1cfc:	8b 8d 80 fe ff ff    	mov    -0x180(%rbp),%ecx
    1d02:	83 ec 08             	sub    $0x8,%esp
    1d05:	31 db                	xor    %ebx,%ebx
    1d07:	b3 03                	mov    $0x3,%bl
    1d09:	d1 e3                	shl    $1,%ebx
    1d0b:	c1 e3 02             	shl    $0x2,%ebx
    1d0e:	83 c3 1a             	add    $0x1a,%ebx
    1d11:	43 8d 7c 24 04       	lea    0x4(%r12,%r12,1),%edi
    1d16:	83 cb 00             	or     $0x0,%ebx
    1d19:	90                   	nop
    1d1a:	85 db                	test   %ebx,%ebx
    1d1c:	90                   	nop
    1d1d:	89 1f                	mov    %ebx,(%rdi)
    1d1f:	89 04 24             	mov    %eax,(%rsp)
    1d22:	bf 28 ad 04 08       	mov    $0x804ad28,%edi
    1d27:	cb                   	lret
    1d28:	48 83 ec 08          	sub    $0x8,%rsp
    1d2c:	4d 31 c9             	xor    %r9,%r9
    1d2f:	41 b1 23             	mov    $0x23,%r9b
    1d32:	49 c1 e1 00          	shl    $0x0,%r9
    1d36:	49 83 c1 00          	add    $0x0,%r9
    1d3a:	4c 8d 44 24 04       	lea    0x4(%rsp),%r8
    1d3f:	4d 89 ca             	mov    %r9,%r10
    1d42:	49 d1 e2             	shl    $1,%r10
    1d45:	49 d1 ea             	shr    $1,%r10
    1d48:	4d 31 db             	xor    %r11,%r11
    1d4b:	49 ff c3             	inc    %r11
    1d4e:	49 ff cb             	dec    %r11
    1d51:	4d 87 e4             	xchg   %r12,%r12
    1d54:	45 89 08             	mov    %r9d,(%r8)
    1d57:	c7 04 24 5f ad 04 08 	movl   $0x804ad5f,(%rsp)
    1d5e:	cb                   	lret
    1d5f:	90                   	nop
    1d60:	5d                   	pop    %rbp
    1d61:	5f                   	pop    %rdi
    1d62:	5e                   	pop    %rsi
    1d63:	5a                   	pop    %rdx
    1d64:	59                   	pop    %rcx
    1d65:	5b                   	pop    %rbx
    1d66:	58                   	pop    %rax
    1d67:	90                   	nop
    1d68:	90                   	nop
    1d69:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    1d6d:	83 7d d4 07          	cmpl   $0x7,-0x2c(%rbp)
    1d71:	0f 8e 3c f8 ff ff    	jle    0x15b3
    1d77:	c7 45 d0 01 00 00 00 	movl   $0x1,-0x30(%rbp)
    1d7e:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
    1d85:	eb 51                	jmp    0x1dd8
    1d87:	8b 45 cc             	mov    -0x34(%rbp),%eax
    1d8a:	8b b4 c5 00 f8 ff ff 	mov    -0x800(%rbp,%rax,8),%esi
    1d91:	8b bc c5 04 f8 ff ff 	mov    -0x7fc(%rbp,%rax,8),%edi
    1d98:	8b 45 cc             	mov    -0x34(%rbp),%eax
    1d9b:	8b 94 c5 c4 fa ff ff 	mov    -0x53c(%rbp,%rax,8),%edx
    1da2:	8b 84 c5 c0 fa ff ff 	mov    -0x540(%rbp,%rax,8),%eax
    1da9:	89 b5 c0 f7 ff ff    	mov    %esi,-0x840(%rbp)
    1daf:	89 85 bc f7 ff ff    	mov    %eax,-0x844(%rbp)
    1db5:	89 f9                	mov    %edi,%ecx
    1db7:	8b 85 c0 f7 ff ff    	mov    -0x840(%rbp),%eax
    1dbd:	8b bd bc f7 ff ff    	mov    -0x844(%rbp),%edi
    1dc3:	31 f8                	xor    %edi,%eax
    1dc5:	31 ca                	xor    %ecx,%edx
    1dc7:	09 d0                	or     %edx,%eax
    1dc9:	74 09                	je     0x1dd4
    1dcb:	c7 45 d0 00 00 00 00 	movl   $0x0,-0x30(%rbp)
    1dd2:	eb 0a                	jmp    0x1dde
    1dd4:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
    1dd8:	83 7d cc 07          	cmpl   $0x7,-0x34(%rbp)
    1ddc:	7e a9                	jle    0x1d87
    1dde:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    1de2:	74 14                	je     0x1df8
    1de4:	83 ec 0c             	sub    $0xc,%esp
    1de7:	8d 83 14 e0 ff ff    	lea    -0x1fec(%rbx),%eax
    1ded:	50                   	push   %rax
    1dee:	e8 6d e2 ff ff       	call   0x60
    1df3:	83 c4 10             	add    $0x10,%esp
    1df6:	eb 12                	jmp    0x1e0a
    1df8:	83 ec 0c             	sub    $0xc,%esp
    1dfb:	8d 83 1c e0 ff ff    	lea    -0x1fe4(%rbx),%eax
    1e01:	50                   	push   %rax
    1e02:	e8 59 e2 ff ff       	call   0x60
    1e07:	83 c4 10             	add    $0x10,%esp
    1e0a:	b8 00 00 00 00       	mov    $0x0,%eax
    1e0f:	8d 65 f0             	lea    -0x10(%rbp),%esp
    1e12:	59                   	pop    %rcx
    1e13:	5b                   	pop    %rbx
    1e14:	5e                   	pop    %rsi
    1e15:	5f                   	pop    %rdi
    1e16:	5d                   	pop    %rbp
    1e17:	8d 61 fc             	lea    -0x4(%rcx),%esp
    1e1a:	c3                   	ret
    1e1b:	8b 04 24             	mov    (%rsp),%eax
    1e1e:	c3                   	ret
    1e1f:	00 53 83             	add    %dl,-0x7d(%rbx)
    1e22:	ec                   	in     (%dx),%al
    1e23:	08 e8                	or     %ch,%al
    1e25:	97                   	xchg   %eax,%edi
    1e26:	e2 ff                	loop   0x1e27
    1e28:	ff 81 c3 cb 21 00    	incl   0x21cbc3(%rcx)
    1e2e:	00 83 c4 08 5b c3    	add    %al,-0x3ca4f73c(%rbx)
	...
