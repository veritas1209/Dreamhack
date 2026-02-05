=> 0x8049099:	mov    (%esp),%ebx
   0x804909c:	ret
   0x804909d:	jmp    0x80494e7
   0x80490a2:	xchg   %ax,%ax
   0x80490a4:	xchg   %ax,%ax
   0x80490a6:	xchg   %ax,%ax
   0x80490a8:	xchg   %ax,%ax
   0x80490aa:	xchg   %ax,%ax
   0x80490ac:	xchg   %ax,%ax
   0x80490ae:	xchg   %ax,%ax
   0x80490b0:	ret
   0x80490b1:	xchg   %ax,%ax
   0x80490b3:	xchg   %ax,%ax
   0x80490b5:	xchg   %ax,%ax
   0x80490b7:	xchg   %ax,%ax
   0x80490b9:	xchg   %ax,%ax
   0x80490bb:	xchg   %ax,%ax
   0x80490bd:	xchg   %ax,%ax
   0x80490bf:	nop
   0x80490c0:	mov    (%esp),%ebx
   0x80490c3:	ret
   0x80490c4:	xchg   %ax,%ax
   0x80490c6:	xchg   %ax,%ax
   0x80490c8:	xchg   %ax,%ax
   0x80490ca:	xchg   %ax,%ax
   0x80490cc:	xchg   %ax,%ax
   0x80490ce:	xchg   %ax,%ax
   0x80490d0:	mov    $0x804d018,%eax
   0x80490d5:	cmp    $0x804d018,%eax
   0x80490da:	je     0x8049100
   0x80490dc:	mov    $0x0,%eax
   0x80490e1:	test   %eax,%eax
   0x80490e3:	je     0x8049100
   0x80490e5:	push   %ebp
   0x80490e6:	mov    %esp,%ebp
   0x80490e8:	sub    $0x14,%esp
   0x80490eb:	push   $0x804d018
   0x80490f0:	call   *%eax
   0x80490f2:	add    $0x10,%esp
   0x80490f5:	leave
   0x80490f6:	ret
   0x80490f7:	lea    %cs:0x0(%esi,%eiz,1),%esi
   0x80490ff:	nop
   0x8049100:	ret
   0x8049101:	lea    %cs:0x0(%esi,%eiz,1),%esi
   0x8049109:	lea    0x0(%esi,%eiz,1),%esi
   0x8049110:	mov    $0x804d018,%eax
   0x8049115:	sub    $0x804d018,%eax
   0x804911a:	mov    %eax,%edx
   0x804911c:	shr    $0x1f,%eax
   0x804911f:	sar    $0x2,%edx
   0x8049122:	add    %edx,%eax
   0x8049124:	sar    $1,%eax
   0x8049126:	je     0x8049148
   0x8049128:	mov    $0x0,%edx
   0x804912d:	test   %edx,%edx
   0x804912f:	je     0x8049148
   0x8049131:	push   %ebp
   0x8049132:	mov    %esp,%ebp
   0x8049134:	sub    $0x10,%esp
   0x8049137:	push   %eax
   0x8049138:	push   $0x804d018
   0x804913d:	call   *%edx
   0x804913f:	add    $0x10,%esp
   0x8049142:	leave
   0x8049143:	ret
   0x8049144:	lea    0x0(%esi,%eiz,1),%esi
   0x8049148:	ret
   0x8049149:	lea    0x0(%esi,%eiz,1),%esi
   0x8049150:	endbr32
   0x8049154:	cmpb   $0x0,0x804d018
   0x804915b:	jne    0x8049178
   0x804915d:	push   %ebp
   0x804915e:	mov    %esp,%ebp
   0x8049160:	sub    $0x8,%esp
   0x8049163:	call   0x80490d0
   0x8049168:	movb   $0x1,0x804d018
   0x804916f:	leave
   0x8049170:	ret
   0x8049171:	lea    0x0(%esi,%eiz,1),%esi
   0x8049178:	ret
   0x8049179:	lea    0x0(%esi,%eiz,1),%esi
   0x8049180:	endbr32
   0x8049184:	jmp    0x8049110
   0x8049186:	call   0x804ae1b
   0x804918b:	add    $0x3e69,%eax
   0x8049190:	dec    %eax
   0x8049191:	sub    $0x60,%esp
   0x8049194:	dec    %eax
   0x8049195:	mov    (%edx),%eax
   0x8049197:	dec    %eax
   0x8049198:	mov    %eax,0x8(%esp)
   0x804919c:	dec    %eax
   0x804919d:	mov    (%ecx),%eax
   0x804919f:	dec    %eax
   0x80491a0:	mov    %eax,0x10(%esp)
   0x80491a4:	dec    %eax
   0x80491a5:	mov    0x8(%esp),%eax
   0x80491a9:	dec    %eax
   0x80491aa:	mov    0x10(%esp),%ebx
   0x80491ae:	dec    %eax
   0x80491af:	lea    (%eax,%ebx,1),%edx
   0x80491b2:	dec    %eax
   0x80491b3:	mov    %edx,0x18(%esp)
   0x80491b7:	dec    %eax
   0x80491b8:	xor    %eax,%eax
   0x80491ba:	dec    %eax
   0x80491bb:	mov    0x18(%esp),%eax
   0x80491bf:	dec    %eax
   0x80491c0:	mov    %eax,%edx
   0x80491c2:	dec    %eax
   0x80491c3:	add    $0x0,%edx
   0x80491c6:	dec    %eax
   0x80491c7:	xor    %ecx,%ecx
   0x80491c9:	dec    %eax
   0x80491ca:	lea    (%edx),%ecx
   0x80491cc:	dec    %eax
   0x80491cd:	mov    %ecx,%eax
   0x80491cf:	dec    %eax
   0x80491d0:	mov    %eax,(%esi)
   0x80491d2:	dec    %eax
   0x80491d3:	add    $0x60,%esp
   0x80491d6:	jmp    *%edi
   0x80491d8:	nop
   0x80491d9:	ud2
   0x80491db:	call   0x804ae1b
   0x80491e0:	add    $0x3e14,%eax
   0x80491e5:	dec    %eax
   0x80491e6:	sub    $0x60,%esp
   0x80491e9:	dec    %eax
   0x80491ea:	mov    (%edx),%eax
   0x80491ec:	dec    %eax
   0x80491ed:	mov    %eax,0x8(%esp)
   0x80491f1:	dec    %eax
   0x80491f2:	mov    (%ecx),%eax
   0x80491f4:	dec    %eax
   0x80491f5:	mov    %eax,0x10(%esp)
   0x80491f9:	dec    %eax
   0x80491fa:	mov    0x8(%esp),%eax
   0x80491fe:	dec    %eax
   0x80491ff:	mov    0x10(%esp),%ebx
   0x8049203:	dec    %eax
   0x8049204:	imul   %ebx,%eax
   0x8049207:	dec    %eax
   0x8049208:	mov    %eax,0x18(%esp)
   0x804920c:	dec    %eax
   0x804920d:	mov    0x18(%esp),%ecx
   0x8049211:	dec    %eax
   0x8049212:	lea    (%ecx),%edx
   0x8049214:	dec    %eax
   0x8049215:	mov    %edx,%eax
   0x8049217:	dec    %eax
   0x8049218:	mov    %eax,(%esi)
   0x804921a:	dec    %eax
   0x804921b:	add    $0x60,%esp
   0x804921e:	jmp    *%edi
   0x8049220:	nop
   0x8049221:	ud2
   0x8049223:	call   0x804ae1b
   0x8049228:	add    $0x3dcc,%eax
   0x804922d:	dec    %eax
   0x804922e:	sub    $0x60,%esp
   0x8049231:	dec    %eax
   0x8049232:	mov    (%edx),%eax
   0x8049234:	dec    %eax
   0x8049235:	mov    %eax,0x8(%esp)
   0x8049239:	dec    %eax
   0x804923a:	mov    (%ecx),%eax
   0x804923c:	dec    %eax
   0x804923d:	mov    %eax,0x10(%esp)
   0x8049241:	dec    %eax
   0x8049242:	mov    0x8(%esp),%eax
   0x8049246:	dec    %eax
   0x8049247:	mov    0x10(%esp),%ebx
   0x804924b:	dec    %eax
   0x804924c:	mov    %eax,%ecx
   0x804924e:	dec    %eax
   0x804924f:	xor    %ebx,%ecx
   0x8049251:	dec    %eax
   0x8049252:	mov    %ecx,0x18(%esp)
   0x8049256:	dec    %eax
   0x8049257:	mov    0x18(%esp),%eax
   0x804925b:	dec    %eax
   0x804925c:	mov    %eax,(%esi)
   0x804925e:	dec    %eax
   0x804925f:	add    $0x60,%esp
   0x8049262:	jmp    *%edi
   0x8049264:	nop
   0x8049265:	ud2
   0x8049267:	call   0x804ae1b
   0x804926c:	add    $0x3d88,%eax
   0x8049271:	dec    %eax
   0x8049272:	sub    $0x60,%esp
   0x8049275:	dec    %eax
   0x8049276:	mov    (%edx),%eax
   0x8049278:	dec    %eax
   0x8049279:	mov    %eax,0x8(%esp)
   0x804927d:	dec    %eax
   0x804927e:	mov    (%ecx),%eax
   0x8049280:	dec    %eax