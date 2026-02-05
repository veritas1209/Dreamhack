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
