	.file	"policy_lang.c"
	.text
	.type	g_string_append_c_inline, @function
g_string_append_c_inline:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	12(%ebp), %eax
	movb	%al, -12(%ebp)
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	leal	1(%eax), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	cmpl	%eax, %edx
	jae	.L2
	movl	8(%ebp), %eax
	movl	(%eax), %edx
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	leal	(%edx,%eax), %ecx
	movzbl	-12(%ebp), %edx
	movb	%dl, (%ecx)
	leal	1(%eax), %edx
	movl	8(%ebp), %eax
	movl	%edx, 4(%eax)
	movl	8(%ebp), %eax
	movl	(%eax), %edx
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	leal	(%edx,%eax), %eax
	movb	$0, (%eax)
	jmp	.L3
.L2:
	movsbl	-12(%ebp),%eax
	movl	%eax, 8(%esp)
	movl	$-1, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_insert_c
.L3:
	movl	8(%ebp), %eax
	leave
	ret
	.size	g_string_append_c_inline, .-g_string_append_c_inline
.globl final_policy
	.bss
	.align 4
	.type	final_policy, @object
	.size	final_policy, 4
final_policy:
	.zero	4
	.section	.rodata
	.align 32
	.type	yytranslate, @object
	.size	yytranslate, 265
yytranslate:
	.byte	0
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	10
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	11
	.byte	12
	.byte	2
	.byte	2
	.byte	16
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	14
	.byte	13
	.byte	15
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.type	yyr1, @object
	.size	yyr1, 22
yyr1:
	.byte	0
	.byte	17
	.byte	18
	.byte	19
	.byte	19
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	20
	.byte	21
	.byte	21
	.type	yyr2, @object
	.size	yyr2, 22
yyr2:
	.byte	0
	.byte	2
	.byte	1
	.byte	3
	.byte	1
	.byte	1
	.byte	3
	.byte	3
	.byte	5
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	1
	.byte	3
	.align 32
	.type	yydefact, @object
	.size	yydefact, 44
yydefact:
	.byte	0
	.byte	5
	.byte	4
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	1
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	4
	.byte	12
	.byte	13
	.byte	9
	.byte	10
	.byte	11
	.byte	0
	.byte	3
	.byte	19
	.byte	17
	.byte	18
	.byte	14
	.byte	15
	.byte	16
	.byte	6
	.byte	7
	.byte	20
	.byte	0
	.byte	8
	.byte	0
	.byte	21
	.type	yydefgoto, @object
	.size	yydefgoto, 5
yydefgoto:
	.byte	-1
	.byte	4
	.byte	5
	.byte	6
	.byte	40
	.align 32
	.type	yypact, @object
	.size	yypact, 44
yypact:
	.byte	-2
	.byte	-1
	.byte	-4
	.byte	-2
	.byte	4
	.byte	2
	.byte	17
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	13
	.byte	29
	.byte	15
	.byte	-5
	.byte	32
	.byte	33
	.byte	34
	.byte	37
	.byte	38
	.byte	-2
	.byte	-2
	.byte	35
	.byte	-5
	.byte	-5
	.byte	-5
	.byte	-5
	.byte	-5
	.byte	-2
	.byte	-5
	.byte	-5
	.byte	-5
	.byte	-5
	.byte	-5
	.byte	-5
	.byte	-5
	.byte	19
	.byte	-5
	.byte	17
	.byte	22
	.byte	-5
	.byte	-2
	.byte	17
	.type	yypgoto, @object
	.size	yypgoto, 5
yypgoto:
	.byte	-5
	.byte	-5
	.byte	21
	.byte	-3
	.byte	-5
	.align 32
	.type	yytable, @object
	.size	yytable, 46
yytable:
	.byte	14
	.byte	1
	.byte	2
	.byte	12
	.byte	15
	.byte	23
	.byte	13
	.byte	7
	.byte	8
	.byte	3
	.byte	16
	.byte	17
	.byte	9
	.byte	10
	.byte	11
	.byte	18
	.byte	19
	.byte	20
	.byte	37
	.byte	38
	.byte	21
	.byte	22
	.byte	21
	.byte	22
	.byte	29
	.byte	22
	.byte	39
	.byte	31
	.byte	24
	.byte	25
	.byte	26
	.byte	27
	.byte	28
	.byte	30
	.byte	41
	.byte	32
	.byte	33
	.byte	34
	.byte	42
	.byte	43
	.byte	35
	.byte	36
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.align 32
	.type	yycheck, @object
	.size	yycheck, 46
yycheck:
	.byte	3
	.byte	3
	.byte	4
	.byte	7
	.byte	0
	.byte	4
	.byte	10
	.byte	8
	.byte	9
	.byte	11
	.byte	8
	.byte	9
	.byte	13
	.byte	14
	.byte	15
	.byte	13
	.byte	14
	.byte	15
	.byte	21
	.byte	22
	.byte	5
	.byte	6
	.byte	5
	.byte	6
	.byte	11
	.byte	6
	.byte	29
	.byte	12
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	4
	.byte	12
	.byte	3
	.byte	3
	.byte	3
	.byte	16
	.byte	42
	.byte	3
	.byte	3
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	10
	.align 32
	.type	yystos, @object
	.size	yystos, 44
yystos:
	.byte	0
	.byte	3
	.byte	4
	.byte	11
	.byte	18
	.byte	19
	.byte	20
	.byte	8
	.byte	9
	.byte	13
	.byte	14
	.byte	15
	.byte	7
	.byte	10
	.byte	20
	.byte	0
	.byte	8
	.byte	9
	.byte	13
	.byte	14
	.byte	15
	.byte	5
	.byte	6
	.byte	4
	.byte	19
	.byte	19
	.byte	19
	.byte	19
	.byte	19
	.byte	11
	.byte	4
	.byte	12
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	20
	.byte	20
	.byte	20
	.byte	21
	.byte	12
	.byte	16
	.byte	20
.LC0:
	.string	"Deleting"
	.text
	.type	yydestruct, @function
yydestruct:
	pushl	%ebp
	movl	%esp, %ebp
	cmpl	$0, 8(%ebp)
	jne	.L7
	movl	$.LC0, 8(%ebp)
.L7:
	popl	%ebp
	ret
	.size	yydestruct, .-yydestruct
	.comm	yychar,4,4
	.comm	yylval,8,4
	.comm	yynerrs,4,4
	.section	.rodata
.LC1:
	.string	"syntax error"
.LC2:
	.string	"Error: discarding"
.LC3:
	.string	"Error: popping"
.LC4:
	.string	"memory exhausted"
.LC5:
	.string	"Cleanup: discarding lookahead"
.LC6:
	.string	"Cleanup: popping"
	.text
.globl yyparse
	.type	yyparse, @function
yyparse:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$2100, %esp
	movl	$0, -52(%ebp)
	movl	$0, -48(%ebp)
	leal	-480(%ebp), %eax
	movl	%eax, -20(%ebp)
	leal	-2080(%ebp), %eax
	movl	%eax, -28(%ebp)
	movl	$200, -36(%ebp)
	movl	$0, -12(%ebp)
	movl	$0, -16(%ebp)
	movl	$0, yynerrs
	movl	$-2, yychar
	movl	-20(%ebp), %eax
	movl	%eax, -24(%ebp)
	movl	-28(%ebp), %eax
	movl	%eax, -32(%ebp)
	jmp	.L9
.L10:
	addl	$2, -24(%ebp)
.L9:
	movl	-12(%ebp), %eax
	movl	%eax, %edx
	movl	-24(%ebp), %eax
	movw	%dx, (%eax)
	movl	-36(%ebp), %eax
	subl	$1, %eax
	addl	%eax, %eax
	addl	-20(%ebp), %eax
	cmpl	-24(%ebp), %eax
	ja	.L11
	movl	-24(%ebp), %edx
	movl	-20(%ebp), %eax
	movl	%edx, %ecx
	subl	%eax, %ecx
	movl	%ecx, %eax
	sarl	%eax
	addl	$1, %eax
	movl	%eax, -56(%ebp)
	cmpl	$9999, -36(%ebp)
	ja	.L70
.L12:
	sall	-36(%ebp)
	cmpl	$10000, -36(%ebp)
	jbe	.L14
	movl	$10000, -36(%ebp)
.L14:
	movl	-20(%ebp), %eax
	movl	%eax, -60(%ebp)
	movl	-36(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	addl	$7, %eax
	movl	%eax, (%esp)
	call	malloc
	movl	%eax, -64(%ebp)
	cmpl	$0, -64(%ebp)
	je	.L71
.L15:
	movl	-56(%ebp), %eax
	leal	(%eax,%eax), %edx
	movl	-64(%ebp), %eax
	movl	%edx, 8(%esp)
	movl	-20(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	memcpy
	movl	-64(%ebp), %eax
	movl	%eax, -20(%ebp)
	movl	-36(%ebp), %eax
	addl	%eax, %eax
	addl	$7, %eax
	movl	%eax, -68(%ebp)
	movl	-68(%ebp), %eax
	shrl	$3, %eax
	sall	$3, %eax
	addl	%eax, -64(%ebp)
	movl	-56(%ebp), %eax
	leal	0(,%eax,8), %edx
	movl	-64(%ebp), %eax
	movl	%edx, 8(%esp)
	movl	-28(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	memcpy
	movl	-64(%ebp), %eax
	movl	%eax, -28(%ebp)
	movl	-36(%ebp), %eax
	sall	$3, %eax
	addl	$7, %eax
	movl	%eax, -72(%ebp)
	movl	-72(%ebp), %eax
	shrl	$3, %eax
	sall	$3, %eax
	addl	%eax, -64(%ebp)
	leal	-480(%ebp), %eax
	cmpl	%eax, -60(%ebp)
	je	.L16
	movl	-60(%ebp), %eax
	movl	%eax, (%esp)
	call	free
.L16:
	movl	-56(%ebp), %eax
	subl	$1, %eax
	addl	%eax, %eax
	addl	-20(%ebp), %eax
	movl	%eax, -24(%ebp)
	movl	-56(%ebp), %eax
	subl	$1, %eax
	sall	$3, %eax
	addl	-28(%ebp), %eax
	movl	%eax, -32(%ebp)
	movl	-36(%ebp), %eax
	subl	$1, %eax
	addl	%eax, %eax
	addl	-20(%ebp), %eax
	cmpl	-24(%ebp), %eax
	jbe	.L72
.L11:
	cmpl	$15, -12(%ebp)
	je	.L73
.L18:
	movl	-12(%ebp), %eax
	movzbl	yypact(%eax), %eax
	movsbl	%al,%eax
	movl	%eax, -40(%ebp)
	cmpl	$-5, -40(%ebp)
	je	.L74
.L20:
	movl	yychar, %eax
	cmpl	$-2, %eax
	jne	.L22
	call	yylex
	movl	%eax, yychar
.L22:
	movl	yychar, %eax
	testl	%eax, %eax
	jg	.L23
	movl	$0, -48(%ebp)
	movl	-48(%ebp), %eax
	movl	%eax, yychar
	jmp	.L24
.L23:
	movl	yychar, %eax
	cmpl	$264, %eax
	ja	.L25
	movl	yychar, %eax
	movzbl	yytranslate(%eax), %eax
	movzbl	%al, %eax
	jmp	.L26
.L25:
	movl	$2, %eax
.L26:
	movl	%eax, -48(%ebp)
.L24:
	movl	-48(%ebp), %eax
	addl	%eax, -40(%ebp)
	cmpl	$0, -40(%ebp)
	js	.L21
	cmpl	$45, -40(%ebp)
	jg	.L21
	movl	-40(%ebp), %eax
	movzbl	yycheck(%eax), %eax
	movsbl	%al,%eax
	cmpl	-48(%ebp), %eax
	jne	.L21
	movl	-40(%ebp), %eax
	movzbl	yytable(%eax), %eax
	movzbl	%al, %eax
	movl	%eax, -40(%ebp)
	cmpl	$0, -40(%ebp)
	jg	.L27
	cmpl	$0, -40(%ebp)
	je	.L28
	cmpl	$-1, -40(%ebp)
	je	.L28
	negl	-40(%ebp)
	jmp	.L29
.L27:
	cmpl	$0, -16(%ebp)
	je	.L30
	subl	$1, -16(%ebp)
.L30:
	movl	$-2, yychar
	movl	-40(%ebp), %eax
	movl	%eax, -12(%ebp)
	addl	$8, -32(%ebp)
	movl	-32(%ebp), %ecx
	movl	yylval, %eax
	movl	yylval+4, %edx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	jmp	.L10
.L74:
	nop
.L21:
	movl	-12(%ebp), %eax
	movzbl	yydefact(%eax), %eax
	movzbl	%al, %eax
	movl	%eax, -40(%ebp)
	cmpl	$0, -40(%ebp)
	je	.L75
.L29:
	movl	-40(%ebp), %eax
	movzbl	yyr2(%eax), %eax
	movzbl	%al, %eax
	movl	%eax, -52(%ebp)
	movl	$1, %eax
	subl	-52(%ebp), %eax
	sall	$3, %eax
	addl	-32(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	%eax, -80(%ebp)
	movl	%edx, -76(%ebp)
	cmpl	$21, -40(%ebp)
	ja	.L31
	movl	-40(%ebp), %eax
	sall	$2, %eax
	movl	.L52(%eax), %eax
	jmp	*%eax
	.section	.rodata
	.align 4
	.align 4
.L52:
	.long	.L31
	.long	.L31
	.long	.L32
	.long	.L33
	.long	.L34
	.long	.L35
	.long	.L36
	.long	.L37
	.long	.L38
	.long	.L39
	.long	.L40
	.long	.L41
	.long	.L42
	.long	.L43
	.long	.L44
	.long	.L45
	.long	.L46
	.long	.L47
	.long	.L48
	.long	.L49
	.long	.L50
	.long	.L51
	.text
.L32:
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, final_policy
	jmp	.L31
.L33:
	movl	-32(%ebp), %eax
	movl	(%eax), %ecx
	movl	4(%eax), %ebx
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	%ecx, 8(%esp)
	movl	%ebx, 12(%esp)
	movl	%eax, (%esp)
	movl	%edx, 4(%esp)
	call	expint
	movl	%eax, -80(%ebp)
	jmp	.L31
.L34:
	movl	-32(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	%eax, (%esp)
	movl	%edx, 4(%esp)
	call	flexint
	movl	%eax, -80(%ebp)
	jmp	.L31
.L35:
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	leaf_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L36:
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %eax
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	movl	$1, (%esp)
	call	kof2_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L37:
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %eax
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	movl	$2, (%esp)
	call	kof2_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L38:
	movl	-32(%ebp), %eax
	subl	$8, %eax
	movl	(%eax), %ecx
	movl	-32(%ebp), %eax
	subl	$32, %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	%ecx, 4(%esp)
	movl	%eax, (%esp)
	call	kof_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L39:
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	eq_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L40:
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	lt_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L41:
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	gt_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L42:
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	le_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L43:
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	ge_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L44:
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	eq_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L45:
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	gt_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L46:
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	lt_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L47:
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	ge_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L48:
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	le_policy
	movl	%eax, -80(%ebp)
	jmp	.L31
.L49:
	movl	-32(%ebp), %eax
	subl	$8, %eax
	movl	(%eax), %eax
	movl	%eax, -80(%ebp)
	jmp	.L31
.L50:
	call	g_ptr_array_new
	movl	%eax, -80(%ebp)
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-80(%ebp), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_add
	jmp	.L31
.L51:
	movl	-32(%ebp), %eax
	subl	$16, %eax
	movl	(%eax), %eax
	movl	%eax, -80(%ebp)
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-80(%ebp), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_add
.L31:
	movl	-52(%ebp), %eax
	sall	$3, %eax
	negl	%eax
	addl	%eax, -32(%ebp)
	movl	-52(%ebp), %eax
	addl	%eax, %eax
	negl	%eax
	addl	%eax, -24(%ebp)
	movl	$0, -52(%ebp)
	addl	$8, -32(%ebp)
	movl	-32(%ebp), %ecx
	movl	-80(%ebp), %eax
	movl	-76(%ebp), %edx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	movl	-40(%ebp), %eax
	movzbl	yyr1(%eax), %eax
	movzbl	%al, %eax
	movl	%eax, -40(%ebp)
	movl	-40(%ebp), %eax
	subl	$17, %eax
	movzbl	yypgoto(%eax), %eax
	movsbl	%al,%edx
	movl	-24(%ebp), %eax
	movzwl	(%eax), %eax
	cwtl
	leal	(%edx,%eax), %eax
	movl	%eax, -12(%ebp)
	cmpl	$0, -12(%ebp)
	js	.L53
	cmpl	$45, -12(%ebp)
	jg	.L53
	movl	-12(%ebp), %eax
	movzbl	yycheck(%eax), %eax
	movsbw	%al,%dx
	movl	-24(%ebp), %eax
	movzwl	(%eax), %eax
	cmpw	%ax, %dx
	jne	.L53
	movl	-12(%ebp), %eax
	movzbl	yytable(%eax), %eax
	movzbl	%al, %eax
	movl	%eax, -12(%ebp)
	nop
	jmp	.L10
.L53:
	movl	-40(%ebp), %eax
	subl	$17, %eax
	movzbl	yydefgoto(%eax), %eax
	movsbl	%al,%eax
	movl	%eax, -12(%ebp)
	jmp	.L10
.L75:
	nop
.L28:
	cmpl	$0, -16(%ebp)
	jne	.L55
	movl	yynerrs, %eax
	addl	$1, %eax
	movl	%eax, yynerrs
	movl	$.LC1, (%esp)
	call	yyerror
.L55:
	cmpl	$3, -16(%ebp)
	jne	.L76
	movl	yychar, %eax
	testl	%eax, %eax
	jg	.L57
	movl	yychar, %eax
	testl	%eax, %eax
	jne	.L77
	jmp	.L17
.L57:
	movl	$yylval, 8(%esp)
	movl	-48(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC2, (%esp)
	call	yydestruct
	movl	$-2, yychar
	jmp	.L59
.L76:
	nop
	jmp	.L59
.L77:
	nop
.L59:
	movl	$3, -16(%ebp)
.L62:
	movl	-12(%ebp), %eax
	movzbl	yypact(%eax), %eax
	movsbl	%al,%eax
	movl	%eax, -40(%ebp)
	cmpl	$-5, -40(%ebp)
	je	.L60
	addl	$1, -40(%ebp)
	cmpl	$0, -40(%ebp)
	js	.L60
	cmpl	$45, -40(%ebp)
	jg	.L60
	movl	-40(%ebp), %eax
	movzbl	yycheck(%eax), %eax
	cmpb	$1, %al
	jne	.L60
	movl	-40(%ebp), %eax
	movzbl	yytable(%eax), %eax
	movzbl	%al, %eax
	movl	%eax, -40(%ebp)
	cmpl	$0, -40(%ebp)
	jle	.L60
	addl	$8, -32(%ebp)
	movl	-32(%ebp), %ecx
	movl	yylval, %eax
	movl	yylval+4, %edx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	movl	-40(%ebp), %eax
	movl	%eax, -12(%ebp)
	jmp	.L10
.L60:
	movl	-24(%ebp), %eax
	cmpl	-20(%ebp), %eax
	je	.L78
.L61:
	movl	-12(%ebp), %eax
	movzbl	yystos(%eax), %eax
	movzbl	%al, %eax
	movl	-32(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	movl	$.LC3, (%esp)
	call	yydestruct
	subl	$8, -32(%ebp)
	subl	$2, -24(%ebp)
	movl	-24(%ebp), %eax
	movzwl	(%eax), %eax
	cwtl
	movl	%eax, -12(%ebp)
	jmp	.L62
.L73:
	nop
.L69:
.L19:
	movl	$0, -44(%ebp)
	jmp	.L63
.L72:
	nop
	jmp	.L17
.L78:
	nop
.L17:
	movl	$1, -44(%ebp)
	jmp	.L63
.L70:
	nop
	jmp	.L13
.L71:
	nop
.L13:
	movl	$.LC4, (%esp)
	call	yyerror
	movl	$2, -44(%ebp)
.L63:
	movl	yychar, %eax
	cmpl	$-2, %eax
	je	.L64
	movl	$yylval, 8(%esp)
	movl	-48(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC5, (%esp)
	call	yydestruct
.L64:
	movl	-52(%ebp), %eax
	sall	$3, %eax
	negl	%eax
	addl	%eax, -32(%ebp)
	movl	-52(%ebp), %eax
	addl	%eax, %eax
	negl	%eax
	addl	%eax, -24(%ebp)
	jmp	.L65
.L66:
	movl	-24(%ebp), %eax
	movzwl	(%eax), %eax
	cwtl
	movzbl	yystos(%eax), %eax
	movzbl	%al, %eax
	movl	-32(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	movl	$.LC6, (%esp)
	call	yydestruct
	subl	$8, -32(%ebp)
	subl	$2, -24(%ebp)
.L65:
	movl	-24(%ebp), %eax
	cmpl	-20(%ebp), %eax
	jne	.L66
	leal	-480(%ebp), %eax
	cmpl	%eax, -20(%ebp)
	je	.L67
	movl	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	free
.L67:
	movl	-44(%ebp), %eax
	addl	$2100, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	yyparse, .-yyparse
	.section	.rodata
	.align 4
.LC7:
	.string	"error parsing policy: zero-length integer \"%llub%llu\"\n"
	.align 4
.LC8:
	.string	"error parsing policy: no more than 64 bits allowed \"%llub%llu\"\n"
	.text
.globl expint
	.type	expint, @function
expint:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$72, %esp
	movl	8(%ebp), %eax
	movl	%eax, -32(%ebp)
	movl	12(%ebp), %eax
	movl	%eax, -28(%ebp)
	movl	16(%ebp), %eax
	movl	%eax, -40(%ebp)
	movl	20(%ebp), %eax
	movl	%eax, -36(%ebp)
	movl	-40(%ebp), %eax
	movl	-36(%ebp), %edx
	orl	%edx, %eax
	testl	%eax, %eax
	jne	.L80
	movl	-40(%ebp), %eax
	movl	-36(%ebp), %edx
	movl	%eax, 12(%esp)
	movl	%edx, 16(%esp)
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	%eax, 4(%esp)
	movl	%edx, 8(%esp)
	movl	$.LC7, (%esp)
	call	die
	jmp	.L81
.L80:
	cmpl	$0, -36(%ebp)
	jb	.L81
	cmpl	$0, -36(%ebp)
	ja	.L84
	cmpl	$64, -40(%ebp)
	jbe	.L81
.L84:
	movl	-40(%ebp), %eax
	movl	-36(%ebp), %edx
	movl	%eax, 12(%esp)
	movl	%edx, 16(%esp)
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	%eax, 4(%esp)
	movl	%edx, 8(%esp)
	movl	$.LC8, (%esp)
	call	die
.L81:
	movl	$12, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %ecx
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	movl	-40(%ebp), %edx
	movl	-12(%ebp), %eax
	movl	%edx, 8(%eax)
	movl	-12(%ebp), %eax
	leave
	ret
	.size	expint, .-expint
.globl flexint
	.type	flexint, @function
flexint:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	8(%ebp), %eax
	movl	%eax, -32(%ebp)
	movl	12(%ebp), %eax
	movl	%eax, -28(%ebp)
	movl	$12, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %ecx
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	movl	-12(%ebp), %eax
	movl	$0, 8(%eax)
	movl	-12(%ebp), %eax
	leave
	ret
	.size	flexint, .-flexint
.globl policy_free
	.type	policy_free, @function
policy_free:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	je	.L88
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	movl	%eax, (%esp)
	call	free
.L88:
	movl	$0, -12(%ebp)
	jmp	.L89
.L90:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	policy_free
	addl	$1, -12(%ebp)
.L89:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L90
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_free
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	policy_free, .-policy_free
.globl leaf_policy
	.type	leaf_policy, @function
leaf_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$12, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	$1, (%eax)
	movl	-12(%ebp), %eax
	movl	8(%ebp), %edx
	movl	%edx, 4(%eax)
	call	g_ptr_array_new
	movl	-12(%ebp), %edx
	movl	%eax, 8(%edx)
	movl	-12(%ebp), %eax
	leave
	ret
	.size	leaf_policy, .-leaf_policy
.globl kof2_policy
	.type	kof2_policy, @function
kof2_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$12, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	8(%ebp), %edx
	movl	%edx, (%eax)
	movl	-12(%ebp), %eax
	movl	$0, 4(%eax)
	call	g_ptr_array_new
	movl	-12(%ebp), %edx
	movl	%eax, 8(%edx)
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_add
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	16(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_add
	movl	-12(%ebp), %eax
	leave
	ret
	.size	kof2_policy, .-kof2_policy
	.section	.rodata
	.align 4
.LC9:
	.string	"error parsing policy: trivially satisfied operator \"%dof\"\n"
	.align 4
.LC10:
	.string	"error parsing policy: unsatisfiable operator \"%dof\" (only %d operands)\n"
	.align 4
.LC11:
	.string	"error parsing policy: identity operator \"%dof\" (only one operand)\n"
	.text
.globl kof_policy
	.type	kof_policy, @function
kof_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	cmpl	$0, 8(%ebp)
	jg	.L97
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC9, (%esp)
	call	die
	jmp	.L98
.L97:
	movl	8(%ebp), %edx
	movl	12(%ebp), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jbe	.L99
	movl	12(%ebp), %eax
	movl	4(%eax), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC10, (%esp)
	call	die
	jmp	.L98
.L99:
	movl	12(%ebp), %eax
	movl	4(%eax), %eax
	cmpl	$1, %eax
	jne	.L98
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC11, (%esp)
	call	die
.L98:
	movl	$12, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	8(%ebp), %edx
	movl	%edx, (%eax)
	movl	-12(%ebp), %eax
	movl	$0, 4(%eax)
	movl	-12(%ebp), %eax
	movl	12(%ebp), %edx
	movl	%edx, 8(%eax)
	movl	-12(%ebp), %eax
	leave
	ret
	.size	kof_policy, .-kof_policy
.globl bit_marker
	.type	bit_marker, @function
bit_marker:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$72, %esp
	movl	20(%ebp), %eax
	movb	%al, -28(%ebp)
	movl	$63, %eax
	subl	16(%ebp), %eax
	movl	$120, 4(%esp)
	movl	%eax, (%esp)
	call	g_strnfill
	movl	%eax, -12(%ebp)
	movl	16(%ebp), %eax
	movl	$120, 4(%esp)
	movl	%eax, (%esp)
	call	g_strnfill
	movl	%eax, -16(%ebp)
	cmpb	$0, -28(%ebp)
	setne	%al
	movzbl	%al, %eax
	movl	-16(%ebp), %edx
	movl	%edx, 16(%esp)
	movl	%eax, 12(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	g_strdup_printf
	movl	%eax, -20(%ebp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	movl	-20(%ebp), %eax
	leave
	ret
	.size	bit_marker, .-bit_marker
	.section	.rodata
.LC12:
	.string	"%s_flexint_%llu"
.LC13:
	.string	"%s_expint%02d_%llu"
	.text
.globl eq_policy
	.type	eq_policy, @function
eq_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	testl	%eax, %eax
	jne	.L104
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	%eax, 8(%esp)
	movl	%edx, 12(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC12, (%esp)
	call	g_strdup_printf
	movl	%eax, (%esp)
	call	leaf_policy
	jmp	.L105
.L104:
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	8(%ebp), %ecx
	movl	8(%ecx), %ecx
	movl	%eax, 12(%esp)
	movl	%edx, 16(%esp)
	movl	%ecx, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC13, (%esp)
	call	g_strdup_printf
	movl	%eax, (%esp)
	call	leaf_policy
.L105:
	leave
	ret
	.size	eq_policy, .-eq_policy
.globl bit_marker_list
	.type	bit_marker_list, @function
bit_marker_list:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$52, %esp
	movl	24(%ebp), %eax
	movl	%eax, -32(%ebp)
	movl	28(%ebp), %eax
	movl	%eax, -28(%ebp)
	movl	$0, -16(%ebp)
	jmp	.L108
.L111:
	addl	$1, -16(%ebp)
.L108:
	cmpl	$0, 8(%ebp)
	je	.L109
	movl	-16(%ebp), %ecx
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	shrdl	%edx, %eax
	shrl	%cl, %edx
	testb	$32, %cl
	je	.L124
	movl	%edx, %eax
	xorl	%edx, %edx
.L124:
	andl	$1, %eax
	jmp	.L110
.L109:
	movl	-16(%ebp), %ecx
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	shrdl	%edx, %eax
	shrl	%cl, %edx
	testb	$32, %cl
	je	.L123
	movl	%edx, %eax
	xorl	%edx, %edx
.L123:
	andl	$1, %eax
	testl	%eax, %eax
	sete	%al
.L110:
	testb	%al, %al
	jne	.L111
	movl	8(%ebp), %eax
	movsbl	%al,%eax
	movl	%eax, 12(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	bit_marker
	movl	%eax, (%esp)
	call	leaf_policy
	movl	%eax, -12(%ebp)
	addl	$1, -16(%ebp)
	jmp	.L112
.L119:
	cmpl	$0, 8(%ebp)
	je	.L113
	movl	8(%ebp), %eax
	movsbl	%al,%eax
	movl	%eax, 12(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	bit_marker
	movl	%eax, (%esp)
	call	leaf_policy
	movl	%eax, %ebx
	movl	-16(%ebp), %ecx
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	shrdl	%edx, %eax
	shrl	%cl, %edx
	testb	$32, %cl
	je	.L122
	movl	%edx, %eax
	xorl	%edx, %edx
.L122:
	andl	$1, %eax
	testb	%al, %al
	je	.L114
	movl	$2, %eax
	jmp	.L115
.L114:
	movl	$1, %eax
.L115:
	movl	%ebx, 8(%esp)
	movl	-12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	kof2_policy
	movl	%eax, -12(%ebp)
	jmp	.L116
.L113:
	movl	8(%ebp), %eax
	movsbl	%al,%eax
	movl	%eax, 12(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	bit_marker
	movl	%eax, (%esp)
	call	leaf_policy
	movl	%eax, %ebx
	movl	-16(%ebp), %ecx
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	shrdl	%edx, %eax
	shrl	%cl, %edx
	testb	$32, %cl
	je	.L121
	movl	%edx, %eax
	xorl	%edx, %edx
.L121:
	andl	$1, %eax
	testb	%al, %al
	je	.L117
	movl	$1, %eax
	jmp	.L118
.L117:
	movl	$2, %eax
.L118:
	movl	%ebx, 8(%esp)
	movl	-12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	kof2_policy
	movl	%eax, -12(%ebp)
.L116:
	addl	$1, -16(%ebp)
.L112:
	movl	-16(%ebp), %eax
	cmpl	20(%ebp), %eax
	jl	.L119
	movl	-12(%ebp), %eax
	addl	$52, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	bit_marker_list, .-bit_marker_list
	.section	.rodata
.LC14:
	.string	"%s_ge_2^%02d"
.LC15:
	.string	"%s_lt_2^%02d"
	.text
.globl flexint_leader
	.type	flexint_leader, @function
flexint_leader:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	16(%ebp), %eax
	movl	%eax, -32(%ebp)
	movl	20(%ebp), %eax
	movl	%eax, -28(%ebp)
	movl	$12, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	$0, 4(%eax)
	call	g_ptr_array_new
	movl	-12(%ebp), %edx
	movl	%eax, 8(%edx)
	movl	$2, -16(%ebp)
	jmp	.L126
.L134:
	cmpl	$0, 8(%ebp)
	je	.L127
	movl	-16(%ebp), %ecx
	movl	$1, %eax
	movl	$0, %edx
	shldl	%eax, %edx
	sall	%cl, %eax
	testb	$32, %cl
	je	.L141
	movl	%eax, %edx
	xorl	%eax, %eax
.L141:
	cmpl	-28(%ebp), %edx
	ja	.L128
	cmpl	-28(%ebp), %edx
	jb	.L127
	cmpl	-32(%ebp), %eax
	ja	.L128
.L127:
	cmpl	$0, 8(%ebp)
	jne	.L130
	movl	-16(%ebp), %ecx
	movl	$1, %eax
	movl	$0, %edx
	shldl	%eax, %edx
	sall	%cl, %eax
	testb	$32, %cl
	je	.L140
	movl	%eax, %edx
	xorl	%eax, %eax
.L140:
	cmpl	-28(%ebp), %edx
	jb	.L130
	cmpl	-28(%ebp), %edx
	ja	.L128
	cmpl	-32(%ebp), %eax
	jb	.L130
.L128:
	cmpl	$0, 8(%ebp)
	je	.L132
	movl	$.LC14, %eax
	jmp	.L133
.L132:
	movl	$.LC15, %eax
.L133:
	movl	-16(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_strdup_printf
	movl	%eax, (%esp)
	call	leaf_policy
	movl	-12(%ebp), %edx
	movl	8(%edx), %edx
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	g_ptr_array_add
.L130:
	sall	-16(%ebp)
.L126:
	cmpl	$32, -16(%ebp)
	jle	.L134
	cmpl	$0, 8(%ebp)
	jne	.L135
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	jmp	.L136
.L135:
	movl	$1, %eax
.L136:
	movl	-12(%ebp), %edx
	movl	%eax, (%edx)
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L137
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	policy_free
	movl	$0, -12(%ebp)
	jmp	.L138
.L137:
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	$1, %eax
	jne	.L138
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	$0, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_remove_index
	movl	%eax, -20(%ebp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	policy_free
	movl	-20(%ebp), %eax
	movl	%eax, -12(%ebp)
.L138:
	movl	-12(%ebp), %eax
	leave
	ret
	.size	flexint_leader, .-flexint_leader
	.section	.rodata
	.align 4
.LC16:
	.string	"error parsing policy: unsatisfiable integer comparison %s > %llu\n(%d-bits are insufficient to satisfy)\n"
	.align 4
.LC17:
	.string	"error parsing policy: unsatisfiable integer comparison %s < 0\n(all numerical attributes are unsigned)\n"
	.align 4
.LC18:
	.string	"error parsing policy: trivially satisfied integer comparison %s < %llu\n(any %d-bit number will satisfy)\n"
.LC19:
	.string	"%%s_expint%02d_%%s%%d%%s"
.LC20:
	.string	"%s_flexint_%s%d%s"
	.text
.globl cmp_policy
	.type	cmp_policy, @function
cmp_policy:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%ebx
	subl	$48, %esp
	cmpl	$0, 12(%ebp)
	je	.L143
	movl	8(%ebp), %eax
	movl	(%eax), %ebx
	movl	4(%eax), %esi
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	testl	%eax, %eax
	je	.L144
	movl	8(%ebp), %eax
	movl	8(%eax), %ecx
	movl	$1, %eax
	movl	$0, %edx
	shldl	%eax, %edx
	sall	%cl, %eax
	testb	$32, %cl
	je	.L185
	movl	%eax, %edx
	xorl	%eax, %eax
.L185:
	addl	$-1, %eax
	adcl	$-1, %edx
	jmp	.L145
.L144:
	movl	$-1, %eax
	movl	$-1, %edx
.L145:
	cmpl	%edx, %esi
	jb	.L143
	cmpl	%edx, %esi
	ja	.L178
	cmpl	%eax, %ebx
	jb	.L143
.L178:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	testl	%eax, %eax
	je	.L147
	movl	8(%ebp), %eax
	movl	8(%eax), %ecx
	jmp	.L148
.L147:
	movl	$64, %ecx
.L148:
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	%ecx, 16(%esp)
	movl	%eax, 8(%esp)
	movl	%edx, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC16, (%esp)
	call	die
	jmp	.L149
.L143:
	cmpl	$0, 12(%ebp)
	jne	.L150
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	orl	%edx, %eax
	testl	%eax, %eax
	jne	.L150
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC17, (%esp)
	call	die
	jmp	.L149
.L150:
	cmpl	$0, 12(%ebp)
	jne	.L149
	movl	8(%ebp), %eax
	movl	(%eax), %ebx
	movl	4(%eax), %esi
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	testl	%eax, %eax
	je	.L151
	movl	8(%ebp), %eax
	movl	8(%eax), %ecx
	movl	$1, %eax
	movl	$0, %edx
	shldl	%eax, %edx
	sall	%cl, %eax
	testb	$32, %cl
	je	.L184
	movl	%eax, %edx
	xorl	%eax, %eax
.L184:
	addl	$-1, %eax
	adcl	$-1, %edx
	jmp	.L152
.L151:
	movl	$-1, %eax
	movl	$-1, %edx
.L152:
	cmpl	%edx, %esi
	jb	.L149
	cmpl	%edx, %esi
	ja	.L179
	cmpl	%eax, %ebx
	jbe	.L149
.L179:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	testl	%eax, %eax
	je	.L154
	movl	8(%ebp), %eax
	movl	8(%eax), %ecx
	jmp	.L155
.L154:
	movl	$64, %ecx
.L155:
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	%ecx, 16(%esp)
	movl	%eax, 8(%esp)
	movl	%edx, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC18, (%esp)
	call	die
.L149:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	testl	%eax, %eax
	je	.L156
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	%eax, 4(%esp)
	movl	$.LC19, (%esp)
	call	g_strdup_printf
	jmp	.L157
.L156:
	movl	$.LC20, (%esp)
	call	strdup
.L157:
	movl	%eax, -16(%ebp)
	movl	8(%ebp), %eax
	movl	(%eax), %ecx
	movl	4(%eax), %ebx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	testl	%eax, %eax
	je	.L158
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	jmp	.L159
.L158:
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	cmpl	$0, %edx
	ja	.L160
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	cmpl	$0, %edx
	ja	.L161
	cmpl	$0, %edx
	jb	.L180
	cmpl	$65535, %eax
	ja	.L161
.L180:
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	cmpl	$0, %edx
	ja	.L163
	cmpl	$0, %edx
	jb	.L181
	cmpl	$255, %eax
	ja	.L163
.L181:
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	cmpl	$0, %edx
	ja	.L165
	cmpl	$0, %edx
	jb	.L182
	cmpl	$15, %eax
	ja	.L165
.L182:
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	cmpl	$0, %edx
	jb	.L167
	cmpl	$0, %edx
	ja	.L183
	cmpl	$3, %eax
	jbe	.L167
.L183:
	movl	$4, %eax
	jmp	.L169
.L167:
	movl	$2, %eax
.L169:
	jmp	.L170
.L165:
	movl	$8, %eax
.L170:
	jmp	.L171
.L163:
	movl	$16, %eax
.L171:
	jmp	.L172
.L161:
	movl	$32, %eax
.L172:
	jmp	.L173
.L160:
	movl	$64, %eax
.L173:
.L159:
	movl	%ecx, 16(%esp)
	movl	%ebx, 20(%esp)
	movl	%eax, 12(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	bit_marker_list
	movl	%eax, -12(%ebp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	testl	%eax, %eax
	jne	.L174
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	movl	%eax, 8(%esp)
	movl	%edx, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	flexint_leader
	movl	%eax, -20(%ebp)
	cmpl	$0, -20(%ebp)
	je	.L174
	cmpl	$0, 12(%ebp)
	je	.L175
	movl	$1, %eax
	jmp	.L176
.L175:
	movl	$2, %eax
.L176:
	movl	-12(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	-20(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	kof2_policy
	movl	%eax, -12(%ebp)
.L174:
	movl	-12(%ebp), %eax
	addl	$48, %esp
	popl	%ebx
	popl	%esi
	popl	%ebp
	ret
	.size	cmp_policy, .-cmp_policy
.globl lt_policy
	.type	lt_policy, @function
lt_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$0, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	cmp_policy
	leave
	ret
	.size	lt_policy, .-lt_policy
.globl gt_policy
	.type	gt_policy, @function
gt_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$1, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	cmp_policy
	leave
	ret
	.size	gt_policy, .-gt_policy
.globl le_policy
	.type	le_policy, @function
le_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	addl	$1, %eax
	adcl	$0, %edx
	movl	8(%ebp), %ecx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	movl	12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$0, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	cmp_policy
	leave
	ret
	.size	le_policy, .-le_policy
.globl ge_policy
	.type	ge_policy, @function
ge_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	4(%eax), %edx
	movl	(%eax), %eax
	addl	$-1, %eax
	adcl	$-1, %edx
	movl	8(%ebp), %ecx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	movl	12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$1, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	cmp_policy
	leave
	ret
	.size	ge_policy, .-ge_policy
.globl cur_string
	.bss
	.align 4
	.type	cur_string, @object
	.size	cur_string, 4
cur_string:
	.zero	4
	.section	.rodata
.LC21:
	.string	"(),=#"
.LC22:
	.string	"<>"
.LC23:
	.string	""
.LC24:
	.string	"%llu"
.LC25:
	.string	"and"
.LC26:
	.string	"or"
.LC27:
	.string	"of"
.LC28:
	.string	"syntax error at \"%c%s\"\n"
	.text
.globl yylex
	.type	yylex, @function
yylex:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
.L197:
	call	__ctype_b_loc
	movl	(%eax), %ecx
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L195
	movl	cur_string, %edx
	movzbl	(%edx), %eax
	movsbl	%al,%eax
	addl	$1, %edx
	movl	%edx, cur_string
	jmp	.L196
.L195:
	movl	$-1, %eax
.L196:
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	addl	%eax, %eax
	leal	(%ecx,%eax), %eax
	movzwl	(%eax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L197
	movl	$0, -16(%ebp)
	cmpl	$-1, -12(%ebp)
	jne	.L198
	movl	$0, -16(%ebp)
	jmp	.L199
.L198:
	cmpl	$38, -12(%ebp)
	jne	.L200
	movl	$261, -16(%ebp)
	jmp	.L199
.L200:
	cmpl	$124, -12(%ebp)
	jne	.L201
	movl	$260, -16(%ebp)
	jmp	.L199
.L201:
	movl	-12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC21, (%esp)
	call	strchr
	testl	%eax, %eax
	jne	.L202
	movl	-12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC22, (%esp)
	call	strchr
	testl	%eax, %eax
	je	.L203
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L202
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	cmpb	$61, %al
	je	.L203
.L202:
	movl	-12(%ebp), %eax
	movl	%eax, -16(%ebp)
	jmp	.L199
.L203:
	cmpl	$60, -12(%ebp)
	jne	.L204
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L204
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	cmpb	$61, %al
	jne	.L204
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L206
	movl	cur_string, %eax
	addl	$1, %eax
	movl	%eax, cur_string
.L206:
	movl	$263, -16(%ebp)
	jmp	.L199
.L204:
	cmpl	$62, -12(%ebp)
	jne	.L207
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L207
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	cmpb	$61, %al
	jne	.L207
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L209
	movl	cur_string, %eax
	addl	$1, %eax
	movl	%eax, cur_string
.L209:
	movl	$264, -16(%ebp)
	jmp	.L199
.L207:
	call	__ctype_b_loc
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	addl	%edx, %edx
	addl	%edx, %eax
	movzwl	(%eax), %eax
	movzwl	%ax, %eax
	andl	$2048, %eax
	testl	%eax, %eax
	je	.L210
	movl	$.LC23, (%esp)
	call	g_string_new
	movl	%eax, -20(%ebp)
	movl	-12(%ebp), %eax
	movsbl	%al,%eax
	movl	%eax, 4(%esp)
	movl	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_append_c_inline
	jmp	.L211
.L216:
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L212
	movl	cur_string, %edx
	movzbl	(%edx), %eax
	movsbl	%al,%eax
	addl	$1, %edx
	movl	%edx, cur_string
	jmp	.L213
.L212:
	movl	$-1, %eax
.L213:
	movl	%eax, 4(%esp)
	movl	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_append_c_inline
.L211:
	call	__ctype_b_loc
	movl	(%eax), %edx
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L214
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	movsbl	%al,%eax
	addl	%eax, %eax
	jmp	.L215
.L214:
	movl	$-2, %eax
.L215:
	leal	(%edx,%eax), %eax
	movzwl	(%eax), %eax
	movzwl	%ax, %eax
	andl	$2048, %eax
	testl	%eax, %eax
	jne	.L216
	movl	$.LC24, %edx
	movl	-20(%ebp), %eax
	movl	(%eax), %eax
	movl	$yylval, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	__isoc99_sscanf
	movl	$1, 4(%esp)
	movl	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_free
	movl	$259, -16(%ebp)
	jmp	.L199
.L210:
	call	__ctype_b_loc
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	addl	%edx, %edx
	addl	%edx, %eax
	movzwl	(%eax), %eax
	movzwl	%ax, %eax
	andl	$1024, %eax
	testl	%eax, %eax
	je	.L217
	movl	$.LC23, (%esp)
	call	g_string_new
	movl	%eax, -24(%ebp)
	movl	-12(%ebp), %eax
	movsbl	%al,%eax
	movl	%eax, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_append_c_inline
	jmp	.L218
.L223:
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L219
	movl	cur_string, %edx
	movzbl	(%edx), %eax
	movsbl	%al,%eax
	addl	$1, %edx
	movl	%edx, cur_string
	jmp	.L220
.L219:
	movl	$-1, %eax
.L220:
	movl	%eax, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_append_c_inline
.L218:
	call	__ctype_b_loc
	movl	(%eax), %edx
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L221
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	movsbl	%al,%eax
	addl	%eax, %eax
	jmp	.L222
.L221:
	movl	$-2, %eax
.L222:
	leal	(%edx,%eax), %eax
	movzwl	(%eax), %eax
	movzwl	%ax, %eax
	andl	$8, %eax
	testl	%eax, %eax
	jne	.L223
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L224
	movl	cur_string, %eax
	movzbl	(%eax), %eax
	cmpb	$95, %al
	je	.L223
.L224:
	movl	-24(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC25, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L225
	movl	$1, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_free
	movl	$261, -16(%ebp)
	jmp	.L199
.L225:
	movl	-24(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC26, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L227
	movl	$1, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_free
	movl	$260, -16(%ebp)
	jmp	.L199
.L227:
	movl	-24(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC27, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L228
	movl	$1, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_free
	movl	$262, -16(%ebp)
	jmp	.L199
.L228:
	movl	-24(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, yylval
	movl	$0, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_free
	movl	$258, -16(%ebp)
	jmp	.L199
.L217:
	movl	cur_string, %eax
	movl	%eax, 8(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC28, (%esp)
	call	die
.L199:
	movl	-16(%ebp), %eax
	leave
	ret
	.size	yylex, .-yylex
	.section	.rodata
.LC29:
	.string	"error parsing policy: %s\n"
	.text
.globl yyerror
	.type	yyerror, @function
yyerror:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC29, (%esp)
	call	die
	leave
	ret
	.size	yyerror, .-yyerror
.globl merge_child
	.type	merge_child, @function
merge_child:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	%eax, -16(%ebp)
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jne	.L233
	movl	8(%ebp), %eax
	movl	(%eax), %edx
	movl	-16(%ebp), %eax
	movl	(%eax), %eax
	addl	%eax, %edx
	movl	8(%ebp), %eax
	movl	%edx, (%eax)
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	-1(%eax), %edx
	movl	8(%ebp), %eax
	movl	%edx, (%eax)
.L233:
	movl	12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_remove_index_fast
	movl	$0, -12(%ebp)
	jmp	.L234
.L235:
	movl	-16(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_add
	addl	$1, -12(%ebp)
.L234:
	movl	-12(%ebp), %edx
	movl	-16(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L235
	movl	-16(%ebp), %eax
	movl	8(%eax), %eax
	movl	$0, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_free
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	merge_child, .-merge_child
.globl simplify
	.type	simplify, @function
simplify:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$0, -12(%ebp)
	jmp	.L238
.L239:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	simplify
	addl	$1, -12(%ebp)
.L238:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L239
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	cmpl	$1, %eax
	jne	.L240
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	je	.L240
	movl	$0, -12(%ebp)
	jmp	.L241
.L243:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	(%eax), %eax
	cmpl	$1, %eax
	jne	.L242
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	je	.L242
	movl	-12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	merge_child
.L242:
	addl	$1, -12(%ebp)
.L241:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L243
.L240:
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jne	.L248
	movl	$0, -12(%ebp)
	jmp	.L245
.L247:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	sall	$2, %ecx
	addl	%ecx, %eax
	movl	(%eax), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jne	.L246
	movl	-12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	merge_child
.L246:
	addl	$1, -12(%ebp)
.L245:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L247
.L248:
	leave
	ret
	.size	simplify, .-simplify
.globl cmp_tidy
	.type	cmp_tidy, @function
cmp_tidy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -12(%ebp)
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -16(%ebp)
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	je	.L250
	movl	-16(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L250
	movl	$-1, %eax
	jmp	.L251
.L250:
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L252
	movl	-16(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	je	.L252
	movl	$1, %eax
	jmp	.L251
.L252:
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L253
	movl	-16(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L253
	movl	-16(%ebp), %eax
	movl	4(%eax), %edx
	movl	-12(%ebp), %eax
	movl	4(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	jmp	.L251
.L253:
	movl	$0, %eax
.L251:
	leave
	ret
	.size	cmp_tidy, .-cmp_tidy
.globl tidy
	.type	tidy, @function
tidy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$0, -12(%ebp)
	jmp	.L256
.L257:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	tidy
	addl	$1, -12(%ebp)
.L256:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L257
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	je	.L259
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	$cmp_tidy, 12(%esp)
	movl	$4, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	qsort
.L259:
	leave
	ret
	.size	tidy, .-tidy
	.section	.rodata
.LC30:
	.string	" "
.LC31:
	.string	"%s %dof%d"
	.text
.globl format_policy_postfix
	.type	format_policy_postfix, @function
format_policy_postfix:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L261
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	movl	%eax, (%esp)
	call	strdup
	jmp	.L262
.L261:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	format_policy_postfix
	movl	%eax, -16(%ebp)
	movl	$1, -12(%ebp)
	jmp	.L263
.L264:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	format_policy_postfix
	movl	%eax, -20(%ebp)
	movl	$0, 12(%esp)
	movl	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC30, (%esp)
	call	g_strjoin
	movl	%eax, -24(%ebp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	movl	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	movl	-24(%ebp), %eax
	movl	%eax, -16(%ebp)
	addl	$1, -12(%ebp)
.L263:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L264
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 12(%esp)
	movl	%eax, 8(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC31, (%esp)
	call	g_strdup_printf
	movl	%eax, -24(%ebp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	movl	-24(%ebp), %eax
.L262:
	leave
	ret
	.size	format_policy_postfix, .-format_policy_postfix
.globl actual_bits
	.type	actual_bits, @function
actual_bits:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	%eax, -24(%ebp)
	movl	12(%ebp), %eax
	movl	%eax, -20(%ebp)
	movl	$32, -4(%ebp)
	jmp	.L267
.L271:
	movl	-4(%ebp), %ecx
	movl	$1, %eax
	movl	$0, %edx
	shldl	%eax, %edx
	sall	%cl, %eax
	testb	$32, %cl
	je	.L274
	movl	%eax, %edx
	xorl	%eax, %eax
.L274:
	cmpl	-20(%ebp), %edx
	ja	.L268
	cmpl	-20(%ebp), %edx
	jb	.L273
	cmpl	-24(%ebp), %eax
	ja	.L268
.L273:
	movl	-4(%ebp), %eax
	addl	%eax, %eax
	jmp	.L270
.L268:
	movl	-4(%ebp), %eax
	movl	%eax, %edx
	shrl	$31, %edx
	leal	(%edx,%eax), %eax
	sarl	%eax
	movl	%eax, -4(%ebp)
.L267:
	cmpl	$0, -4(%ebp)
	jg	.L271
	movl	$1, %eax
.L270:
	leave
	ret
	.size	actual_bits, .-actual_bits
	.section	.rodata
.LC32:
	.string	" %s = %llu # %u "
	.align 4
.LC33:
	.string	"error parsing attribute \"%s\": 64 bits is the maximum allowed\n"
	.align 4
.LC34:
	.string	"error parsing attribute \"%s\": value %llu too big for %d bits\n"
.LC35:
	.string	" %s = %llu "
	.align 4
.LC36:
	.string	"error parsing attribute \"%s\"\n(note that numerical attributes are unsigned integers)\n"
	.text
.globl parse_attribute
	.type	parse_attribute, @function
parse_attribute:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%ebx
	subl	$96, %esp
	movl	$61, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	strchr
	testl	%eax, %eax
	jne	.L276
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_slist_append
	movl	8(%ebp), %edx
	movl	%eax, (%edx)
	jmp	.L293
.L276:
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	strlen
	movl	%eax, (%esp)
	call	malloc
	movl	%eax, -16(%ebp)
	movl	$.LC32, %edx
	movl	12(%ebp), %eax
	leal	-24(%ebp), %ecx
	movl	%ecx, 16(%esp)
	leal	-32(%ebp), %ecx
	movl	%ecx, 12(%esp)
	movl	-16(%ebp), %ecx
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	__isoc99_sscanf
	cmpl	$3, %eax
	jne	.L278
	movl	-24(%ebp), %eax
	cmpl	$64, %eax
	jle	.L279
	movl	-24(%ebp), %ecx
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	%ecx, 16(%esp)
	movl	%eax, 8(%esp)
	movl	%edx, 12(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC33, (%esp)
	call	die
.L279:
	movl	-24(%ebp), %esi
	movl	$1, -64(%ebp)
	movl	$0, -60(%ebp)
	movl	-64(%ebp), %eax
	movl	-60(%ebp), %edx
	movl	%esi, %ecx
	shldl	%eax, %edx
	sall	%cl, %eax
	testb	$32, %cl
	je	.L299
	movl	%eax, %edx
	xorl	%eax, %eax
.L299:
	movl	%eax, -48(%ebp)
	movl	%edx, -44(%ebp)
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	cmpl	%edx, -44(%ebp)
	ja	.L280
	cmpl	%edx, -44(%ebp)
	jb	.L294
	cmpl	%eax, -48(%ebp)
	ja	.L280
.L294:
	movl	-24(%ebp), %ecx
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	%ecx, 16(%esp)
	movl	%eax, 8(%esp)
	movl	%edx, 12(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC34, (%esp)
	call	die
.L280:
	movl	-24(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC19, (%esp)
	call	g_strdup_printf
	movl	%eax, -20(%ebp)
	movl	$0, -12(%ebp)
	jmp	.L282
.L283:
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	-12(%ebp), %ecx
	shrdl	%edx, %eax
	shrl	%cl, %edx
	testb	$32, %cl
	je	.L298
	movl	%edx, %eax
	xorl	%edx, %edx
.L298:
	movsbl	%al,%eax
	andl	$1, %eax
	movl	%eax, 12(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	-20(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	bit_marker
	movl	8(%ebp), %edx
	movl	(%edx), %edx
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	g_slist_append
	movl	8(%ebp), %edx
	movl	%eax, (%edx)
	addl	$1, -12(%ebp)
.L282:
	movl	-24(%ebp), %eax
	cmpl	%eax, -12(%ebp)
	jl	.L283
	movl	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	-24(%ebp), %ecx
	movl	%eax, 12(%esp)
	movl	%edx, 16(%esp)
	movl	%ecx, 8(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC13, (%esp)
	call	g_strdup_printf
	movl	%eax, %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_slist_append
	movl	8(%ebp), %edx
	movl	%eax, (%edx)
	jmp	.L284
.L278:
	movl	$.LC35, %edx
	movl	12(%ebp), %eax
	leal	-32(%ebp), %ecx
	movl	%ecx, 12(%esp)
	movl	-16(%ebp), %ecx
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	__isoc99_sscanf
	cmpl	$2, %eax
	jne	.L285
	movl	$2, -12(%ebp)
	jmp	.L286
.L290:
	movl	-12(%ebp), %esi
	movl	$1, -64(%ebp)
	movl	$0, -60(%ebp)
	movl	-64(%ebp), %eax
	movl	-60(%ebp), %edx
	movl	%esi, %ecx
	shldl	%eax, %edx
	sall	%cl, %eax
	testb	$32, %cl
	je	.L297
	movl	%eax, %edx
	xorl	%eax, %eax
.L297:
	movl	%eax, -48(%ebp)
	movl	%edx, -44(%ebp)
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	cmpl	%edx, -44(%ebp)
	jb	.L287
	cmpl	%edx, -44(%ebp)
	ja	.L295
	cmpl	%eax, -48(%ebp)
	jbe	.L287
.L295:
	movl	$.LC15, %eax
	jmp	.L289
.L287:
	movl	$.LC14, %eax
.L289:
	movl	-12(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	-16(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_strdup_printf
	movl	%eax, %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_slist_append
	movl	8(%ebp), %edx
	movl	%eax, (%edx)
	sall	-12(%ebp)
.L286:
	cmpl	$32, -12(%ebp)
	jle	.L290
	movl	$0, -12(%ebp)
	jmp	.L291
.L292:
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	-12(%ebp), %ecx
	shrdl	%edx, %eax
	shrl	%cl, %edx
	testb	$32, %cl
	je	.L296
	movl	%edx, %eax
	xorl	%edx, %edx
.L296:
	movsbl	%al,%eax
	andl	$1, %eax
	movl	%eax, 12(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$.LC20, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	bit_marker
	movl	8(%ebp), %edx
	movl	(%edx), %edx
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	g_slist_append
	movl	8(%ebp), %edx
	movl	%eax, (%edx)
	addl	$1, -12(%ebp)
.L291:
	cmpl	$63, -12(%ebp)
	jle	.L292
	movl	-32(%ebp), %eax
	movl	-28(%ebp), %edx
	movl	%eax, 8(%esp)
	movl	%edx, 12(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC12, (%esp)
	call	g_strdup_printf
	movl	%eax, %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_slist_append
	movl	8(%ebp), %edx
	movl	%eax, (%edx)
	jmp	.L284
.L285:
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC36, (%esp)
	call	die
.L284:
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
.L293:
	addl	$96, %esp
	popl	%ebx
	popl	%esi
	popl	%ebp
	ret
	.size	parse_attribute, .-parse_attribute
.globl parse_policy_lang
	.type	parse_policy_lang, @function
parse_policy_lang:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	%eax, cur_string
	call	yyparse
	movl	final_policy, %eax
	movl	%eax, (%esp)
	call	simplify
	movl	final_policy, %eax
	movl	%eax, (%esp)
	call	tidy
	movl	final_policy, %eax
	movl	%eax, (%esp)
	call	format_policy_postfix
	movl	%eax, -12(%ebp)
	movl	final_policy, %eax
	movl	%eax, (%esp)
	call	policy_free
	movl	-12(%ebp), %eax
	leave
	ret
	.size	parse_policy_lang, .-parse_policy_lang
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
