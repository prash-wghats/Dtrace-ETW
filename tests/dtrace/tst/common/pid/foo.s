	.file	"foø.c"
	.section .rdata,"dr"
LC0:
	.ascii "in foø\0"
	.text
	.globl	_foø
	.def	_foø;	.scl	2;	.type	32;	.endef
_foø:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	$LC0, (%esp)
	call	_puts
	nop
	leave
	ret
	.def	___main;	.scl	2;	.type	32;	.endef
	.globl	_main
	.def	_main;	.scl	2;	.type	32;	.endef
_main:
	pushl	%ebp
	movl	%esp, %ebp
	andl	$-16, %esp
	call	___main
	call	_foø
	nop
	leave
	ret
	.ident	"GCC: (tdm64-1) 5.1.0"
	.def	_puts;	.scl	2;	.type	32;	.endef
