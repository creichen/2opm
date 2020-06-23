.text
main:
	li $t1, 1
	la $t0, modme
	li $t1, 42
	sb $t1, 2($t0)

modme:	li $a0, 1
	jal print_int
	jreturn

.data
root:
.word
	left, right, 0
left:	0, 0, -5
right:	0, 0, 2
