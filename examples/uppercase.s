.text
main:
	push $fp
	move $fp, $sp
	push $s0
	push $s1
	push $s2

	move $a0, $gp
	addi $a0, string
	move $t1, $a0
	li   $s0, 0x40
loop:	lb   $t0, 0($t1)
	beqz $t0, done_loop
	ble  $t0, $s0, skip
	andi $t0, 0x5f
skip:
	sb   $t0, 0($t1)
	addi $t1, 1
	j loop
done_loop:
	jal print_string	; output
	pop $s2
	pop $s1
	pop $s0
	pop $fp
	jreturn
.data
.asciiz
string:
	"Hello, World!"
