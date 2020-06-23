.text
main:
	li   $a0, 2
	li   $t1, 1
	and  $a0, $t1
	jal  print_int 		; 0
	li   $a0, 17
	andi $a0, 4097
	jal  print_int 		; 1
	li   $a0, 2
	li   $t1, 2
	or   $a0, $t1
	jal  print_int 		; 2
	li   $a0, 2
	ori  $a0, 3
	jal print_int 		; 3
	li   $a0, 6
	li   $t1, 2
	xor  $a0, $t1
	jal  print_int 		; 4
	li   $a0, 20
	xori $a0, 17
	jal print_int 		; 5
	jreturn

