.text
main:
	la	$a0, intro
	jal	print_string
	jal	read_int
	;; back up user selection
	la	$a0, storage
	sd	$v0, 0($a0)
	la	$a0, thanks
	jal	print_string
	;; restore user selection
	la	$a0, storage
	ld	$v0, 0($a0)
	la	$t0, option
	slli	$v0, 3
	add	$t0, $v0
	ld	$t1, 0($t0)
	jr	$t1

a:
	la $a0, t
	jal print_string
	jreturn
b:
	li $a0, 1
	jal print_int
c:
	li $a0, 2
	jal print_int
	jreturn

.data
storage:
.word 0
option:
.word a, b, c
.asciiz
t:	"Hello"
intro:	"Enter 0, 1, or 2"
thanks:	"Thank you! Processing..."
