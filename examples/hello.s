.text
main:
	la $a0, string
	jal print_string
	jreturn
.data
.asciiz
string:
	"Hello, World!"
