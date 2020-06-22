/***************************************************************************
  Copyright (C) 2014 Christoph Reichenbach


 This program may be modified and copied freely according to the terms of
 the GNU general public license (GPL), as long as the above copyright
 notice and the licensing information contained herein are preserved.

 Please refer to www.gnu.org for licensing details.

 This work is provided AS IS, without warranty of any kind, expressed or
 implied, including but not limited to the warranties of merchantability,
 noninfringement, and fitness for a specific purpose. The author will not
 be held liable for any damage caused by this work or derivatives of it.

 By using this source code, you agree to the licensing terms as stated
 above.


 Please contact the maintainer for bug reports or inquiries.

 Current Maintainer:

    Christoph Reichenbach (CR) <creichen@gmail.com>

***************************************************************************/

#ifndef _A2OPM_REGISTERS_H
#define _A2OPM_REGISTERS_H

#define REGISTERS_NR 16

// Special registers
#define REGISTER_V0 0 // Return value
#define REGISTER_SP 4
#define REGISTER_FP 5
#define REGISTER_GP 15

#define REGISTERS_TEMP_NR		2	// Caller-saved (not including args/special registers)
#define REGISTERS_CALLEE_SAVED_NR	4	// Callee-saved
#define REGISTERS_ARGUMENT_NR		6	// Arguments

// Kuerzel zum bequemen Zugriff
#define REGISTER_T0	10	// cf. registers_temp[0]
#define REGISTER_T1	11	// cf. registers_temp[1]
#define REGISTER_A0	7	// cf. registers_argument[0]
#define REGISTER_A1	6	// cf. registers_argument[1]
#define REGISTER_A2	2	// cf. registers_argument[2]
#define REGISTER_A3	1	// cf. registers_argument[3]

typedef struct {
	char *intel; // native intel name
	char *mips;  // 2OPM name
} regname_t;

extern regname_t register_names[REGISTERS_NR];
extern int registers_temp[REGISTERS_TEMP_NR];
extern int registers_callee_saved[REGISTERS_CALLEE_SAVED_NR];
extern int registers_argument[REGISTERS_ARGUMENT_NR];


#endif // !defined(_A2OPM_REGISTERS_H)
