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

#ifndef _A2OPM_ERRORS_H
#define _A2OPM_ERRORS_H

// error messages linked to some input file's line numbers

extern int error_line_nr;
extern int errors_nr;
extern int warnings_nr;

void
error(const char *fmt, ...);

void
warn(const char *fmt, ...);

void
fail(char *msg) __attribute__ ((noreturn));

#endif // !defined(_A2OPM_ERRORS_H)
