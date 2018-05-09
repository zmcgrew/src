/*	$NetBSD: umprintf.c,v 1.5 2001/09/24 13:22:33 wiz Exp $	*/

/*-
 * Copyright (c) 1986, 1988, 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      hacked out from ..
 *  pc532/umprintf.c
 *      which was hacked out from ..
 *	@(#)subr_prf.c	7.30 (Berkeley) 6/29/91
 */

#include <riscv/sbi.h>
#include <riscv/umprintf.h>
#include <sys/stdarg.h>

void pOK(void);
void pOK(void) {
  static int OK = 0;
  ++OK;
  char pOK[] = "OK X\n";

  /* Change X to # */
  pOK[3] = '0' + OK;

  for (int i = 0; i < 5; ++i) {
    sbi_console_putchar(pOK[i]);
  }
  
};

static char *ksprintn __P((unsigned long num, int base, int *len));
void umprintf(const char *fmt, ...);

void
umprintf(const char *fmt, ...)
{
	va_list ap;
	char *p;
	int tmp;
	int base;
	unsigned long ul;
	char ch;

	va_start(ap,fmt);

	for (;;) {
		while ((ch = *fmt++) != '%') {
			if (ch == '\0') {
				va_end(ap);
				return;
			}
      sbi_console_putchar(ch);
		}
		ch = *fmt++;
		switch (ch) {
		case 'd':
			ul = va_arg(ap, unsigned long);
			base = 10;
			goto number;
		case 'x':
			ul = va_arg(ap, unsigned long);
			base = 16;
number:			p = ksprintn(ul, base, &tmp);
			while ((ch = *p--))
        sbi_console_putchar(ch);
			break;
		default:
      sbi_console_putchar(ch);
		}
	}
	va_end(ap);
}

/*
 * Put a number (base <= 16) in a buffer in reverse order; return an
 * optional length and a pointer to the NULL terminated (preceded?)
 * buffer.
 */
static char *
ksprintn(unsigned long ul, int base, int *lenp)
{
	static char buf[32]; /* 32 seems big enough? */
	register char *p;
	int d;

	p = buf;
	*p='\0';
	do {
		d = ul % base;
		if (d < 10)
			*++p = '0' + d;
		else
			*++p = 'a' + d - 10;
	} while ((ul /= base));
	if (lenp)
		*lenp = p - buf;
	return (p);
}

#define PADDR(var) \
  do { \
  umprintf("&"#var": 0x%x\n", &(var)); \
  } while (0);

#define PVALX(var) \
  do { \
  umprintf(#var"= 0x%x\n", (var)); \
  } while (0);

#define PVALD(var) \
  do { \
  umprintf(#var"= %d\n", (var)); \
  } while (0);

void print_msg(void) {
  const char *msg = "Hello RISC-V world!\n";
  /* umprintf("The address of msg is 0x%x\n", &msg); //PC = 0x0000000080200758 */
  PADDR(msg);

  PVALX(msg);

  PVALD(msg);
}
