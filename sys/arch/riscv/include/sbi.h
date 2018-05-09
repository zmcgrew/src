#ifndef _RISCV_SBI_H_
#define _RISCV_SBI_H_

#define SBI_SET_TIMER              0 /* TODO */
#define SBI_CONSOLE_PUTCHAR        1
#define SBI_CONSOLE_GETCHAR        2
#define SBI_CLEAR_IPI              3 /* TODO */
#define SBI_SEND_IPI               4 /* TODO */
#define SBI_REMOTE_FENCE_I         5 /* TODO */
#define SBI_REMOTE_SFENCE_VMA      6 /* TODO */
#define SBI_REMOTE_SFENCE_VMA_ASID 7 /* TODO */
#define SBI_SHUTDOWN               8

#include <riscv/types.h>

static __inline __uint64_t
sbi_call(__uint64_t arg7, __uint64_t arg0, __uint64_t arg1, __uint64_t arg2) {
  /* a7 is the actual SBI_ID from above */
  register register_t a7 __asm ("a7") = (register_t)arg7;

  /* Max of 3 arguments -- Copy the args to their respective registers */
  register register_t a0 __asm ("a0") = (register_t)arg0;
  register register_t a1 __asm ("a1") = (register_t)arg1;
  register register_t a2 __asm ("a2") = (register_t)arg2;

  __asm __volatile (
                "ecall"
                : "+r" (a0)
                : "r" (a1), "r" (a2), "r" (a7)
                : "memory");
	return a0;
}

static __inline void
sbi_console_putchar(char c) {
	sbi_call(SBI_CONSOLE_PUTCHAR, c, 0, 0);
}

static __inline char
sbi_console_getchar(void) {
	return sbi_call(SBI_CONSOLE_GETCHAR, 0, 0, 0);
}

static __inline void
sbi_shutdown(void) {
	sbi_call(SBI_SHUTDOWN, 0, 0, 0);
}

#endif /* _RISCV_SBI_H_ */
