#ifndef _RISCV_UMPRINTF_H_
#define _RISCV_UMPRINTF_H_

void umprintf(const char *fmt, ...);

void print_msg(void);

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

#endif /* _RISCV_UMPRINTF_H_ */
