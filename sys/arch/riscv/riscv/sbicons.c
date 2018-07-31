#include <sys/param.h>
#include <sys/device.h>
#include <dev/cons.h>
#include <riscv/sbi.h>

static int sbicons_cngetc(dev_t dv);
static void sbicons_cnputc(dev_t dv, int c);
void consinit(void);

static struct consdev sbiconsdev = {
	.cn_putc = sbicons_cnputc,
	.cn_getc = sbicons_cngetc,
	.cn_pollc = nullcnpollc,
};

static int
sbicons_cngetc(dev_t dv)
{
	return sbi_console_getchar();
}

static void
sbicons_cnputc(dev_t dv, int c)
{
	sbi_console_putchar(c);
}

void
consinit(void)
{
	cn_tab = &sbiconsdev;
}
