# $NetBSD: Makefile,v 1.4 2018/05/02 18:46:05 kamil Exp $

.include <bsd.own.mk>

TESTSDIR=	${TESTSBASE}/usr.bin/cc

TESTS_SH=	#
TESTS_SH+=	t_asan_double_free
TESTS_SH+=	t_asan_global_buffer_overflow
TESTS_SH+=	t_asan_heap_overflow
TESTS_SH+=	t_asan_off_by_one
TESTS_SH+=	t_asan_poison
TESTS_SH+=	t_asan_uaf
TESTS_SH+=	t_ubsan_int_add_overflow
TESTS_SH+=	t_ubsan_int_sub_overflow
TESTS_SH+=	t_ubsan_int_neg_overflow
TESTS_SH+=	t_ubsan_int_divzero
TESTS_SH+=	t_ubsan_vla_out_of_bounds
TESTS_SH+=	t_hello

.include <bsd.test.mk>
