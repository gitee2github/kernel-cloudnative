/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/export.h>

#define FIXUP_LDST(x, y)	\
	x, y

	.globl memcpy
	.ent memcpy
memcpy:
	.frame $30, 0, $26, 0
	.prologue 0
	mov	$16, $0
#include "deep-copy_template.S"
$out:
	ret
	.end memcpy
	EXPORT_SYMBOL(memcpy)
__memcpy = memcpy
.globl __memcpy
