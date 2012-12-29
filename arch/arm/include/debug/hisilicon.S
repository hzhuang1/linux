/*
 * Early serial output macro for Hisilicon SoC
 *
 * Copyright (C) 2012-2013 Linaro Ltd.
 *
 * Haojian Zhuang <haojian.zhuang@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#define HI3620_UART0_PHYS_BASE	0xfcb00000
#define HI3620_UART0_VIRT_BASE	0xfeb00000

#if defined(CONFIG_DEBUG_HI3620_UART0)
		.macro	addruart,rp,rv,tmp
		ldr	\rp, =HI3620_UART0_PHYS_BASE
		ldr	\rv, =HI3620_UART0_VIRT_BASE
		.endm

#include <asm/hardware/debug-pl01x.S>

#endif
