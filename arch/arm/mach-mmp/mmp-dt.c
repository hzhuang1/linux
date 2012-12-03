/*
 *  linux/arch/arm/mach-mmp/mmp-dt.c
 *
 *  Copyright (C) 2012 Marvell Technology Group Ltd.
 *  Author: Haojian Zhuang <haojian.zhuang@marvell.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  publishhed by the Free Software Foundation.
 */

#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <asm/mach/arch.h>
#include <asm/mach/time.h>
#include <mach/irqs.h>

#include "common.h"

extern void __init mmp_dt_irq_init(void);
extern void __init mmp_dt_init_timer(void);

static struct sys_timer mmp_dt_timer = {
	.init	= mmp_dt_init_timer,
};

static void __init pxa168_dt_init(void)
{
	of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL);
}

static void __init pxa910_dt_init(void)
{
	of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL);
}

static const char *mmp_dt_board_compat[] __initdata = {
	"mrvl,pxa168-aspenite",
	"mrvl,pxa910-dkb",
	NULL,
};

DT_MACHINE_START(PXA168_DT, "Marvell PXA168 (Device Tree Support)")
	.map_io		= mmp_map_io,
	.init_irq	= mmp_dt_irq_init,
	.timer		= &mmp_dt_timer,
	.init_machine	= pxa168_dt_init,
	.dt_compat	= mmp_dt_board_compat,
MACHINE_END

DT_MACHINE_START(PXA910_DT, "Marvell PXA910 (Device Tree Support)")
	.map_io		= mmp_map_io,
	.init_irq	= mmp_dt_irq_init,
	.timer		= &mmp_dt_timer,
	.init_machine	= pxa910_dt_init,
	.dt_compat	= mmp_dt_board_compat,
MACHINE_END
