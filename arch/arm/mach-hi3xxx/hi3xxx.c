/*
 * (Hisilicon's Hi36xx/Hi37xx SoC based) flattened device tree enabled machine
 *
 * Copyright (c) 2012-2013 Hisilicon Ltd.
 * Copyright (c) 2012-2013 Linaro Ltd.
 *
 * Author: Haojian Zhuang <haojian.zhuang@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/clk-provider.h>
#include <linux/clocksource.h>
#include <linux/irqchip.h>
#include <linux/of_platform.h>

#include <asm/mach/arch.h>
#include <asm/mach/map.h>

static void __init hi3xxx_timer_init(void)
{
	of_clk_init(NULL);
	clocksource_of_init();
}

static void __init hs_init(void)
{
	of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL);
}

static const char *hs_compat[] __initdata = {
	"hisilicon,hi3620-hi4511",
	NULL,
};

DT_MACHINE_START(HI3xxx, "Hisilicon Hi36xx/Hi37xx (Flattened Device Tree)")
	/* Maintainer: Haojian Zhuang <haojian.zhuang@linaro.org> */
	.map_io		= debug_ll_io_init,
	.init_irq	= irqchip_init,
	.init_time	= hi3xxx_timer_init,
	.init_machine	= hs_init,
	.dt_compat	= hs_compat,
MACHINE_END
