/*
 * (Hisilicon's Hi36xx/Hi37xx SoC based) flattened device tree enabled machine
 *
 * Copyright (c) 2012-2013 Linaro Ltd.
 *
 * Haojian Zhuang <haojian.zhuang@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/clk.h>
#include <linux/clkdev.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>

#include <asm/hardware/arm_timer.h>
#include <asm/hardware/gic.h>
#include <asm/hardware/timer-sp.h>
#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/time.h>

static struct of_device_id hs_timer_match[] __initdata = {
	{ .compatible = "arm,sp804", },
	{}
};

static struct clk_lookup sp804_lookup = {
	.dev_id	= "sp804",
	.clk	= NULL,
};

extern void __init hs_init_clocks(void);
static void __init hs_timer_init(void)
{
	struct device_node *node = NULL;
	void __iomem *base;
	int irq;

	hs_init_clocks();

	node = of_find_matching_node(NULL, hs_timer_match);
	WARN_ON(!node);
	if (!node) {
		pr_err("Failed to find sp804 timer\n");
		return;
	}
	base = of_iomap(node, 0);
	WARN_ON(!base);

	/* timer0 is used as clock event, and timer1 is clock source. */
	irq = irq_of_parse_and_map(node, 0);
	WARN_ON(!irq);

	sp804_lookup.clk = of_clk_get(node, 0);
	clkdev_add(&sp804_lookup);

	sp804_clocksource_and_sched_clock_init(base + TIMER_2_BASE, "timer1");
	sp804_clockevents_init(base, irq, "timer0");
}

static struct sys_timer hs_timer = {
	.init = hs_timer_init,
};

static struct of_device_id hs_irq_match[] __initdata = {
	{ .compatible = "arm,cortex-a9-gic", .data = gic_of_init, },
	{}
};

static void __init hs_irq_init(void)
{
	of_irq_init(hs_irq_match);
}

static void __init hs_init(void)
{
	of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL);
}

static const char *hs_compat[] __initdata = {
	"hisilicon,hi3620-hi4511",
	NULL,
};

DT_MACHINE_START(HS_DT, "Hisilicon Hi36xx/Hi37xx (Flattened Device Tree)")
	/* Maintainer: Haojian Zhuang <haojian.zhuang@linaro.org> */
	.map_io		= debug_ll_io_init,
	.init_irq	= hs_irq_init,
	.timer		= &hs_timer,
	.init_machine	= hs_init,
	.handle_irq	= gic_handle_irq,
	.dt_compat	= hs_compat,
MACHINE_END
