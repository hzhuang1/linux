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
#include <linux/irqchip.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/amba/pl061.h>

#include <asm/hardware/arm_timer.h>
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

static struct pl061_platform_data hi3620_gpio_pdata0 = {
	.gpio_base	= 0,
	.irq_base	= 160,
};

static struct pl061_platform_data hi3620_gpio_pdata1 = {
	.gpio_base	= 8,
	.irq_base	= 168,
};

static struct pl061_platform_data hi3620_gpio_pdata2 = {
	.gpio_base	= 16,
	.irq_base	= 176,
};

static struct pl061_platform_data hi3620_gpio_pdata3 = {
	.gpio_base	= 24,
	.irq_base	= 184,
};

static struct pl061_platform_data hi3620_gpio_pdata4 = {
	.gpio_base	= 32,
	.irq_base	= 192,
};

static struct pl061_platform_data hi3620_gpio_pdata5 = {
	.gpio_base	= 40,
	.irq_base	= 200,
};

static struct pl061_platform_data hi3620_gpio_pdata6 = {
	.gpio_base	= 48,
	.irq_base	= 208,
};

static struct pl061_platform_data hi3620_gpio_pdata7 = {
	.gpio_base	= 56,
	.irq_base	= 216,
};

static struct pl061_platform_data hi3620_gpio_pdata8 = {
	.gpio_base	= 64,
	.irq_base	= 224,
};

static struct pl061_platform_data hi3620_gpio_pdata9 = {
	.gpio_base	= 72,
	.irq_base	= 232,
};

static struct pl061_platform_data hi3620_gpio_pdata10 = {
	.gpio_base	= 80,
	.irq_base	= 240,
};

static struct pl061_platform_data hi3620_gpio_pdata11 = {
	.gpio_base	= 88,
	.irq_base	= 248,
};

static struct pl061_platform_data hi3620_gpio_pdata12 = {
	.gpio_base	= 96,
	.irq_base	= 256,
};

static struct pl061_platform_data hi3620_gpio_pdata13 = {
	.gpio_base	= 104,
	.irq_base	= 264,
};

static struct pl061_platform_data hi3620_gpio_pdata14 = {
	.gpio_base	= 112,
	.irq_base	= 272,
};

static struct pl061_platform_data hi3620_gpio_pdata15 = {
	.gpio_base	= 120,
	.irq_base	= 280,
};

static struct pl061_platform_data hi3620_gpio_pdata16 = {
	.gpio_base	= 128,
	.irq_base	= 288,
};

static struct pl061_platform_data hi3620_gpio_pdata17 = {
	.gpio_base	= 136,
	.irq_base	= 296,
};

static struct pl061_platform_data hi3620_gpio_pdata18 = {
	.gpio_base	= 144,
	.irq_base	= 304,
};

static struct pl061_platform_data hi3620_gpio_pdata19 = {
	.gpio_base	= 152,
	.irq_base	= 312,
};

static struct pl061_platform_data hi3620_gpio_pdata20 = {
	.gpio_base	= 160,
	.irq_base	= 320,
};

static struct pl061_platform_data hi3620_gpio_pdata21 = {
	.gpio_base	= 168,
	.irq_base	= 328,
};

static const struct of_dev_auxdata hi3620_auxdata_lookup[] __initconst = {
	OF_DEV_AUXDATA("arm,pl061", 0xfc806000, "fc806000.gpio",
		       &hi3620_gpio_pdata0),
	OF_DEV_AUXDATA("arm,pl061", 0xfc807000, "fc807000.gpio",
		       &hi3620_gpio_pdata1),
	OF_DEV_AUXDATA("arm,pl061", 0xfc808000, "fc808000.gpio",
		       &hi3620_gpio_pdata2),
	OF_DEV_AUXDATA("arm,pl061", 0xfc809000, "fc809000.gpio",
		       &hi3620_gpio_pdata3),
	OF_DEV_AUXDATA("arm,pl061", 0xfc80a000, "fc80a000.gpio",
		       &hi3620_gpio_pdata4),
	OF_DEV_AUXDATA("arm,pl061", 0xfc80b000, "fc80b000.gpio",
		       &hi3620_gpio_pdata5),
	OF_DEV_AUXDATA("arm,pl061", 0xfc80c000, "fc80c000.gpio",
		       &hi3620_gpio_pdata6),
	OF_DEV_AUXDATA("arm,pl061", 0xfc80d000, "fc80d000.gpio",
		       &hi3620_gpio_pdata7),
	OF_DEV_AUXDATA("arm,pl061", 0xfc80e000, "fc80e000.gpio",
		       &hi3620_gpio_pdata8),
	OF_DEV_AUXDATA("arm,pl061", 0xfc80f000, "fc80f000.gpio",
		       &hi3620_gpio_pdata9),
	OF_DEV_AUXDATA("arm,pl061", 0xfc810000, "fc810000.gpio",
		       &hi3620_gpio_pdata10),
	OF_DEV_AUXDATA("arm,pl061", 0xfc811000, "fc811000.gpio",
		       &hi3620_gpio_pdata11),
	OF_DEV_AUXDATA("arm,pl061", 0xfc812000, "fc812000.gpio",
		       &hi3620_gpio_pdata12),
	OF_DEV_AUXDATA("arm,pl061", 0xfc813000, "fc813000.gpio",
		       &hi3620_gpio_pdata13),
	OF_DEV_AUXDATA("arm,pl061", 0xfc814000, "fc814000.gpio",
		       &hi3620_gpio_pdata14),
	OF_DEV_AUXDATA("arm,pl061", 0xfc815000, "fc815000.gpio",
		       &hi3620_gpio_pdata15),
	OF_DEV_AUXDATA("arm,pl061", 0xfc816000, "fc816000.gpio",
		       &hi3620_gpio_pdata16),
	OF_DEV_AUXDATA("arm,pl061", 0xfc817000, "fc817000.gpio",
		       &hi3620_gpio_pdata17),
	OF_DEV_AUXDATA("arm,pl061", 0xfc818000, "fc818000.gpio",
		       &hi3620_gpio_pdata18),
	OF_DEV_AUXDATA("arm,pl061", 0xfc819000, "fc819000.gpio",
		       &hi3620_gpio_pdata19),
	OF_DEV_AUXDATA("arm,pl061", 0xfc81a000, "fc81a000.gpio",
		       &hi3620_gpio_pdata20),
	OF_DEV_AUXDATA("arm,pl061", 0xfc81b000, "fc81b000.gpio",
		       &hi3620_gpio_pdata21),
};

static void __init hs_init(void)
{
	of_platform_populate(NULL, of_default_bus_match_table,
			     hi3620_auxdata_lookup, NULL);
}

static const char *hs_compat[] __initdata = {
	"hisilicon,hi3620-hi4511",
	NULL,
};

DT_MACHINE_START(HS_DT, "Hisilicon Hi36xx/Hi37xx (Flattened Device Tree)")
	/* Maintainer: Haojian Zhuang <haojian.zhuang@linaro.org> */
	.map_io		= debug_ll_io_init,
	.init_irq	= irqchip_init,
	.init_time	= hs_timer_init,
	.init_machine	= hs_init,
	.dt_compat	= hs_compat,
MACHINE_END
