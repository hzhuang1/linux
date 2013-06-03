/*
 * linux/arch/arm/mach-mmp/time.c
 *
 *   Support for clocksource and clockevents
 *
 * Copyright (C) 2008 Marvell International Ltd.
 * All rights reserved.
 *
 *   2008-04-11: Jason Chagas <Jason.chagas@marvell.com>
 *   2008-10-08: Bin Yang <bin.yang@marvell.com>
 *
 * The timers module actually includes three timers, each timer with up to
 * three match comparators. Timer #0 is used here in free-running mode as
 * the clock source, and match comparator #1 used as clock event device.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/clk-provider.h>
#include <linux/clockchips.h>

#include <linux/io.h>
#include <linux/irq.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <asm/sched_clock.h>
#include <asm/mach/time.h>

#define TMR_CCR		(0x0000)
#define TMR_TN_MM(n, m)	(0x0004 + ((n) << 3) + (((n) + (m)) << 2))
#define TMR_CR(n)	(0x0028 + ((n) << 2))
#define TMR_SR(n)	(0x0034 + ((n) << 2))
#define TMR_IER(n)	(0x0040 + ((n) << 2))
#define TMR_PLVR(n)	(0x004c + ((n) << 2))
#define TMR_PLCR(n)	(0x0058 + ((n) << 2))
#define TMR_WMER	(0x0064)
#define TMR_WMR		(0x0068)
#define TMR_WVR		(0x006c)
#define TMR_WSR		(0x0070)
#define TMR_ICR(n)	(0x0074 + ((n) << 2))
#define TMR_WICR	(0x0080)
#define TMR_CER		(0x0084)
#define TMR_CMR		(0x0088)
#define TMR_ILR(n)	(0x008c + ((n) << 2))
#define TMR_WCR		(0x0098)
#define TMR_WFAR	(0x009c)
#define TMR_WSAR	(0x00A0)
#define TMR_CVWR(n)	(0x00A4 + ((n) << 2))

#define TMR_CCR_CS_0(x)	(((x) & 0x3) << 0)
#define TMR_CCR_CS_1(x)	(((x) & 0x7) << 2)
#define TMR_CCR_CS_2(x)	(((x) & 0x3) << 5)

#define TIMERS1_PHY_BASE	(0xd4000000 + 0x14000)
#define TIMERS2_PHY_BASE	(0xd4000000 + 0x16000)

#define TIMERS_PHY_BASE		TIMERS1_PHY_BASE

#define MAX_DELTA		(0xfffffffe)
#define MIN_DELTA		(16)

static void __iomem *mmp_timer_base;

/*
 * FIXME: the timer needs some delay to stablize the counter capture
 */
static inline uint32_t timer_read(void)
{
	int delay = 100;

	__raw_writel(1, mmp_timer_base + TMR_CVWR(1));

	while (delay--)
		cpu_relax();

	return __raw_readl(mmp_timer_base + TMR_CVWR(1));
}

static u32 notrace mmp_read_sched_clock(void)
{
	return timer_read();
}

static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	struct clock_event_device *c = dev_id;

	/*
	 * Clear pending interrupt status.
	 */
	__raw_writel(0x01, mmp_timer_base + TMR_ICR(0));

	/*
	 * Disable timer 0.
	 */
	__raw_writel(0x02, mmp_timer_base + TMR_CER);

	c->event_handler(c);

	return IRQ_HANDLED;
}

static int timer_set_next_event(unsigned long delta,
				struct clock_event_device *dev)
{
	unsigned long flags;

	local_irq_save(flags);

	/*
	 * Disable timer 0.
	 */
	__raw_writel(0x02, mmp_timer_base + TMR_CER);

	/*
	 * Clear and enable timer match 0 interrupt.
	 */
	__raw_writel(0x01, mmp_timer_base + TMR_ICR(0));
	__raw_writel(0x01, mmp_timer_base + TMR_IER(0));

	/*
	 * Setup new clockevent timer value.
	 */
	__raw_writel(delta - 1, mmp_timer_base + TMR_TN_MM(0, 0));

	/*
	 * Enable timer 0.
	 */
	__raw_writel(0x03, mmp_timer_base + TMR_CER);

	local_irq_restore(flags);

	return 0;
}

static void timer_set_mode(enum clock_event_mode mode,
			   struct clock_event_device *dev)
{
	unsigned long flags;

	local_irq_save(flags);
	switch (mode) {
	case CLOCK_EVT_MODE_ONESHOT:
	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
		/* disable the matching interrupt */
		__raw_writel(0x00, mmp_timer_base + TMR_IER(0));
		break;
	case CLOCK_EVT_MODE_RESUME:
	case CLOCK_EVT_MODE_PERIODIC:
		break;
	}
	local_irq_restore(flags);
}

static struct clock_event_device ckevt = {
	.name		= "clockevent",
	.features	= CLOCK_EVT_FEAT_ONESHOT,
	.rating		= 200,
	.set_next_event	= timer_set_next_event,
	.set_mode	= timer_set_mode,
};

static cycle_t clksrc_read(struct clocksource *cs)
{
	return timer_read();
}

static struct clocksource cksrc = {
	.name		= "clocksource",
	.rating		= 200,
	.read		= clksrc_read,
	.mask		= CLOCKSOURCE_MASK(32),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

static void __init timer_init_clk(int mmp2_mode)
{
	uint32_t ccr = __raw_readl(mmp_timer_base + TMR_CCR);

	__raw_writel(0x0, mmp_timer_base + TMR_CER); /* disable */

	ccr &= mmp2_mode ? (TMR_CCR_CS_0(0) | TMR_CCR_CS_1(0)) :
		(TMR_CCR_CS_0(3) | TMR_CCR_CS_1(3));
	__raw_writel(ccr, mmp_timer_base + TMR_CCR);
}

static void __init timer_config(void)
{
	/* set timer 0 to periodic mode, and timer 1 to free-running mode */
	__raw_writel(0x2, mmp_timer_base + TMR_CMR);

	__raw_writel(0x1, mmp_timer_base + TMR_PLCR(0)); /* periodic */
	__raw_writel(0x7, mmp_timer_base + TMR_ICR(0));  /* clear status */
	__raw_writel(0x0, mmp_timer_base + TMR_IER(0));

	__raw_writel(0x0, mmp_timer_base + TMR_PLCR(1)); /* free-running */
	__raw_writel(0x7, mmp_timer_base + TMR_ICR(1));  /* clear status */
	__raw_writel(0x0, mmp_timer_base + TMR_IER(1));

	/* enable timer 1 counter */
	__raw_writel(0x2, mmp_timer_base + TMR_CER);
}

static struct irqaction timer_irq = {
	.name		= "timer",
	.flags		= IRQF_DISABLED | IRQF_TIMER | IRQF_IRQPOLL,
	.handler	= timer_interrupt,
	.dev_id		= &ckevt,
};

void __init timer_init(int irq, int mmp2_mode)
{
	mmp_timer_base = ioremap(TIMERS_PHY_BASE, PAGE_SIZE);
	BUG_ON(!mmp_timer_base);

	timer_init_clk(mmp2_mode);
	timer_config();

	setup_sched_clock(mmp_read_sched_clock, 32, CLOCK_TICK_RATE);

	ckevt.cpumask = cpumask_of(0);

	setup_irq(irq, &timer_irq);

	clocksource_register_hz(&cksrc, CLOCK_TICK_RATE);
	clockevents_config_and_register(&ckevt, CLOCK_TICK_RATE,
					MIN_DELTA, MAX_DELTA);
}

static void __init mmp_dt_init_timer(struct device_node *np)
{
	struct clk *clk;
	int irq;
	u32 rate = 0;

	if (!of_device_is_available(np))
		return;
	if (of_property_read_u32(np, "clock-frequency", &rate)) {
		pr_err("failed to find clock-frequency property\n");
		return;
	}
	irq = irq_of_parse_and_map(np, 0);
	if (!irq)
		return;
	clk = of_clk_get(np, 0);
	if (IS_ERR(clk)) {
		pr_err("failed to get timer clock\n");
		return;
	}
	mmp_timer_base = of_iomap(np, 0);
	if (!mmp_timer_base)
		goto out;

	__raw_writel(0x0, mmp_timer_base + TMR_CER); /* disable */
	if (rate)
		clk_set_rate(clk, rate);
	clk_prepare_enable(clk);
	timer_config();

	setup_sched_clock(mmp_read_sched_clock, 32, rate);

	ckevt.cpumask = cpumask_of(0);

	setup_irq(irq, &timer_irq);

	clocksource_register_hz(&cksrc, rate);
	clockevents_config_and_register(&ckevt, rate,
					MIN_DELTA, MAX_DELTA);
	return;
out:
	clk_put(clk);
}
CLOCKSOURCE_OF_DECLARE(mmp_timer, "mrvl,mmp-timer", mmp_dt_init_timer);
