/*
 * Marvell MMP clock driver
 *
 * Copyright (c) 2012 Linaro Limited.
 *
 * Author: Haojian Zhuang <haojian.zhuang@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <linux/kernel.h>
#include <linux/clk-provider.h>
#include <linux/clkdev.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>

/* Common APB clock register bit definitions */
#define APBC_APBCLK	(1 << 0)  /* APB Bus Clock Enable */
#define APBC_FNCLK	(1 << 1)  /* Functional Clock Enable */
#define APBC_RST	(1 << 2)  /* Reset Generation */
#define APBC_POWER	(1 << 7)  /* Reset Generation */

#define APBC_NO_BUS_CTRL	BIT(0)
#define APBC_POWER_CTRL		BIT(1)

#define to_clk_apbc(hw) container_of(hw, struct clk_apbc, hw)
struct clk_apbc {
	struct clk_hw	hw;
	void __iomem	*reg;
	u8		shift;
	u8		width;
	u8		flags;
	u8		delay;
	spinlock_t	*lock;
};

struct mmp_clk {
	void __iomem *mpmu_base;
	void __iomem *apmu_base;
	void __iomem *apbc_base;
	void __iomem *apbcp_base;
};

static struct mmp_clk mmp_clk;

static DEFINE_SPINLOCK(mmp_clk_lock);

static int clk_apbc_prepare(struct clk_hw *hw)
{
	struct clk_apbc *apbc = to_clk_apbc(hw);
	unsigned int data;
	unsigned long flags = 0;

	/*
	 * It may share same register as MUX clock,
	 * and it will impact FNCLK enable. Spinlock is needed
	 */
	if (apbc->lock)
		spin_lock_irqsave(apbc->lock, flags);

	data = readl_relaxed(apbc->reg);
	if (apbc->flags & APBC_POWER_CTRL)
		data |= APBC_POWER;
	data |= APBC_FNCLK;
	writel_relaxed(data, apbc->reg);

	if (apbc->lock)
		spin_unlock_irqrestore(apbc->lock, flags);

	udelay(apbc->delay);

	if (apbc->lock)
		spin_lock_irqsave(apbc->lock, flags);

	data = readl_relaxed(apbc->reg);
	data |= APBC_APBCLK;
	writel_relaxed(data, apbc->reg);

	if (apbc->lock)
		spin_unlock_irqrestore(apbc->lock, flags);

	udelay(apbc->delay);

	if (!(apbc->flags & APBC_NO_BUS_CTRL)) {
		if (apbc->lock)
			spin_lock_irqsave(apbc->lock, flags);

		data = readl_relaxed(apbc->reg);
		data &= ~APBC_RST;
		writel_relaxed(data, apbc->reg);

		if (apbc->lock)
			spin_unlock_irqrestore(apbc->lock, flags);
	}

	return 0;
}

static void clk_apbc_unprepare(struct clk_hw *hw)
{
	struct clk_apbc *apbc = to_clk_apbc(hw);
	unsigned long data;
	unsigned long flags = 0;

	if (apbc->lock)
		spin_lock_irqsave(apbc->lock, flags);

	data = readl_relaxed(apbc->reg);
	if (apbc->flags & APBC_POWER_CTRL)
		data &= ~APBC_POWER;
	data &= ~APBC_FNCLK;
	writel_relaxed(data, apbc->reg);

	if (apbc->lock)
		spin_unlock_irqrestore(apbc->lock, flags);

	udelay(10);

	if (apbc->lock)
		spin_lock_irqsave(apbc->lock, flags);

	data = readl_relaxed(apbc->reg);
	data &= ~APBC_APBCLK;
	writel_relaxed(data, apbc->reg);

	if (apbc->lock)
		spin_unlock_irqrestore(apbc->lock, flags);
}

static u8 clk_apbc_get_parent(struct clk_hw *hw)
{
	struct clk_apbc *apbc = to_clk_apbc(hw);
	u32 val;

	val = readl_relaxed(apbc->reg) >> apbc->shift;
	val &= (1 << apbc->width) - 1;

	if (val >= __clk_get_num_parents(hw->clk))
		return -EINVAL;

	return val;
}

static int clk_apbc_set_parent(struct clk_hw *hw, u8 index)
{
	struct clk_apbc *apbc = to_clk_apbc(hw);
	u32 val;
	unsigned long flags = 0;

	if (apbc->lock)
		spin_lock_irqsave(apbc->lock, flags);

	val = readl_relaxed(apbc->reg);
	val &= ~(((1 << apbc->width) - 1) << apbc->shift);
	val |= index << apbc->shift;
	writel_relaxed(val, apbc->reg);

	if (apbc->lock)
		spin_unlock_irqrestore(apbc->lock, flags);

	return 0;
}
static struct clk_ops clk_apbc_ops = {
	.prepare = clk_apbc_prepare,
	.unprepare = clk_apbc_unprepare,
	.get_parent = clk_apbc_get_parent,
	.set_parent = clk_apbc_set_parent,
};

static struct clk *
mmp_clk_register_apbc(const char *name, const char **parent_names,
		      u8 num_parents, void __iomem *base, u8 shift,
		      u8 width, u8 delay, unsigned int apbc_flags,
		      spinlock_t *lock)
{
	struct clk_apbc *apbc;
	struct clk *clk;
	struct clk_init_data init;

	apbc = kzalloc(sizeof(*apbc), GFP_KERNEL);
	if (!apbc)
		return NULL;

	init.name = name;
	init.ops = &clk_apbc_ops;
	init.flags = CLK_SET_RATE_PARENT;
	init.parent_names = parent_names;
	init.num_parents = num_parents;

	apbc->reg = base;
	apbc->shift = shift;
	apbc->width = width;
	apbc->delay = delay;
	apbc->flags = apbc_flags;
	apbc->lock = lock;
	apbc->hw.init = &init;

	clk = clk_register(NULL, &apbc->hw);
	if (IS_ERR(clk))
		kfree(apbc);

	return clk;
}

static int __init mmp_parse_mux(struct device_node *np,
				const char **parent_names,
				u8 *num_parents,
				u32 *clk_sel)
{
	int i, cnt, ret;

	/* get the count of items in mux */
	for (i = 0, cnt = 0; ; i++, cnt++) {
		/* parent's #clock-cells property is always 0 */
		if (!of_parse_phandle(np, "clocks", i))
			break;
	}

	for (i = 0; ; i++) {
		if (!of_clk_get_parent_name(np, i))
			break;
	}
	*num_parents = i;
	if (!*num_parents)
		return -ENOENT;

	clk_sel = kzalloc(sizeof(u32 *) * *num_parents, GFP_KERNEL);
	if (!clk_sel)
		return -ENOMEM;
	ret = of_property_read_u32_array(np, "marvell,mmp-clk-sel", clk_sel, cnt);
	if (ret)
		goto err;
	return 0;
err:
	kfree(clk_sel);
	return ret;
}

static void __init mmp_apbc_setup(struct device_node *np)
{
	u32 data[2], delay, apbc_flags, *clk_sel;
	u8 shift, width, num_parents;
	void __iomem *reg;
	const char **parent_names;
	const char *clk_name;
	struct clk *clk;
	int i, ret;

	if (!mmp_clk.apbc_base)
		return;

	ret = mmp_parse_mux(np, parent_names, &num_parents, clk_sel);
	if (ret)
		return;

	if (of_property_read_string(np, "clock-names", &clk_name))
		return;

	if (of_property_read_u32_array(np, "marvell,mmp-clk-reg", &data[0], 2))
		return;
	/* If the delay property isn't defined, assmue it as 10us. */
	if (of_property_read_u32(np, "marvell,mmp-clk-delay", &delay))
		delay = 10;
	if (of_get_property(np, "marvell,mmp-apbc-power-ctl", NULL))
		apbc_flags |= APBC_POWER_CTRL;

	reg = mmp_clk.apbc_base + data[0];
	shift = ffs(data[1]) - 1;
	width = fls(data[1]) - ffs(data[1]) + 1;

	parent_names = kzalloc(sizeof(char *) * num_parents, GFP_KERNEL);
	if (!parent_names)
		return;

	for (i = 0; i < num_parents; i++)
		parent_names[i] = of_clk_get_parent_name(np, i);
	clk = mmp_clk_register_apbc(clk_name, parent_names, num_parents,
				reg, shift, width, delay, 0, &mmp_clk_lock);
	if (IS_ERR(clk)) {
		kfree(parent_names);
		return;
	}
	if (!of_property_read_string(np, "clock-names", &clk_name))
		clk_register_clkdev(clk, clk_name, NULL);
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
}

static void __init mmp_fixed_rate_setup(struct device_node *np)
{
	struct clk *clk;
	const char *clk_name, *parent_name;
	int rate;

	if (of_property_read_u32(np, "clock-frequency", &rate))
		return;

	if (of_property_read_string(np, "clock-output-names", &clk_name))
		return;

	/* this node has only one parent */
	parent_name = of_clk_get_parent_name(np, 0);
	if (!parent_name)
		return;

	clk = clk_register_fixed_rate(NULL, clk_name, parent_name, 0, rate);
	if (IS_ERR(clk))
		return;
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
}

static void __init mmp_fixed_factor_setup(struct device_node *np)
{
	struct clk *clk;
	const char *clk_name, *output_name, *parent_name;
	u32 data[2];

	if (of_property_read_u32_array(np, "marvell,mmp-fixed-factor",
				&data[0], 2))
		return;
	if (of_property_read_string(np, "clock-output-names", &output_name))
		return;

	/* this node has only one parent */
	parent_name = of_clk_get_parent_name(np, 0);
	if (!parent_name)
		return;

	clk = clk_register_fixed_factor(NULL, output_name, parent_name, 0,
			data[0], data[1]);
	if (IS_ERR(clk))
		return;
	if (!of_property_read_string(np, "clock-names", &clk_name))
		clk_register_clkdev(clk, clk_name, NULL);
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
}

static void __init mmp_mux_setup(struct device_node *np, void __iomem *reg,
				 u8 shift, u8 width)
{
	int i, cnt;
	u32 *clk_sel;
	u8 num_parents;
	const char *clk_name, *output_name, **parent_names;
	struct clk *clk;

	if (of_property_read_string(np, "clock-output-names", &output_name))
		return;
	/* get the count of items in mux */
	for (i = 0, cnt = 0; ; i++, cnt++) {
		/* parent's #clock-cells property is always 0 */
		if (!of_parse_phandle(np, "clocks", i))
			break;
	}

	for (i = 0; ; i++) {
		if (!of_clk_get_parent_name(np, i))
			break;
	}
	num_parents = i;
	if (!num_parents)
		return;

	clk_sel = kzalloc(sizeof(u32 *) * num_parents, GFP_KERNEL);
	if (!clk_sel)
		return;
	if (of_property_read_u32_array(np, "marvell,mmp-clk-sel", clk_sel, cnt))
		goto err_sel;
	parent_names = kzalloc(sizeof(char *) * num_parents, GFP_KERNEL);
	if (!parent_names)
		goto err_sel;

	for (i = 0; i < num_parents; i++)
		parent_names[i] = of_clk_get_parent_name(np, i);
	clk = clk_register_mux(NULL, output_name, parent_names, num_parents,
				CLK_SET_RATE_PARENT,
				reg, shift, width, 0, &mmp_clk_lock);
				//reg, shift, width, 0, NULL);
	if (IS_ERR(clk))
		goto err_mux;
	if (!of_property_read_string(np, "clock-names", &clk_name))
		clk_register_clkdev(clk, clk_name, NULL);
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
	return;
err_mux:
	kfree(parent_names);
err_sel:
	kfree(clk_sel);
}

static void __init mmp_mpmu_mux_setup(struct device_node *np)
{
	u32 data[2];
	u8 shift, width;
	void __iomem *reg;

	if (!mmp_clk.mpmu_base)
		return;
	if (of_property_read_u32_array(np, "marvell,mmp-clk-reg", &data[0], 2))
		return;
	reg = mmp_clk.mpmu_base + data[0];
	shift = ffs(data[1]) - 1;
	width = fls(data[1]) - ffs(data[1]) + 1;

	mmp_mux_setup(np, reg, shift, width);
}

static void __init mmp_apmu_div_setup(struct device_node *np)
{
	u32 data[2];
	u8 shift, width;
	void __iomem *reg;
	const char *parent_name, *clk_name;
	struct clk *clk;

	if (!mmp_clk.apmu_base)
		return;

	if (of_property_read_u32_array(np, "marvell,mmp-clk-reg", &data[0], 2))
		return;
	reg = mmp_clk.apmu_base + data[0];
	shift = ffs(data[1]) - 1;
	width = fls(data[1]) - ffs(data[1]) + 1;

	parent_name = of_clk_get_parent_name(np, 0);
	if (!parent_name)
		return;
	if (of_property_read_string(np, "clock-output-names", &clk_name))
		return;

	clk = clk_register_divider(NULL, clk_name, parent_name,
			CLK_SET_RATE_PARENT, reg, shift, width, 0,
			&mmp_clk_lock);
	if (IS_ERR(clk))
		return;
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
	return;
}

static void __init mmp_apbcp_setup(struct device_node *np)
{
	int i, cnt;
	u32 *clk_sel, data[2];
	u8 num_parents, shift, width;
	void __iomem *reg;
	const char **parent_names, *clk_name;
	struct clk *clk;

	if (!mmp_clk.apbcp_base)
		return;
	if (of_property_read_string(np, "clock-output-names", &clk_name))
		return;
	/* get the count of items in mux */
	for (i = 0, cnt = 0; ; i++, cnt++) {
		/* parent's #clock-cells property is always 0 */
		if (!of_parse_phandle(np, "clocks", i))
			break;
	}

	for (i = 0; ; i++) {
		if (!of_clk_get_parent_name(np, i))
			break;
	}
	num_parents = i;
	if (!num_parents)
		return;

	if (of_property_read_u32_array(np, "marvell,mmp-clk-reg", &data[0], 2))
		return;
	reg = mmp_clk.apbcp_base + data[0];
	shift = ffs(data[1]) - 1;
	width = fls(data[1]) - ffs(data[1]) + 1;

	clk_sel = kzalloc(sizeof(u32 *) * num_parents, GFP_KERNEL);
	if (!clk_sel)
		return;
	if (of_property_read_u32_array(np, "marvell,mmp-clk-sel", clk_sel, cnt))
		goto err_sel;
	parent_names = kzalloc(sizeof(char *) * num_parents, GFP_KERNEL);
	if (!parent_names)
		goto err_sel;

	for (i = 0; i < num_parents; i++)
		parent_names[i] = of_clk_get_parent_name(np, i);
	clk = clk_register_mux(NULL, clk_name, parent_names, num_parents, 0,
				reg, shift, width, 0, &mmp_clk_lock);
	if (IS_ERR(clk))
		goto err_mux;
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
	return;
err_mux:
	kfree(parent_names);
err_sel:
	kfree(clk_sel);
}

static const __initconst struct of_device_id mmp_clk_match[] = {
	{
		.compatible = "fixed-clock",
		.data = of_fixed_clk_setup,
	}, {
		.compatible = "marvell,mmp-fixed-clkrate",
		.data = mmp_fixed_rate_setup,
	}, {
		.compatible = "marvell,mmp-fixed-clkfactor",
		.data = mmp_fixed_factor_setup,
	}, {
		.compatible = "marvell,mmp-mpmu-clkmux",
		.data = mmp_mpmu_mux_setup,
	}, {
		.compatible = "marvell,mmp-apmu-clkdiv",
		.data = mmp_apmu_div_setup,
	}, {
		.compatible = "marvell,mmp-apbc-clk",
		.data = mmp_apbc_setup,
	}, {
		.compatible = "marvell,mmp-apbcp-clock",
		.data = mmp_apbcp_setup,
	}, {
	}
};

void __init mmp_init_clocks(void)
{
	struct device_node *np;

	np = of_find_compatible_node(NULL, NULL, "marvell,mmp-mpmu");
	mmp_clk.mpmu_base = of_iomap(np, 0);
	if (WARN_ON(!mmp_clk.mpmu_base))
		return;

	np = of_find_compatible_node(NULL, NULL, "marvell,mmp-apmu");
	mmp_clk.apmu_base = of_iomap(np, 0);
	if (WARN_ON(!mmp_clk.apmu_base))
		return;

	np = of_find_compatible_node(NULL, NULL, "marvell,mmp-apbc");
	mmp_clk.apbc_base = of_iomap(np, 0);
	if (WARN_ON(!mmp_clk.apbc_base))
		return;

	np = of_find_compatible_node(NULL, NULL, "marvell,mmp-apbcp");
	mmp_clk.apbcp_base = of_iomap(np, 0);
	if (WARN_ON(!mmp_clk.apbcp_base))
		return;

	of_clk_init(mmp_clk_match);
}
