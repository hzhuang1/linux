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
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>

struct mmp_clk {
	void __iomem *mpmu_base;	/* virtual address */
	void __iomem *apmu_base;	/* virtual address */
};

static struct mmp_clk mmp_clk;

static DEFINE_SPINLOCK(mmp_clk_lock);

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
	const char *clk_name, *parent_name;
	u32 data[2];

	if (of_property_read_u32_array(np, "marvell,mmp-fixed-factor",
				&data[0], 2))
		return;
	if (of_property_read_string(np, "clock-output-names", &clk_name))
		return;

	/* this node has only one parent */
	parent_name = of_clk_get_parent_name(np, 0);
	if (!parent_name)
		return;

	clk = clk_register_fixed_factor(NULL, clk_name, parent_name, 0,
			data[0], data[1]);
	if (IS_ERR(clk))
		return;
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
}

static void __init mmp_mpmu_mux_setup(struct device_node *np)
{
	int i, cnt;
	u32 *clk_sel, data[2];
	u8 num_parents, shift, width;
	void __iomem *reg;
	const char *clk_name, **parent_names;
	struct clk *clk;

	if (!mmp_clk.mpmu_base)
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
	reg = mmp_clk.mpmu_base + data[0];
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

	of_clk_init(mmp_clk_match);
}
