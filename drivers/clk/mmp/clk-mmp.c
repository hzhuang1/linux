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

#include <linux/clk-provider.h>
#include <linux/clkdev.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>

#include "clk.h"

enum {
	MMP_MPMU = 0,
	MMP_APMU,
	MMP_APBC,
	MMP_APBCP,
	MMP_APB,
	MMP_MAX,
};

static void __iomem *mmp_clk_base[MMP_MAX];

static DEFINE_SPINLOCK(mmp_clk_lock);

static const struct of_device_id mmp_of_match[] = {
	{ .compatible = "marvell,mmp-mpmu", .data = (void *)MMP_MPMU, },
	{ .compatible = "marvell,mmp-apmu", .data = (void *)MMP_APMU, },
	{ .compatible = "marvell,mmp-apbc", .data = (void *)MMP_APBC, },
	{ .compatible = "marvell,mmp-apbcp", .data = (void *)MMP_APBCP, },
	{ .compatible = "mrvl,apb-bus", .data = (void *)MMP_APB, },
};

void __iomem __init *mmp_init_clocks(struct device_node *np)
{
	struct device_node *parent;
	const struct of_device_id *match;
	void __iomem *ret = NULL;
	int i;

	parent = of_get_parent(np);
	if (!parent)
		goto out;
	match = of_match_node(mmp_of_match, parent);
	if (!match)
		goto out;

	i = (unsigned int)match->data;
	switch (i) {
	case MMP_MPMU:
	case MMP_APMU:
	case MMP_APBC:
	case MMP_APBCP:
	case MMP_APB:
		if (!mmp_clk_base[i]) {
			ret = of_iomap(parent, 0);
			WARN_ON(!ret);
			mmp_clk_base[i] = ret;
		} else {
			ret = mmp_clk_base[i];
		}
		break;
	default:
		goto out;
	}
out:
	return ret;
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
CLK_OF_DECLARE(mmp_fixed_rate, "marvell,mmp-fixed-clkrate",
	       mmp_fixed_rate_setup);

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
CLK_OF_DECLARE(mmp_fixed_factor, "marvell,mmp-fixed-clkfactor",
	       mmp_fixed_factor_setup);

static void __init mmp_apmu_div_setup(struct device_node *np)
{
	u32 data[2];
	u8 shift, width;
	void __iomem *reg, *base;
	const char *parent_name, *clk_name;
	struct clk *clk;

	base = mmp_init_clocks(np);
	if (!base)
		return;

	if (of_property_read_u32_array(np, "marvell,mmp-clk-reg", &data[0], 2))
		return;
	reg = base + data[0];
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
CLK_OF_DECLARE(mmp_div, "mmp-apmu-clkdiv", mmp_apmu_div_setup);

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

static void __init mmp_mux_setup(struct device_node *np)
{
	u32 data[2], *clk_sel, mux_flags = 0;
	u8 shift, width, num_parents;
	void __iomem *reg, *base;
	const char **parent_names;
	const char *clk_name;
	struct clk *clk;
	int i, ret;

	base = mmp_init_clocks(np);
	if (!base)
		return;
	if (of_property_read_string(np, "clock-output-names", &clk_name))
		return;
	if (of_property_read_u32_array(np, "marvell,mmp-clk-reg", &data[0], 2))
		return;
	ret = mmp_parse_mux(np, parent_names, &num_parents, clk_sel);
	if (ret)
		return;

	reg = base + data[0];
	shift = ffs(data[1]) - 1;
	width = fls(data[1]) - ffs(data[1]) + 1;

	parent_names = kzalloc(sizeof(char *) * num_parents, GFP_KERNEL);
	if (!parent_names)
		return;

	for (i = 0; i < num_parents; i++)
		parent_names[i] = of_clk_get_parent_name(np, i);
	clk = clk_register_mux(NULL, clk_name, parent_names, num_parents,
			       CLK_SET_RATE_PARENT, reg, shift, width,
			       mux_flags, &mmp_clk_lock);
	if (IS_ERR(clk)) {
		kfree(parent_names);
		return;
	}
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
}
CLK_OF_DECLARE(mmp_mux, "marvell,mmp-clkmux", mmp_mux_setup);

#define APBC_NO_BUS_CTRL	BIT(0)
#define APBC_POWER_CTRL		BIT(1)

static void __init mmp_apbc_setup(struct device_node *np)
{
	u32 data[2], delay, apbc_flags, clkdev;
	void __iomem *reg, *base;
	const char **parent_names;
	const char *clk_name = NULL;
	struct clk *clk;

	base = mmp_init_clocks(np);
	if (!base)
		return;

	if (of_property_read_string(np, "clock-names", &clk_name))
		clkdev = 1;
	else {
		of_property_read_string(np, "clock-output-names", &clk_name);
		clkdev = 0;
	}

	if (of_property_read_u32_array(np, "marvell,mmp-clk-reg", &data[0], 2))
		return;
	/* If marvell,mmp-clk-delay property isn't defined, set delay as 10us */
	if (of_property_read_u32(np, "marvell,mmp-clk-delay", &delay))
		delay = 10;
	if (of_get_property(np, "marvell,mmp-apbc-power-ctl", NULL))
		apbc_flags |= APBC_POWER_CTRL;

	reg = base + data[0];

	/* only has the fixed parent */
	parent_names = kzalloc(sizeof(char *), GFP_KERNEL);
	if (!parent_names)
		return;
	parent_names[0] = of_clk_get_parent_name(np, 0);

	clk = mmp_clk_register_apbc(clk_name, parent_names[0],
				    reg, delay, 0, &mmp_clk_lock);
	if (IS_ERR(clk)) {
		kfree(parent_names);
		return;
	}
	if (clkdev)
		clk_register_clkdev(clk, clk_name, NULL);
	of_clk_add_provider(np, of_clk_src_simple_get, clk);
}
CLK_OF_DECLARE(mmp_apbc, "marvell,mmp-apbc-clk", mmp_apbc_setup);

static void __init mmp_apbcp_setup(struct device_node *np)
{
	int i, cnt;
	u32 *clk_sel, data[2];
	u8 num_parents, shift, width;
	void __iomem *reg, *base;
	const char **parent_names, *clk_name;
	struct clk *clk;

	base = mmp_init_clocks(np);
	if (!base)
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
	reg = base + data[0];
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
CLK_OF_DECLARE(mmp_apbcp, "mmp-apbcp-clk", mmp_apbcp_setup);
