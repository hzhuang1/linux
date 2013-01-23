/*
 *  linux/arch/arm/plat-pxa/gpio.c
 *
 *  Generic PXA GPIO handling
 *
 *  Author:	Nicolas Pitre
 *  Created:	Jun 15, 2001
 *  Copyright:	MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/gpio-pxa.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/syscore_ops.h>
#include <linux/slab.h>

#include <asm/mach/irq.h>

#include <mach/irqs.h>

/*
 * We handle the GPIOs by banks, each bank covers up to 32 GPIOs with
 * one set of registers. The register offsets are organized below:
 *
 *           GPLR    GPDR    GPSR    GPCR    GRER    GFER    GEDR
 * BANK 0 - 0x0000  0x000C  0x0018  0x0024  0x0030  0x003C  0x0048
 * BANK 1 - 0x0004  0x0010  0x001C  0x0028  0x0034  0x0040  0x004C
 * BANK 2 - 0x0008  0x0014  0x0020  0x002C  0x0038  0x0044  0x0050
 *
 * BANK 3 - 0x0100  0x010C  0x0118  0x0124  0x0130  0x013C  0x0148
 * BANK 4 - 0x0104  0x0110  0x011C  0x0128  0x0134  0x0140  0x014C
 * BANK 5 - 0x0108  0x0114  0x0120  0x012C  0x0138  0x0144  0x0150
 *
 * NOTE:
 *   BANK 3 is only available on PXA27x and later processors.
 *   BANK 4 and 5 are only available on PXA935
 */

#define GPLR_OFFSET	0x00
#define GPDR_OFFSET	0x0C
#define GPSR_OFFSET	0x18
#define GPCR_OFFSET	0x24
#define GRER_OFFSET	0x30
#define GFER_OFFSET	0x3C
#define GEDR_OFFSET	0x48
#define GAFR_OFFSET	0x54
#define ED_MASK_OFFSET	0x9C	/* GPIO edge detection for AP side */

#define BANK_OFF(n)	(((n) < 3) ? (n) << 2 : 0x100 + (((n) - 3) << 2))

int pxa_last_gpio;

#ifdef CONFIG_OF
static struct device_node *pxa_gpio_of_node;
#endif

struct pxa_gpio_chip {
	struct gpio_chip chip;
	void __iomem	*regbase;
	unsigned int	irq_base;
	unsigned int	inverted;
	unsigned int	gafr;
	char label[10];

	unsigned long	irq_mask;
	unsigned long	irq_edge_rise;
	unsigned long	irq_edge_fall;
	int (*set_wake)(unsigned int gpio, unsigned int on);

#ifdef CONFIG_PM
	unsigned long	saved_gplr;
	unsigned long	saved_gpdr;
	unsigned long	saved_grer;
	unsigned long	saved_gfer;
#endif
};

static DEFINE_SPINLOCK(gpio_lock);
static struct pxa_gpio_chip *pxa_gpio_chips;
static void __iomem *gpio_reg_base;

#define for_each_gpio_chip(i, c)			\
	for (i = 0, c = &pxa_gpio_chips[0]; i <= pxa_last_gpio; i += 32, c++)

static inline void __iomem *gpio_chip_base(struct gpio_chip *gc)
{
	return container_of(gc, struct pxa_gpio_chip, chip)->regbase;
}

static inline struct pxa_gpio_chip *gpio_to_pxachip(unsigned gpio)
{
	return &pxa_gpio_chips[gpio_to_bank(gpio)];
}

/* GPIO86/87/88/89 on PXA26x have their direction bits in PXA_GPDR(2 inverted,
 * as well as their Alternate Function value being '1' for GPIO in GAFRx.
 */
static inline int __gpio_is_inverted(struct pxa_gpio_chip *chip, int gpio)
{
	if ((chip->inverted) && (gpio > 85))
		return 1;
	return 0;
}

/*
 * On PXA25x and PXA27x, GAFRx and GPDRx together decide the alternate
 * function of a GPIO, and GPDRx cannot be altered once configured. It
 * is attributed as "occupied" here (I know this terminology isn't
 * accurate, you are welcome to propose a better one :-)
 */
static inline int __gpio_is_occupied(struct pxa_gpio_chip *chip, unsigned gpio)
{
	void __iomem *base;
	unsigned long gafr = 0, gpdr = 0;
	int ret, af = 0, dir = 0;

	base = gpio_chip_base(&chip->chip);
	gpdr = readl_relaxed(base + GPDR_OFFSET);

	if (chip->gafr) {
		gafr = readl_relaxed(base + GAFR_OFFSET);
		af = (gafr >> ((gpio & 0xf) * 2)) & 0x3;
		dir = gpdr & GPIO_bit(gpio);

		if (__gpio_is_inverted(chip, gpio))
			ret = (af != 1) || (dir == 0);
		else
			ret = (af != 0) || (dir != 0);
	} else {
		ret = gpdr & GPIO_bit(gpio);
	}
	return ret;
}

static int pxa_gpio_to_irq(struct gpio_chip *gc, unsigned offset)
{
	struct pxa_gpio_chip *chip = NULL;

	chip = container_of(gc, struct pxa_gpio_chip, chip);
	return chip->irq_base + offset;
}

int pxa_irq_to_gpio(struct irq_data *d)
{
	struct pxa_gpio_chip *chip;
	int gpio;

	chip = (struct pxa_gpio_chip *)d->domain->host_data;
	gpio = d->irq - chip->irq_base + chip->chip.base;
	return gpio;
}

static int pxa_gpio_direction_input(struct gpio_chip *gc, unsigned offset)
{
	struct pxa_gpio_chip *chip = NULL;
	void __iomem *base = gpio_chip_base(gc);
	uint32_t value, mask = 1 << offset;
	unsigned long flags;

	chip = container_of(gc, struct pxa_gpio_chip, chip);

	spin_lock_irqsave(&gpio_lock, flags);

	value = readl_relaxed(base + GPDR_OFFSET);
	if (__gpio_is_inverted(chip, gc->base + offset))
		value |= mask;
	else
		value &= ~mask;
	writel_relaxed(value, base + GPDR_OFFSET);

	spin_unlock_irqrestore(&gpio_lock, flags);
	return 0;
}

static int pxa_gpio_direction_output(struct gpio_chip *gc,
				     unsigned offset, int value)
{
	struct pxa_gpio_chip *chip = NULL;
	void __iomem *base = gpio_chip_base(gc);
	uint32_t tmp, mask = 1 << offset;
	unsigned long flags;

	chip = container_of(gc, struct pxa_gpio_chip, chip);

	writel_relaxed(mask, base + (value ? GPSR_OFFSET : GPCR_OFFSET));

	spin_lock_irqsave(&gpio_lock, flags);

	tmp = readl_relaxed(base + GPDR_OFFSET);
	if (__gpio_is_inverted(chip, gc->base + offset))
		tmp &= ~mask;
	else
		tmp |= mask;
	writel_relaxed(tmp, base + GPDR_OFFSET);

	spin_unlock_irqrestore(&gpio_lock, flags);
	return 0;
}

static int pxa_gpio_get(struct gpio_chip *gc, unsigned offset)
{
	return readl_relaxed(gpio_chip_base(gc) + GPLR_OFFSET) & (1 << offset);
}

static void pxa_gpio_set(struct gpio_chip *gc, unsigned offset, int value)
{
	writel_relaxed(1 << offset, gpio_chip_base(gc) +
				(value ? GPSR_OFFSET : GPCR_OFFSET));
}

#ifdef CONFIG_OF_GPIO
static int pxa_gpio_of_xlate(struct gpio_chip *gc,
			     const struct of_phandle_args *gpiospec,
			     u32 *flags)
{
	if (gpiospec->args[0] > pxa_last_gpio)
		return -EINVAL;

	if (gc != &pxa_gpio_chips[gpiospec->args[0] / 32].chip)
		return -EINVAL;

	if (flags)
		*flags = gpiospec->args[1];

	return gpiospec->args[0] % 32;
}
#endif

/* Update only those GRERx and GFERx edge detection register bits if those
 * bits are set in c->irq_mask
 */
static inline void update_edge_detect(struct pxa_gpio_chip *chip)
{
	uint32_t grer, gfer;

	grer = readl_relaxed(chip->regbase + GRER_OFFSET) & ~chip->irq_mask;
	gfer = readl_relaxed(chip->regbase + GFER_OFFSET) & ~chip->irq_mask;
	grer |= chip->irq_edge_rise & chip->irq_mask;
	gfer |= chip->irq_edge_fall & chip->irq_mask;
	writel_relaxed(grer, chip->regbase + GRER_OFFSET);
	writel_relaxed(gfer, chip->regbase + GFER_OFFSET);
}

static int pxa_gpio_irq_type(struct irq_data *d, unsigned int type)
{
	struct pxa_gpio_chip *chip;
	int gpio = pxa_irq_to_gpio(d);
	unsigned long gpdr, mask = GPIO_bit(gpio);

	chip = gpio_to_pxachip(gpio);

	if (type == IRQ_TYPE_PROBE) {
		/* Don't mess with enabled GPIOs using preconfigured edges or
		 * GPIOs set to alternate function or to output during probe
		 */
		if ((chip->irq_edge_rise | chip->irq_edge_fall)
			& GPIO_bit(gpio))
			return 0;

		if (__gpio_is_occupied(chip, gpio))
			return 0;

		type = IRQ_TYPE_EDGE_RISING | IRQ_TYPE_EDGE_FALLING;
	}

	gpdr = readl_relaxed(chip->regbase + GPDR_OFFSET);

	if (__gpio_is_inverted(chip, gpio))
		writel_relaxed(gpdr | mask,  chip->regbase + GPDR_OFFSET);
	else
		writel_relaxed(gpdr & ~mask, chip->regbase + GPDR_OFFSET);

	if (type & IRQ_TYPE_EDGE_RISING)
		chip->irq_edge_rise |= mask;
	else
		chip->irq_edge_rise &= ~mask;

	if (type & IRQ_TYPE_EDGE_FALLING)
		chip->irq_edge_fall |= mask;
	else
		chip->irq_edge_fall &= ~mask;

	update_edge_detect(chip);

	pr_debug("%s: IRQ%d (GPIO%d) - edge%s%s\n", __func__, d->irq, gpio,
		((type & IRQ_TYPE_EDGE_RISING)  ? " rising"  : ""),
		((type & IRQ_TYPE_EDGE_FALLING) ? " falling" : ""));
	return 0;
}

static void pxa_gpio_demux_handler(unsigned int irq, struct irq_desc *desc)
{
	struct pxa_gpio_chip *chip;
	int loop, gpio, gpio_base, n;
	unsigned long gedr;
	struct irq_chip *ic = irq_desc_get_chip(desc);

	chained_irq_enter(ic, desc);

	do {
		loop = 0;
		for_each_gpio_chip(gpio, chip) {
			gpio_base = chip->chip.base;

			gedr = readl_relaxed(chip->regbase + GEDR_OFFSET);
			gedr = gedr & chip->irq_mask;
			writel_relaxed(gedr, chip->regbase + GEDR_OFFSET);

			for_each_set_bit(n, &gedr, BITS_PER_LONG) {
				loop = 1;

				generic_handle_irq(gpio_to_irq(gpio_base + n));
			}
		}
	} while (loop);

	chained_irq_exit(ic, desc);
}

static void pxa_ack_muxed_gpio(struct irq_data *d)
{
	int gpio = pxa_irq_to_gpio(d);
	struct pxa_gpio_chip *chip = gpio_to_pxachip(gpio);

	writel_relaxed(GPIO_bit(gpio), chip->regbase + GEDR_OFFSET);
}

static void pxa_mask_muxed_gpio(struct irq_data *d)
{
	int gpio = pxa_irq_to_gpio(d);
	struct pxa_gpio_chip *chip = gpio_to_pxachip(gpio);
	uint32_t grer, gfer;

	chip->irq_mask &= ~GPIO_bit(gpio);

	grer = readl_relaxed(chip->regbase + GRER_OFFSET) & ~GPIO_bit(gpio);
	gfer = readl_relaxed(chip->regbase + GFER_OFFSET) & ~GPIO_bit(gpio);
	writel_relaxed(grer, chip->regbase + GRER_OFFSET);
	writel_relaxed(gfer, chip->regbase + GFER_OFFSET);
}

static int pxa_gpio_set_wake(struct irq_data *d, unsigned int on)
{
	int gpio = pxa_irq_to_gpio(d);
	struct pxa_gpio_chip *chip = gpio_to_pxachip(gpio);

	if (chip->set_wake)
		return chip->set_wake(gpio, on);
	else
		return 0;
}

static void pxa_unmask_muxed_gpio(struct irq_data *d)
{
	int gpio = pxa_irq_to_gpio(d);
	struct pxa_gpio_chip *chip = gpio_to_pxachip(gpio);

	chip->irq_mask |= GPIO_bit(gpio);
	update_edge_detect(chip);
}

static struct irq_chip pxa_muxed_gpio_chip = {
	.name		= "GPIO",
	.irq_ack	= pxa_ack_muxed_gpio,
	.irq_mask	= pxa_mask_muxed_gpio,
	.irq_unmask	= pxa_unmask_muxed_gpio,
	.irq_set_type	= pxa_gpio_irq_type,
	.irq_set_wake	= pxa_gpio_set_wake,
};

#ifdef CONFIG_OF
static struct of_device_id pxa_gpio_dt_ids[] = {
	{ .compatible = "mrvl,pxa-gpio" },
	{ .compatible = "mrvl,mmp-gpio" },
	{}
};

static int pxa_irq_domain_map(struct irq_domain *d, unsigned int irq,
			      irq_hw_number_t hw)
{
	irq_set_chip_and_handler(irq, &pxa_muxed_gpio_chip,
				 handle_edge_irq);
	set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	return 0;
}

static const struct irq_domain_ops pxa_irq_domain_ops = {
	.map	= pxa_irq_domain_map,
	.xlate	= irq_domain_xlate_twocell,
};

static int pxa_gpio_probe_dt(struct platform_device *pdev)
{
	int ret, nr_banks;
	struct pxa_gpio_platform_data *pdata;
	struct device_node *prev, *next, *np = pdev->dev.of_node;
	const struct of_device_id *of_id =
				of_match_device(pxa_gpio_dt_ids, &pdev->dev);

	if (!of_id) {
		dev_err(&pdev->dev, "Failed to find gpio controller\n");
		return -EFAULT;
	}
	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;
	ret = of_find_property(np, "marvell,gpio-ed-mask", NULL);
	if (ret)
		pdata->ed_mask = 1;
	/* It's only valid for PXA26x */
	ret = of_find_property(np, "marvell,gpio-inverted", NULL);
	if (ret)
		pdata->inverted = 1;
	ret = of_property_read_u32(np, "marvell,nr-gpios", &pdata->nr_gpios);
	if (ret < 0) {
		dev_err(&pdev->dev, "nr-gpios isn't specified\n");
		return -ENOTSUPP;
	}
	/* set the platform data */
	pdev->dev.platform_data = pdata;

	next = of_get_next_child(np, NULL);
	prev = next;
	if (!next) {
		dev_err(&pdev->dev, "Failed to find child gpio node\n");
		ret = -EINVAL;
		goto err;
	}
	for (nr_banks = 1; ; nr_banks++) {
		next = of_get_next_child(np, prev);
		if (!next)
			break;
		prev = next;
	}
	of_node_put(prev);

	return 0;
err:
	iounmap(gpio_reg_base);
	return ret;
}
#else
#define pxa_gpio_probe_dt(pdev)		(-1)
#endif

static int pxa_init_gpio_chip(struct platform_device *pdev, int gpio_end,
			      int (*set_wake)(unsigned int, unsigned int))
{
	int i, gpio, nbanks = gpio_to_bank(gpio_end) + 1;
	struct pxa_gpio_chip *chips;

	chips = devm_kzalloc(&pdev->dev, nbanks * sizeof(*chips), GFP_KERNEL);
	if (chips == NULL) {
		pr_err("%s: failed to allocate GPIO chips\n", __func__);
		return -ENOMEM;
	}

	for (i = 0, gpio = 0; i < nbanks; i++, gpio += 32) {
		struct gpio_chip *gc = &chips[i].chip;

		sprintf(chips[i].label, "gpio-%d", i);
		chips[i].regbase = gpio_reg_base + BANK_OFF(i);
		chips[i].set_wake = set_wake;

		/* number of GPIOs on last bank may be less than 32 */
		gc->ngpio = (gpio + 31 > gpio_end) ? (gpio_end - gpio + 1) : 32;

		chips[i].irq_base = irq_alloc_descs(-1, 0, gc->ngpio, 0);
		if (chips[i].irq_base < 0)
			return -EINVAL;
		if (!irq_domain_add_legacy(pdev->dev.of_node, gc->ngpio,
					   chips[i].irq_base, 0,
					   &pxa_irq_domain_ops, &chips[i]))
			return -ENODEV;

		gc->base  = gpio;
		gc->label = chips[i].label;

		gc->direction_input  = pxa_gpio_direction_input;
		gc->direction_output = pxa_gpio_direction_output;
		gc->get = pxa_gpio_get;
		gc->set = pxa_gpio_set;
		gc->to_irq = pxa_gpio_to_irq;
#ifdef CONFIG_OF_GPIO
		gc->of_node = pxa_gpio_of_node;
		gc->of_xlate = pxa_gpio_of_xlate;
		gc->of_gpio_n_cells = 2;
#endif
		gpiochip_add(gc);
	}
	pxa_gpio_chips = chips;
	return 0;
}

static int pxa_gpio_probe(struct platform_device *pdev)
{
	struct pxa_gpio_chip *chip;
	struct resource *res;
	struct clk *clk;
	struct pxa_gpio_platform_data *pdata;
	int gpio, irq, ret, use_of = 0;
	int irq0 = 0, irq1 = 0, irq_mux, gpio_offset = 0;

	ret = pxa_gpio_probe_dt(pdev);
	if (!ret)
		use_of = 1;

	irq0 = platform_get_irq_byname(pdev, "gpio0");
	irq1 = platform_get_irq_byname(pdev, "gpio1");
	irq_mux = platform_get_irq_byname(pdev, "gpio_mux");
	if ((irq0 > 0 && irq1 <= 0) || (irq0 <= 0 && irq1 > 0)
		|| (irq_mux <= 0))
		return -EINVAL;
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -EINVAL;
	gpio_reg_base = ioremap(res->start, resource_size(res));
	if (!gpio_reg_base)
		return -EINVAL;

	if (irq0 > 0)
		gpio_offset = 2;

	clk = clk_get(&pdev->dev, NULL);
	if (IS_ERR(clk)) {
		dev_err(&pdev->dev, "Error %ld to get gpio clock\n",
			PTR_ERR(clk));
		iounmap(gpio_reg_base);
		return PTR_ERR(clk);
	}
	ret = clk_prepare_enable(clk);
	if (ret) {
		clk_put(clk);
		iounmap(gpio_reg_base);
		return ret;
	}

	/* Initialize GPIO chips */
	pdata = dev_get_platdata(&pdev->dev);
	pxa_last_gpio = pdata->nr_gpios - 1;
	ret = pxa_init_gpio_chip(pdev, pxa_last_gpio,
				 pdata ? pdata->gpio_set_wake : NULL);
	if (ret < 0)
		return ret;

	/* clear all GPIO edge detects */
	for_each_gpio_chip(gpio, chip) {
		writel_relaxed(0, chip->regbase + GFER_OFFSET);
		writel_relaxed(0, chip->regbase + GRER_OFFSET);
		writel_relaxed(~0,chip->regbase + GEDR_OFFSET);
		/* unmask GPIO edge detect for AP side */
		if (pdata->ed_mask)
			writel_relaxed(~0, chip->regbase + ED_MASK_OFFSET);
		/* update for gpio inverted & gafr */
		chip->inverted = pdata->inverted;
		chip->gafr = pdata->gafr;
	}

	if (!use_of) {
		if (irq0 > 0) {
			irq = gpio_to_irq(0);
			irq_set_chip_and_handler(irq, &pxa_muxed_gpio_chip,
						 handle_edge_irq);
			set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
			irq_set_chained_handler(irq0, pxa_gpio_demux_handler);
		}
		if (irq1 > 0) {
			irq = gpio_to_irq(1);
			irq_set_chip_and_handler(irq, &pxa_muxed_gpio_chip,
						 handle_edge_irq);
			set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
			irq_set_chained_handler(irq1, pxa_gpio_demux_handler);
		}
		for (irq = gpio_to_irq(gpio_offset);
			irq <= gpio_to_irq(pxa_last_gpio); irq++) {
			irq_set_chip_and_handler(irq, &pxa_muxed_gpio_chip,
						 handle_edge_irq);
			set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
		}
	}

	irq_set_chained_handler(irq_mux, pxa_gpio_demux_handler);
	return 0;
}

static struct platform_driver pxa_gpio_driver = {
	.probe		= pxa_gpio_probe,
	.driver		= {
		.name	= "pxa-gpio",
		.of_match_table = of_match_ptr(pxa_gpio_dt_ids),
	},
};
module_platform_driver(pxa_gpio_driver);

#ifdef CONFIG_PM
static int pxa_gpio_suspend(void)
{
	struct pxa_gpio_chip *chip;
	int gpio;

	for_each_gpio_chip(gpio, chip) {
		chip->saved_gplr = readl_relaxed(chip->regbase + GPLR_OFFSET);
		chip->saved_gpdr = readl_relaxed(chip->regbase + GPDR_OFFSET);
		chip->saved_grer = readl_relaxed(chip->regbase + GRER_OFFSET);
		chip->saved_gfer = readl_relaxed(chip->regbase + GFER_OFFSET);

		/* Clear GPIO transition detect bits */
		writel_relaxed(~0, chip->regbase + GEDR_OFFSET);
	}
	return 0;
}

static void pxa_gpio_resume(void)
{
	struct pxa_gpio_chip *chip;
	int gpio;

	for_each_gpio_chip(gpio, chip) {
		/* restore level with set/clear */
		writel_relaxed( chip->saved_gplr, chip->regbase + GPSR_OFFSET);
		writel_relaxed(~chip->saved_gplr, chip->regbase + GPCR_OFFSET);

		writel_relaxed(chip->saved_grer, chip->regbase + GRER_OFFSET);
		writel_relaxed(chip->saved_gfer, chip->regbase + GFER_OFFSET);
		writel_relaxed(chip->saved_gpdr, chip->regbase + GPDR_OFFSET);
	}
}
#else
#define pxa_gpio_suspend	NULL
#define pxa_gpio_resume		NULL
#endif

struct syscore_ops pxa_gpio_syscore_ops = {
	.suspend	= pxa_gpio_suspend,
	.resume		= pxa_gpio_resume,
};

static int __init pxa_gpio_sysinit(void)
{
	register_syscore_ops(&pxa_gpio_syscore_ops);
	return 0;
}
postcore_initcall(pxa_gpio_sysinit);
