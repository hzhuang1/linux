// SPDX-License-Identifier: GPL-2.0
// test crypto
//
// Copyright (C) 2024 Haojian Zhuang <haojian.zhuang@linaro.org>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("crypto/shash")
int bpf_md5()
{
	__u64 tfm;

	tfm = bpf_crypto_alloc_shash("md5", 0, 0);
	bpf_printk("tfm:0x%x\n", tfm);
	return 0;
}

char _license[] SEC("license") = "GPL";
