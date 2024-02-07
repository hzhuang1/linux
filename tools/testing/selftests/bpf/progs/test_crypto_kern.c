// SPDX-License-Identifier: GPL-2.0
// test crypto
//
// Copyright (C) 2024 Haojian Zhuang <haojian.zhuang@linaro.org>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#if 1
volatile int my_pid_var = 0;
volatile int res_var = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 2);
} hash_map SEC(".maps");

//SEC("perf_event")
/*
SEC("crypto/shash")
int bpf_md5()
{
	//__u64 tfm = 0;
	int tfm = 0;
	int ret, key;
	int *value;
	char fmt[] = "tfm:0x%x\n";
	char fmt2[] = "hello world\n";

	key = 0;
	//value = 0x55;
	//bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY);
	tfm = bpf_crypto_alloc_shash("md5", 0, 0);
	ret = bpf_crypto_shash_init(tfm);
	value = bpf_map_lookup_elem(&hash_map, &key);
	if (value) {
		*value = 0x55;
	}
	key = 1;
	//value = ret;
	//bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY);
	return ret;
	bpf_trace_printk(fmt, sizeof(fmt), tfm);
	bpf_trace_printk(fmt2, sizeof(fmt2));
	//return 0;
}
*/
typedef __u64 u64;
typedef char stringkey[64];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	stringkey* key;
	__type(value, u64);
} execve_counter SEC(".maps");

SEC("crypto/shash")
int bpf_md5(void *ctx)
{
	stringkey key = "execve_counter";
	u64 *v = NULL;
	v = bpf_map_lookup_elem(&execve_counter, &key);
	if (v != NULL) {
		*v += 1;
	}
	return 0;
}

SEC("tp/raw_syscalls/sys_enter")
int handle_modern(void *ctx)
{
	int cur_pid;
	char fmt2[] = "hello world\n";

	bpf_trace_printk(fmt2, sizeof(fmt2));
	cur_pid = bpf_get_current_pid_tgid() >> 32;
	if (cur_pid != my_pid_var)
		return 1;

	if (res_var == 0)
		/* we need bpf_printk() to validate libbpf logic around unused
		 * global maps and legacy kernels; see comment in handle_legacy()
		 */
		bpf_printk("Modern-case bpf_printk test, pid %d\n", cur_pid);
	res_var = 1;

	return res_var;
}

char _license[] SEC("license") = "GPL";
#endif

#if 0
char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
        int pid = bpf_get_current_pid_tgid() >> 32;

        if (pid != my_pid)
                return 0;

        bpf_printk("BPF triggered from PID %d.\n", pid);

        return 0;
}
#endif
