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

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} user_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} kern_rb SEC(".maps");

static int dump_md5_digest(void *digest, size_t digest_sz)
{
	int i, offset;
	char out[64] = {};
	__u64 tmp;
	unsigned char c;
	for (i = 0, offset = 0; i < digest_sz; i++) {
		if (i % 8 == 0)
			tmp = *(__u64 *)(digest + i);
		c = (tmp & 0xf0) >> 4;
		if ((c >= 0) && (c <= 9)) {
			out[offset++] = 0x30 + c;
		} else if ((c >= 0xa) && (c <= 0xf)) {
			out[offset++] = 0x61 + c - 10;
		} else {
			bpf_printk("wc[%d]:%x, whole value:0x%llx\n", i, c, *(__u64 *)digest);
		}
		c = tmp & 0x0f;
		if ((c >= 0) && (c <= 9)) {
			out[offset++] = 0x30 + c;
		} else if ((c >= 0xa) && (c <= 0xf)) {
			out[offset++] = 0x61 + c - 10;
		} else {
			bpf_printk("wc[%d]:%x, whole value:0x%llx\n", i, c, *(__u64 *)digest);
		}
		tmp = tmp >> 8;
		if (i < digest_sz - 1)
			out[offset++] = '-';
	}
	out[offset] = '\0';
	bpf_printk("digest:%s\n", out);
	return 0;
}

//static long do_md5(const struct bpf_dynptr *dynptr, void *ctx)
static long do_md5(__u64 arg1, __u64 arg2, __u64 arg3, __u64 arg4, __u64 arg5)
{
	struct bpf_dynptr *dynptr = (struct bpf_dynptr *)arg1;
	__u64 tmp;
	int ret;
	char words[] = "start MD5 calculation";
	char digest[32] = {};
	__u64 handle;
	char fmt[] = "tfm:0x%llx, ret:%x\n";
	//void *p = NULL;

	bpf_printk("entering do_md5()\n");
	ret = bpf_dynptr_read(&tmp, sizeof(__u64), dynptr, 0, 0);
	bpf_printk("ret:%d\n", ret);
	bpf_printk("dynptr:0x%llx\n", (__u64)dynptr);
	/* trigger MD5 */
	ret = bpf_crypto_alloc_shash("md5", 3, 0, 0, &handle);
	bpf_trace_printk(fmt, sizeof(fmt), handle, ret);
	ret = bpf_crypto_shash_digest(handle, words, 21, (void *)&digest, 32);
	dump_md5_digest(digest, 16);
	//bpf_printk("digest ret:%d, digest:0x%llx\n", ret, *(__u64 *)digest);
	bpf_crypto_free_shash(handle);
	//bpf_printk("arg1:0x%llx\n", arg1);
	//bpf_printk("*dynptr:0x%llx\n", *(__u64 *)dynptr);
	//bpf_printk("entering do_md5(), arg1:%llx, arg2:%llx, arg3:%llx\n", arg1, arg2, arg3);
	//p = bpf_dynptr_data(dynptr, 0, 5);
	//p = dynptr;
	//p = p + 8;
	//bpf_printk("p:0x%llx\n", (__u64)p);
	//bpf_printk("*p:0x%llx\n", *(__u64 *)p);
	return 0;
}

//SEC("fentry/__arm64_sys_getpgid")
SEC("tracepoint/syscalls/sys_enter_getpgid")
int handle_user_ringbuf()
{
	long status = 0;
	long cons_pos, prod_pos, avail_data, rb_size;
	char fmt3[] = "rb_size:%d, avail_data:%d\n";
	char fmt4[] = "cons_pos:%d, prod_pos:%d\n";

	bpf_printk("entering handle_user_ringbuf()\n");
	cons_pos = bpf_ringbuf_query(&kern_rb, BPF_RB_CONS_POS);
	prod_pos = bpf_ringbuf_query(&kern_rb, BPF_RB_PROD_POS);
	avail_data = bpf_ringbuf_query(&kern_rb, BPF_RB_AVAIL_DATA);
	rb_size = bpf_ringbuf_query(&kern_rb, BPF_RB_RING_SIZE);
	bpf_trace_printk(fmt3, sizeof(fmt3), rb_size, avail_data);
	bpf_trace_printk(fmt4, sizeof(fmt4), cons_pos, prod_pos);

	status = bpf_user_ringbuf_drain(&user_rb, do_md5, NULL, 0);
	bpf_printk("status:%ld\n", status);
	if (status < 0) {
		bpf_printk("drain user ringbuf returned %ld\n", status);
		return -1;
	}
	return 0;
}

//SEC("perf_event")
//SEC("crypto/shash")
//SEC("tracepoint/raw_syscalls/sys_enter")
//SEC("sys_getpgid")
int bpf_md5()
{
	__u64 handle;
	int ret;
	long cons_pos, prod_pos, avail_data, rb_size;
	//int ret, key;
	//int *value;
	char fmt[] = "tfm:0x%llx, ret:%x\n";
	char fmt3[] = "rb_size:%d, avail_data:%d\n";
	char fmt4[] = "cons_pos:%d, prod_pos:%d\n";

	cons_pos = bpf_ringbuf_query(&kern_rb, BPF_RB_CONS_POS);
	prod_pos = bpf_ringbuf_query(&kern_rb, BPF_RB_PROD_POS);
	avail_data = bpf_ringbuf_query(&kern_rb, BPF_RB_AVAIL_DATA);
	rb_size = bpf_ringbuf_query(&kern_rb, BPF_RB_RING_SIZE);
	bpf_trace_printk(fmt3, sizeof(fmt3), rb_size, avail_data);
	bpf_trace_printk(fmt4, sizeof(fmt4), cons_pos, prod_pos);
	//key = 0;
	//value = 0x55;
	//bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY);
	ret = bpf_crypto_alloc_shash("md5", 3, 0, 0, &handle);
	bpf_trace_printk(fmt, sizeof(fmt), handle, ret);
	bpf_crypto_free_shash(handle);
	/*
	ret = bpf_crypto_shash_init(tfm);
	bpf_trace_printk(fmt3, sizeof(fmt3), ret);
	value = bpf_map_lookup_elem(&hash_map, &key);
	if (value) {
		*value = 0x55;
	}
	key = 1;
	*/
	//value = ret;
	//bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY);
	return ret;
	//return 0;
}

  #if 0
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
  #endif

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
