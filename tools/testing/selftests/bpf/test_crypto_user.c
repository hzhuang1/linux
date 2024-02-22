// SPDX-License-Identifier: GPL-2.0
// test ir decoder
//
// Copyright (C) 2018 Sean Young <sean@mess.org>

// A lirc chardev is a device representing a consumer IR (cir) device which
// can receive infrared signals from remote control and/or transmit IR.
//
// IR is sent as a series of pulses and space somewhat like morse code. The
// BPF program can decode this into scancodes so that rc-core can translate
// this into input key codes using the rc keymap.
//
// This test works by sending IR over rc-loopback, so the IR is processed by
// BPF and then decoded into scancodes. The lirc chardev must be the one
// associated with rc-loopback, see the output of ir-keytable(1).
//
// The following CONFIG options must be enabled for the test to succeed:
// CONFIG_RC_CORE=y
// CONFIG_BPF_RAWIR_EVENT=y
// CONFIG_RC_LOOPBACK=y

// Steps:
// 1. Open the /dev/lircN device for rc-loopback (given on command line)
// 2. Attach bpf_lirc_mode2 program which decodes some IR.
// 3. Send some IR to the same IR device; since it is loopback, this will
//    end up in the bpf program
// 4. bpf program should decode IR and report keycode
// 5. We can read keycode from same /dev/lirc device

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
//#include <linux/compiler.h>
#include <linux/ring_buffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "bpf_util.h"

#include "testing_helpers.h"

#if 0
int main(int argc, char **argv)
{
	struct bpf_object *obj;
	int ret, /*lircfd, */progfd/*, inputfd*/;
	/*
	int testir1 = 0x1dead;
	int testir2 = 0x20101;
	u32 prog_ids[10], prog_flags[10], prog_cnt;
	*/

	ret = bpf_prog_test_load("test_crypto_kern.bpf.o",
				 BPF_PROG_TYPE_CRYPTO_SHASH, &obj, &progfd);
	if (ret) {
		printf("Failed to load bpf program\n");
		return 1;
	}
	printf("hello!\n");

	bpf_object__close(obj);
	/*
	lircfd = 0;
	ret = bpf_prog_detach2(progfd, lircfd, BPF_CRYPTO_SHASH);
	if (ret != -1 || errno != ENOENT) {
		printf("bpf_prog_detach2 not attached should fail: %m\n");
		return 1;
	}
	*/

	return 0;
}
#endif

#if 0
int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	char filename[256] = "test_crypto_kern.bpf.o";
	int ret, map_fd;
	int key, value[10];

	printf("hello!\n");
	obj = bpf_object__open_file(filename, NULL);
	ret = libbpf_get_error(obj);
	if (ret) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		obj = NULL;
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_md5");
	if (!prog) {
		fprintf(stderr, "ERROR: find a prog in obj file failed\n");
		goto out_prog;
	}

	/* load BPF program */
	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		fprintf(stderr, "ret:%d\n", ret);
		goto out_prog;
	}
	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "array_map", sizeof(int),
				sizeof(__s64), 10, NULL);
	if (map_fd == -1) {
		fprintf(stderr, "ERROR: create map failed (%s)\n",
			strerror(errno));
		goto out_prog;
	}
	ret = bpf_map_lookup_elem(map_fd, &key, value);
	for (int i = 0; i < 10; i++) {
		printf("[%d]: 0x%x\n", i, value[i]);
	}
	printf("hello end!\n");
	close(map_fd);
out_prog:
	bpf_object__close(obj);
out:
	return ret;
}
#endif

#if 1
#include "test_crypto_kern.skel.h"

typedef char stringkey[64];
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

int rb_event(void *ctx, void *data, size_t data_sz)
{
	return 0;
}

size_t load_test_data(void *dst)
{
	void *p;
	char *src = "hello world";
	size_t size = strlen(src);

	memset(dst, 0, BPF_RINGBUF_HDR_SZ);
	p = dst + BPF_RINGBUF_HDR_SZ;
	memcpy(p, src, size);
	*(__u32 *)dst = size;

	return size;
}

int drain_md5(void)
{
	syscall(__NR_getpgid);
	return 0;
}

int main(int argc, char **argv)
{
	struct test_crypto_kern *skel;
	struct user_ring_buffer *rb_data = NULL;
	struct ring_buffer *rb_digest = NULL;
	int err, urb_fd, krb_fd;
	int urb_size = 256 * 1024;
	__u64 /* *cons_pos_ptr, */*prod_pos_ptr;
	void *data_ptr;
	size_t size = 0;
	char words[] = "start to calculate md5";

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = test_crypto_kern__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return -EFAULT;
	}

	err = test_crypto_kern__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = test_crypto_kern__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* create ring buffer */
	urb_fd = bpf_map__fd(skel->maps.user_rb);
	rb_data = user_ring_buffer__new(urb_fd, NULL);
	if (!rb_data) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create user ringbuf\n");
		goto cleanup_urb;
	}
	krb_fd = bpf_map__fd(skel->maps.kern_rb);
	rb_digest = ring_buffer__new(krb_fd, rb_event, NULL, NULL);
	if (!rb_digest) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup_krb;
	}
	data_ptr = user_ring_buffer__reserve(rb_data, strlen(words));
	fprintf(stderr, "#urb_fd:%d, krb_fd:%d, data_ptr:0x%llx\n", urb_fd, krb_fd, (__u64)data_ptr);
	memcpy(data_ptr, words, strlen(words));
	user_ring_buffer__submit(rb_data, data_ptr);
	drain_md5();
	return 0;

	/* map the producer_pos as RW */
	/* cons_pos can be mapped R/O, can't add +X with mprotect. */
	/*
	cons_pos_ptr = mmap(NULL, urb_size, PROT_READ, MAP_SHARED, urb_fd, 0);
	if (!cons_pos_ptr) {
		err = -EINVAL;
		fprintf(stderr, "Failed to mmap cons_pos_ptr\n");
		goto cleanup_map;
	}
	fprintf(stderr, "#cons_pos_ptr:%p\n", cons_pos_ptr);
	*/
	prod_pos_ptr = mmap(NULL, urb_size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, urb_fd, urb_size);
	if (!prod_pos_ptr) {
		err = -EINVAL;
		fprintf(stderr, "Failed to mmap prod_pos_ptr\n");
		goto cleanup_map2;
	}
	fprintf(stderr, "#prod_pos_ptr:%p\n", prod_pos_ptr);
	data_ptr = mmap(NULL, urb_size, PROT_WRITE, MAP_SHARED, urb_fd, urb_size);
	if (!data_ptr) {
		err = -EINVAL;
		fprintf(stderr, "Failed to mmap data_ptr\n");
		goto cleanup_map3;
	}
	fprintf(stderr, "data_ptr:0x%lx\n", (long unsigned int)data_ptr);

	size = load_test_data(data_ptr);
	fprintf(stderr, "size:%ld\n", size);

	/*
	 * Synchronize with smp_load_acquire() in __bpf_user_ringbuf_peek()
	 * in the kernel.
	 */
	smp_store_release(prod_pos_ptr, size + BPF_RINGBUF_HDR_SZ);
	drain_md5();

	/* set up ring buffer polling */
	/*
	stringkey key = "execve_counter";
	__u64 v = 0;
	fprintf(stderr, "#%s, %d\n", __func__, __LINE__);
	err = bpf_map__update_elem(skel->maps.execve_counter, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the counter, %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "#%s, %d\n", __func__, __LINE__);
	err = test_crypto_kern__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	fprintf(stderr, "#%s, %d\n", __func__, __LINE__);
	for (;;) {
		fprintf(stderr, "#%s, %d\n", __func__, __LINE__);
		err = bpf_map__lookup_elem(skel->maps.execve_counter, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Lookup key from map error: %d\n", err);
			goto cleanup;
		} else {
			printf("execve_counter is %llu\n", v);
		}
		sleep(5);
	}
	*/
cleanup_map3:
	munmap(prod_pos_ptr, urb_size);
cleanup_map2:
//	munmap(cons_pos_ptr, urb_size);
//cleanup_map:
	ring_buffer__free(rb_digest);
cleanup_krb:
	user_ring_buffer__free(rb_data);
cleanup_urb:
	test_crypto_kern__detach(skel);
cleanup:
	test_crypto_kern__destroy(skel);
	return err;
}
/*
int main(int argc, char **argv)
{
	struct test_crypto_kern *skel;
	int ret, key, value;

	libbpf_set_print(libbpf_print_fn);

	skel = test_crypto_kern__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return -EFAULT;
	}

	ret = test_crypto_kern__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto out;
	}

	ret = test_crypto_kern__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto out;
	}
	key = 0;
	value = 0xa5a5;
	ret = bpf_map__update_elem(skel->maps.hash_map, &key, sizeof(key),
				   &value, sizeof(value), BPF_ANY);
	if (ret) {
		fprintf(stderr, "Failed to init value\n");
		goto out;
	}
	for (;;) {
		ret = bpf_map__lookup_elem(skel->maps.hash_map, &key, sizeof(key),
					   &value, sizeof(value), BPF_ANY);
		printf("key:%d, value:%d\n", key, value);
		if (value == 0x55)
			break;
		sleep(1);
	}
	key = 1;
	ret = bpf_map__lookup_elem(skel->maps.hash_map, &key, sizeof(key),
				   &value, sizeof(value), BPF_ANY);
	printf("key:%d, value:%d\n", key, value);
	test_crypto_kern__destroy(skel);
	return 0;
out:
	test_crypto_kern__destroy(skel);
	return ret;
}
*/
#endif
