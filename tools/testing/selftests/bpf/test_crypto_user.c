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

#include <linux/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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

int main(int argc, char **argv)
{
	struct test_crypto_kern *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = test_crypto_kern__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = test_crypto_kern__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	stringkey key = "execve_counter";
	__u64 v = 0;
	err = bpf_map__update_elem(skel->maps.execve_counter, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "Failed to init the counter, %d\n", err);
		goto cleanup;
	}

	err = test_crypto_kern__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	for (;;) {
		err = bpf_map__lookup_elem(skel->maps.execve_counter, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Lookup key from map error: %d\n", err);
			goto cleanup;
		} else {
			printf("execve_counter is %llu\n", v);
		}
		sleep(5);
	}
cleanup:
	test_crypto_kern__destroy(skel);
	return -err;
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
