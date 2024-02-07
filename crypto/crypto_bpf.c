// SPDX-License-Identifier: GPL-2.0
// crypto_bpf.c

#include <crypto/hash.h>
#include <linux/bpf.h>
#include <linux/filter.h>

const struct bpf_prog_ops crypto_shash_prog_ops = {
};

BPF_CALL_3(bpf_crypto_alloc_shash, const char *, alg_name, u32, type, u32, mask)
{
	return (u64)crypto_alloc_shash(alg_name, type, mask);
}

const struct bpf_func_proto bpf_crypto_alloc_shash_proto = {
	.func		= bpf_crypto_alloc_shash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CONST_STR | MEM_RDONLY,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_crypto_free_shash, u64, tfm)
{
	struct crypto_shash *shash = (struct crypto_shash *)tfm;

	crypto_free_shash(shash);
	return 0;
}

const struct bpf_func_proto bpf_crypto_free_shash_proto = {
	.func		= bpf_crypto_free_shash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_crypto_shash_init, u64, handle)
{
	struct shash_desc *desc = (struct shash_desc *)handle;

	return crypto_shash_init(desc);
}

const struct bpf_func_proto bpf_crypto_shash_init_proto = {
	.func		= bpf_crypto_shash_init,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_crypto_shash_update, u64, handle, const u8 *, data,
	   unsigned int, len)
{
	struct shash_desc *desc = (struct shash_desc *)handle;

	if (!len)
		return -EINVAL;
	return crypto_shash_update(desc, data, len);
}

const struct bpf_func_proto bpf_crypto_shash_update_proto = {
	.func		= bpf_crypto_shash_update,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_crypto_shash_final, u64, handle, void *, out)
{
	struct shash_desc *desc = (struct shash_desc *)handle;
	int ret;

	ret = crypto_shash_final(desc, (u8 *)out);
	vfree(desc);
	return ret;
}

const struct bpf_func_proto bpf_crypto_shash_final_proto = {
	.func		= bpf_crypto_shash_final,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM,
};

BPF_CALL_4(bpf_crypto_shash_digest, u64, handle, const u8 *, data,
	   unsigned int, len, void *, out)
{
	struct shash_desc *desc = (struct shash_desc *)handle;

	return crypto_shash_digest(desc, data, len, out);
}

const struct bpf_func_proto bpf_crypto_shash_digest_proto = {
	.func		= bpf_crypto_shash_digest,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
};

BPF_CALL_1(bpf_crypto_shash_digestsize, u64, tfm)
{
	struct crypto_shash *shash = (struct crypto_shash *)tfm;

	return crypto_shash_digestsize(shash);
}

const struct bpf_func_proto bpf_crypto_shash_digestsize_proto = {
	.func		= bpf_crypto_shash_digestsize,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_crypto_shash_setkey, u64, tfm, const u8 *, key,
	   unsigned int, keylen)
{
	struct crypto_shash *shash = (struct crypto_shash *)tfm;

	return crypto_shash_setkey(shash, key, keylen);
}

const struct bpf_func_proto bpf_crypto_shash_setkey_proto = {
	.func		= bpf_crypto_shash_setkey,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_ANYTHING,
};

const struct bpf_func_proto *
crypto_shash_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_crypto_alloc_shash:
		return &bpf_crypto_alloc_shash_proto;
	case BPF_FUNC_crypto_free_shash:
		return &bpf_crypto_free_shash_proto;
	case BPF_FUNC_crypto_shash_init:
		return &bpf_crypto_shash_init_proto;
	case BPF_FUNC_crypto_shash_update:
		return &bpf_crypto_shash_update_proto;
	case BPF_FUNC_crypto_shash_final:
		return &bpf_crypto_shash_final_proto;
	case BPF_FUNC_crypto_shash_digest:
		return &bpf_crypto_shash_digest_proto;
	case BPF_FUNC_crypto_shash_digestsize:
		return &bpf_crypto_shash_digestsize_proto;
	case BPF_FUNC_crypto_shash_setkey:
		return &bpf_crypto_shash_setkey_proto;
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_map_push_elem:
		return &bpf_map_push_elem_proto;
	case BPF_FUNC_map_pop_elem:
		return &bpf_map_pop_elem_proto;
	case BPF_FUNC_map_peek_elem:
		return &bpf_map_peek_elem_proto;
	case BPF_FUNC_trace_printk:
		if (perfmon_capable())
			return bpf_get_trace_printk_proto();
		fallthrough;
	default:
		return NULL;
	}
}

const struct bpf_verifier_ops crypto_shash_verifier_ops = {
	.get_func_proto  = crypto_shash_func_proto,
};

int crypto_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	int ret = 0;

	if (attr->attach_flags)
		return -EINVAL;

	return ret;
}

int crypto_prog_detach(const union bpf_attr *attr)
{
	struct bpf_prog *prog;
	int ret = 0;

	if (attr->attach_flags)
		return -EINVAL;

	prog = bpf_prog_get_type(attr->attach_bpf_fd,
				 BPF_PROG_TYPE_CRYPTO_SHASH);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	bpf_prog_put(prog);

	return ret;
}

int crypto_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr)
{
	__u32 __user *prog_ids = u64_to_user_ptr(attr->query.prog_ids);
	struct bpf_prog_array *progs;
	u32 cnt, flags = 0;
	int ret = 0;

	if (attr->query.query_flags)
		return -EINVAL;
	return ret;
}
