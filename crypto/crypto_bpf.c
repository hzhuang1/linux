// SPDX-License-Identifier: GPL-2.0
// crypto_bpf.c

#include <crypto/hash.h>
#include <linux/bpf.h>
#include <linux/filter.h>

const struct bpf_prog_ops crypto_shash_prog_ops = {
};

struct shash_digest_size {
	union {
		char buf[32];
	};
};

BPF_CALL_4(bpf_crypto_alloc_shash, const char *, alg_name,
	   u32, type, u32, mask, u64 *, handle)
{
	struct crypto_shash *shash = NULL;
	struct shash_desc *sdesc = NULL;
	int size;
	long ret;

	if (!handle)
		return -EINVAL;
	shash = crypto_alloc_shash(alg_name, type, mask);
	if (IS_ERR(shash)) {
		ret = PTR_ERR(shash);
		goto out;
	}
	size = sizeof(struct shash_desc) + crypto_shash_descsize(shash);
	sdesc = kzalloc(size, GFP_KERNEL);
	if (!sdesc) {
		goto out_sdesc;
	}
	sdesc->tfm = shash;
	ret = crypto_shash_init(sdesc);
	*handle = (unsigned long)sdesc;
	return ret;
out_sdesc:
	crypto_free_shash(shash);
out:
	return ret;
}

const struct bpf_func_proto bpf_crypto_alloc_shash_proto = {
	.func		= bpf_crypto_alloc_shash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CONST_STR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_LONG,
};

BPF_CALL_1(bpf_crypto_free_shash, u64, handle)
{
	struct shash_desc *sdesc;
	struct crypto_shash *shash;

	if (handle == 0)
		return -EINVAL;
	sdesc = (struct shash_desc *)handle;
	shash = sdesc->tfm;
	crypto_free_shash(shash);
	kfree(sdesc);
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

BPF_CALL_3(bpf_crypto_shash_update, u64, handle, const void *, data,
	   size_t, len)
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

BPF_CALL_3(bpf_crypto_shash_final, u64, handle, void *, out,
	   size_t, len)
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
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_5(bpf_crypto_shash_digest, u64, handle, void *, data,
	   size_t, len, void *, out, size_t, size)
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
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_1(bpf_crypto_shash_digestsize, u64, handle)
{
	struct crypto_shash *shash = (struct crypto_shash *)handle;

	return crypto_shash_digestsize(shash);
}

const struct bpf_func_proto bpf_crypto_shash_digestsize_proto = {
	.func		= bpf_crypto_shash_digestsize,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_crypto_shash_setkey, u64, handle, const void *, key,
	   size_t, keylen)
{
	struct crypto_shash *shash = (struct crypto_shash *)handle;

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
	/*
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
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_trace_vprintk:
		return bpf_get_trace_vprintk_proto();
	*/
	default:
		return bpf_base_func_proto(func_id);
	}
}

static bool crypto_shash_is_valid_access(int off, int size,
					 enum bpf_access_type type,
					 const struct bpf_prog *prog,
					 struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= U16_MAX)
		return false;
	if (off % size != 0)
		return false;
	return true;
}

const struct bpf_verifier_ops crypto_shash_verifier_ops = {
	.get_func_proto  = crypto_shash_func_proto,
	.is_valid_access = crypto_shash_is_valid_access,
};

int crypto_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	int ret = 0;

	if (attr->attach_flags)
		return -EINVAL;

	pr_err("#%s, %d\n", __func__, __LINE__);
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
