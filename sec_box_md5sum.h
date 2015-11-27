#ifndef __sec_box_md5sum_h__
#define __sec_box_md5sum_h__

#define MD5_BLOCK_WORDS		16
#define MD5_HASH_WORDS		4

#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#define F2(x, y, z)	F1(z, x, y)
#define F3(x, y, z)	(x ^ y ^ z)
#define F4(x, y, z)	(y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, in, s) \
	(w += f(x, y, z) + in, w = (w<<s | w>>(32-s)) + x)

struct md5_ctx
{
	u32 hash[MD5_HASH_WORDS];
	u32 block[MD5_BLOCK_WORDS];
	u64 byte_count;
};

struct sec_box_md5sum
{
	void (* init)(void *ctx);
	void (* update)(void *ctx, const u_char *data, uint len);
	void (* final)(void *ctx, u_char *out);
	int (* handler)(u8 * file, u8 * digest);
};
extern struct sec_box_md5sum sec_box_md5sum;

#endif
