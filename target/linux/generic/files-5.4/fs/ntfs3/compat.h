/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/overflow.h>

#ifndef __bitmap_set
#define __bitmap_set(a, b, c)	bitmap_set(a, b, c)
#endif

#ifndef __bitmap_clear
#define __bitmap_clear(a, b, c)	bitmap_clear(a, b, c)
#endif

/*
 * Copy from include/linux/compiler_attributes.h
 */
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef fallthrough
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough do {} while (0)  /* fallthrough */
#endif
#endif

/*
 * Copy from include/linux/build_bug.h
 */
#ifndef static_assert
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#endif

/*
 * Copy from include/linux/overflow.h
 */
#ifndef struct_size
#define struct_size(p, member, n) (sizeof(*(p)) + n * sizeof(*(p)->member))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
static inline void *__compat_kvmalloc(size_t size, gfp_t flags)
{
	gfp_t kmalloc_flags = flags;
	void *ret;
	if (size > PAGE_SIZE) {
		kmalloc_flags |= __GFP_NOWARN;
		if (!(kmalloc_flags & __GFP_REPEAT) || (size <= PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER))
			kmalloc_flags |= __GFP_NORETRY;
	}
	ret = kmalloc(size, kmalloc_flags);
	if (ret || size <= PAGE_SIZE)
		return ret;
	return __vmalloc(size, flags, PAGE_KERNEL);
}
static inline void *__compat_kvzalloc(size_t size, gfp_t flags)
{
	return __compat_kvmalloc(size, flags | __GFP_ZERO);
}
#define kvmalloc __compat_kvmalloc
#define kvzalloc __compat_kvzalloc
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
static inline void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;

	return kvmalloc(bytes, flags);
}
#endif

#ifndef PAGE_KERNEL_RO
#define PAGE_KERNEL_RO PAGE_KERNEL
#endif

/* MS flags were renamed to SB on v4.14 */
#ifndef SB_NODIRATIME
#define SB_NODIRATIME MS_NODIRATIME
#endif

#ifndef SB_RDONLY
#define SB_RDONLY MS_RDONLY
#endif

#ifndef SB_ACTIVE
#define SB_ACTIVE MS_ACTIVE
#endif

#ifndef SB_SYNCHRONOUS
#define SB_SYNCHRONOUS MS_SYNCHRONOUS
#endif

#ifndef SB_POSIXACL
#define SB_POSIXACL MS_POSIXACL
#endif

#ifndef SB_LAZYTIME
#define SB_LAZYTIME MS_LAZYTIME
#endif

#ifndef SB_NOATIME
#define SB_NOATIME MS_NOATIME
#endif

#if !defined(sb_rdonly)
#define sb_rdonly(sb) ((sb)->s_flags & MS_RDONLY)
#endif

#if !defined(bio_set_dev)
#define bio_set_dev(bio, bdev) do { (bio)->bi_bdev = (bdev); } while(0);
#endif

#if !defined(BIO_MAX_VECS)
#define BIO_MAX_VECS BIO_MAX_PAGES
#endif

#if !defined(copy_page_from_iter_atomic)
#define copy_page_from_iter_atomic(page, off, min, from) \
	iov_iter_copy_from_user_atomic((page), (from), (off), (min))
#endif

#if !defined(fault_in_iov_iter_readable)
#define fault_in_iov_iter_readable(from, bytes) \
	iov_iter_fault_in_readable((from), (bytes))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 86)
static inline size_t __must_check size_add(size_t addend1, size_t addend2)
{
	size_t bytes;

	if (check_add_overflow(addend1, addend2, &bytes))
		return SIZE_MAX;

	return bytes;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#include <linux/fs.h>
static inline unsigned char fs_umode_to_dtype(umode_t mode)
{
	if (S_ISREG(mode))
		return DT_REG;
	if (S_ISLNK(mode))
		return DT_LNK;
	if (S_ISFIFO(mode))
		return DT_FIFO;
	if (S_ISCHR(mode))
		return DT_CHR;
	if (S_ISBLK(mode))
		return DT_BLK;
	if (S_ISSOCK(mode))
		return DT_SOCK;

	return DT_UNKNOWN;
}
#endif
