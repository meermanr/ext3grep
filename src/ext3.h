// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file ext3.h Declaration of ext3 types and macros.
//
// Copyright (C) 2008, by
// 
// Carlo Wood, Run on IRC <carlo@alinoe.com>
// RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
// Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#define USE_KERNEL_HEADERS 0

#ifndef EXT3_H
#define EXT3_H

#if USE_KERNEL_HEADERS

// We're NOT supposed to use kernel headers at all,
// so we have to do a few really dirty things to
// make it work.
#define cpu_to_le32 __cpu_to_le32
#define cpu_to_le16 __cpu_to_le16
#define le16_to_cpu __le16_to_cpu
#define BUG() (void)0
typedef unsigned int gfp_t;
extern int get_order(unsigned long size);
extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
extern void free_pages(unsigned long addr, unsigned int order);

#include <linux/byteorder/little_endian.h>
#include <linux/ext3_fs.h>
#include <linux/jbd.h>				// This includes "jfs_compat.h"
#include <linux/limits.h>

#else // !USE_KERNEL_HEADERS

// Use the header files from e2progs (http://e2fsprogs.sourceforge.net)
// We can use these headers and then everything named ext2 or ext3.
#include <ext2fs/ext2_fs.h>			// Definitions of ext2, ext3 and ext4.

// All of the following is backwards compatible, so we can use the EXT2 versions.
#define EXT3_BLOCK_SIZE		EXT2_BLOCK_SIZE
#define EXT3_FRAG_SIZE		EXT2_FRAG_SIZE
#define EXT3_BLOCKS_PER_GROUP	EXT2_BLOCKS_PER_GROUP
#define EXT3_INODES_PER_GROUP	EXT2_INODES_PER_GROUP
#define EXT3_FIRST_INO		EXT2_FIRST_INO
#define EXT3_INODE_SIZE		EXT2_INODE_SIZE
#define EXT3_BLOCK_SIZE_BITS	EXT2_BLOCK_SIZE_BITS
#define EXT3_DESC_PER_BLOCK	EXT2_DESC_PER_BLOCK
#define EXT3_DIR_ROUND		EXT2_DIR_ROUND
#define EXT3_DIR_REC_LEN	EXT2_DIR_REC_LEN
#define EXT3_FT_DIR		EXT2_FT_DIR
#define EXT3_FT_UNKNOWN		EXT2_FT_UNKNOWN
#define EXT3_FT_MAX		EXT2_FT_MAX
#define EXT3_MAX_BLOCK_SIZE	EXT2_MAX_BLOCK_SIZE
#define EXT3_NDIR_BLOCKS	EXT2_NDIR_BLOCKS
#define EXT3_IND_BLOCK		EXT2_IND_BLOCK
#define EXT3_DIND_BLOCK		EXT2_DIND_BLOCK
#define EXT3_TIND_BLOCK		EXT2_TIND_BLOCK
#define EXT3_VALID_FS		EXT2_VALID_FS
#define EXT3_ERROR_FS		EXT2_ERROR_FS
#define EXT3_FT_REG_FILE	EXT2_FT_REG_FILE
#define EXT3_FT_CHRDEV		EXT2_FT_CHRDEV
#define EXT3_FT_BLKDEV		EXT2_FT_BLKDEV
#define EXT3_FT_FIFO		EXT2_FT_FIFO
#define EXT3_FT_SOCK		EXT2_FT_SOCK
#define EXT3_FT_SYMLINK		EXT2_FT_SYMLINK
#define EXT3_N_BLOCKS		EXT2_N_BLOCKS
#define EXT3_DIR_PAD		EXT2_DIR_PAD
typedef ext2_super_block ext3_super_block;
typedef ext2_group_desc ext3_group_desc;
typedef ext2_inode ext3_inode;
typedef ext2_dir_entry_2 ext3_dir_entry_2;

// Get declaration of journal_superblock_t
#include <ext2fs/ext2fs.h>
// This header is a copy from e2fsprogs-1.40.7 except that the type
// of 'journal_revoke_header_t::r_count' was changed from int to __s32.
#include "kernel-jbd.h"

#endif // !USE_KERNEL_HEADERS

// This (POD) struct protects it's members so we
// can do access control for debugging purposes.

struct Inode : protected ext3_inode {
  public:
    __u16 mode(void) const { return i_mode; }
    __u16 uid_low(void) const { return i_uid_low; }
    __u32 size(void) const { return i_size; }
    __u32 atime(void) const { return i_atime; }
    __u32 ctime(void) const { return i_ctime; }
    __u32 mtime(void) const { return i_mtime; }
    __u32 dtime(void) const { return i_dtime; }
    __u16 gid_low(void) const { return i_gid_low; }
    __u16 links_count(void) const { return i_links_count; }
    __u32 blocks(void) const { return i_blocks; }
    __u32 flags(void) const { return i_flags; }
    __u32 const* block(void) const { return i_block; }
    __u32 generation(void) const { return i_generation; }
    __u32 file_acl(void) const { return i_file_acl; }
    __u32 dir_acl(void) const { return i_dir_acl; }
    __u32 faddr(void) const { return i_faddr; }
    __u16 uid_high(void) const { return i_uid_high; }
    __u16 gid_high(void) const { return i_gid_high; }
    __u32 reserved2(void) const { return i_reserved2; }

    void set_reserved2(__u32 val) { i_reserved2 = val; }
};

#endif // EXT3_H
