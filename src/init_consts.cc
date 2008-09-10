// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file init_consts.cc Definition of the function init_consts.
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

#ifndef USE_PCH
#include "sys.h"
#include <cassert>
#include "debug.h"
#endif

#include "globals.h"
#include "superblock.h"
#include "forward_declarations.h"
#include "init_consts.h"
#include "conversion.h"

//-----------------------------------------------------------------------------
//
// Initialization
//

void init_consts()
{
  // Sanity checks.
  assert(super_block.s_magic == 0xEF53);	// EXT3.
  assert(super_block.s_creator_os == 0);	// Linux.
  assert(super_block.s_block_group_nr == 0);	// First super block.

  // Frequently used constants.
  groups_ = groups(super_block);
  block_size_ = block_size(super_block);
  block_size_log_ = EXT3_BLOCK_SIZE_BITS(&super_block);
  inodes_per_group_ = inodes_per_group(super_block);
  inode_size_ = inode_size(super_block);
  inode_count_ = inode_count(super_block);
  block_count_ = block_count(super_block);
#if USE_MMAP
  page_size_ = sysconf(_SC_PAGESIZE);
#endif

  // More sanity checks.
  assert((uint32_t)groups_ * inodes_per_group(super_block) == inode_count_);	// All inodes belong to a group.
  // extX does not support block fragments.
  // "File System Forensic Analysis, chapter 14, Overview --> Blocks"
  assert(block_size_ == fragment_size(super_block));
  // The inode bitmap has to fit in a single block.
  assert(inodes_per_group(super_block) <= 8 * block_size_);
  // The rest of the code assumes that sizeof(Inode) is a power of 2.
  assert(sizeof(Inode) == 128);
  // inode_size is expected to be (at least) the size of Inode.
  assert((size_t)inode_size_ >= sizeof(Inode));
  // Each inode must fit within one block.
  assert(inode_size_ <= block_size_);
  // inode_size must be a power of 2.
  assert(!((inode_size_ - 1) & inode_size_));
  // There should fit exactly an integer number of inodes in one block.
  assert((block_size_ / inode_size_) * inode_size_ == block_size_);
  // Space needed for the inode table should match the returned value of the number of blocks they need.
  assert((inodes_per_group_ * inode_size_ - 1) / block_size_ + 1 == inode_blocks_per_group(super_block));
  // File system must have a journal.
  assert((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL));
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_DIR_PREALLOC))
    std::cout << "WARNING: I don't know what EXT3_FEATURE_COMPAT_DIR_PREALLOC is.\n";
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_IMAGIC_INODES))
    std::cout << "WARNING: I don't know what EXT3_FEATURE_COMPAT_IMAGIC_INODES is (sounds scary).\n";
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_EXT_ATTR))
    std::cout << "WARNING: I don't know what EXT3_FEATURE_COMPAT_EXT_ATTR is.\n";
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_COMPRESSION))
    std::cout << "WARNING: I don't know what EXT3_FEATURE_INCOMPAT_COMPRESSION is (Houston, we have problem).\n";
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER))
  {
    std::cout << "WARNING: EXT3_FEATURE_INCOMPAT_RECOVER is set. "
        "This either means that your partition is still mounted, and/or the file system is in an unclean state.\n";
  }
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_JOURNAL_DEV))
    std::cout << "WARNING: I don't know what EXT3_FEATURE_INCOMPAT_JOURNAL_DEV is, but it doesn't sound good!\n";
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_META_BG))
    std::cout << "WARNING: I don't know what EXT3_FEATURE_INCOMPAT_META_BG is.\n";

  // Initialize accept bitmasks.
  init_accept();

  // Global arrays.
  reserved_memory = new char [50000];				// This is freed in dump_backtrace_on to make sure we have enough memory.
  inodes_buf = new char[inodes_per_group_ * inode_size_];

  // Global arrays of pointers.
  all_inodes = new Inode const* [groups_];
#if USE_MMAP
  // We use this array to know of which groups we mmapped, therefore zero it out.
  std::memset(all_inodes, 0, sizeof(Inode*) * groups_);
  all_mmaps = new void* [groups_];
  nr_mmaps = 0;
  refs_to_mmap = new int [groups_];
  // We use this array to know of which mmap inodes are being used, therefore zero it out.
  std::memset(refs_to_mmap, 0, sizeof(int) * groups_);
#endif
  block_bitmap = new bitmap_t* [groups_];
  // We use this array to know of which groups we loaded the metadata. Therefore zero it out.
  std::memset(block_bitmap, 0, sizeof(bitmap_t*) * groups_);
  inode_bitmap = new bitmap_t* [groups_];

  // Initialize group_descriptor_table.

  // Calculate the block where the group descriptor table starts.
  int const super_block_block = SUPER_BLOCK_OFFSET / block_size(super_block);
  // The block following the superblock is the group descriptor table.
  int const group_descriptor_table_block = super_block_block + 1;

  // Allocate group descriptor table.
  ASSERT(EXT3_DESC_PER_BLOCK(&super_block) * sizeof(ext3_group_desc) == (size_t)block_size_);
  group_descriptor_table = new ext3_group_desc[groups_];

  device.seekg(block_to_offset(group_descriptor_table_block));
  ASSERT(device.good());
  device.read(reinterpret_cast<char*>(group_descriptor_table), sizeof(ext3_group_desc) * groups_);
  ASSERT(device.good());
}
