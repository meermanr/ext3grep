// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file globals.h Declaration of global variables.
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

#ifndef GLOBALS_H
#define GLOBALS_H

#ifndef USE_PCH
#include <stdint.h>	// Needed for uint32_t
#include <fstream>	// Needed for std::ifstream
#include <string>	// Needed for std::string
#endif

#include "ext3.h"	// Needed for ext3_super_block, ext3_group_desc and Inode
#include "bitmap.h"	// Needed for bitmap_t

// The superblock.
extern ext3_super_block super_block;

// Frequently used constant values from the superblock.
extern int groups_;
extern int block_size_;
extern int block_size_log_;
extern int inodes_per_group_;
extern int inode_size_;
extern uint32_t inode_count_;
extern uint32_t block_count_;

// The journal super block.
extern journal_superblock_t journal_super_block;
// Frequently used constant values from the journal superblock.
extern int journal_block_size_;
extern int journal_maxlen_;
extern int journal_first_;
extern int journal_sequence_;
extern int journal_start_;
extern Inode journal_inode;

// Globally used variables.
extern char const* progname;
extern std::ifstream device;
#if USE_MMAP
extern int device_fd;
extern long page_size_;
extern void** all_mmaps;
extern int* refs_to_mmap;
extern int nr_mmaps;
#endif
extern char* reserved_memory;
extern Inode const** all_inodes;
extern bitmap_t** block_bitmap;
extern bitmap_t** inode_bitmap;
extern char* inodes_buf;
extern ext3_group_desc* group_descriptor_table;
extern int no_filtering;
extern std::string device_name;
extern bool feature_incompat_filetype;
extern uint32_t wrapped_journal_sequence;

#endif // GLOBALS_H
