// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file globals.cc Definitions of the global variables used in the application.
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
#include <stdint.h>
#include <fstream>
#include "ext3.h"
#endif

#include "bitmap.h"

// The superblock.
ext3_super_block super_block;
// Frequently used constant values from the superblock.
int groups_;
int block_size_;
int block_size_log_;
int inodes_per_group_;
int inode_size_;
uint32_t inode_count_;
uint32_t block_count_;

// The journal super block.
journal_superblock_t journal_super_block;
// Frequently used constant values from the journal superblock.
int journal_block_size_;
int journal_maxlen_;
int journal_first_;
int journal_sequence_;
int journal_start_;
Inode journal_inode;

// Globally used variables.
char const* progname;
std::ifstream device;
#if USE_MMAP
int device_fd;
long page_size_;
void** all_mmaps;
int* refs_to_mmap;
int nr_mmaps;
#endif
char* reserved_memory;
Inode const** all_inodes;
bitmap_t** block_bitmap;
bitmap_t** inode_bitmap;
char* inodes_buf;
ext3_group_desc* group_descriptor_table;
int no_filtering = 0;
std::string device_name;
bool feature_incompat_filetype = false;
uint32_t wrapped_journal_sequence = 0;

