// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file load_meta_data.cc Implementation of the function load_meta_data.
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
#include "debug.h"
#endif

#include "globals.h"
#include "conversion.h"

//-----------------------------------------------------------------------------
//
// load_meta_data
//

#if !USE_MMAP
void load_inodes(int group)
{
  DoutEntering(dc::notice, "load_inodes(" << group << ")");
  if (!block_bitmap[group])
    load_meta_data(group);
  // The start block of the inode table.
  int block_number = group_descriptor_table[group].bg_inode_table;
  // Load all inodes of this group into memory.
  char* inode_table = new char[inodes_per_group_ * inode_size_];
  device.seekg(block_to_offset(block_number));
  ASSERT(device.good());
  device.read(inode_table, inodes_per_group_ * inode_size_);
  ASSERT(device.good());
  all_inodes[group] = new Inode[inodes_per_group_];
  // Copy the first 128 bytes of each inode into all_inodes[group].
  for (int i = 0; i < inodes_per_group_; ++i)
    std::memcpy(all_inodes[group][i], inode_table + i * inode_size_, sizeof(Inode));
  // Free temporary table again.
  delete [] inode_table;
#ifdef DEBUG
  // We set this, so that we can find back where an inode struct came from
  // during debugging of this program in gdb. It is not used anywhere.
  // Note that THIS is the only reason that !USE_MMAP exists: we can't write to a mmapped area.
  // Another solution would be to just allocate a seperate array for just this number, of course.
  for (int i = 0; i < inodes_per_group_; ++i)
    const_cast<Inode*>(all_inodes[group])[i].set_reserved2(i + 1 + group * inodes_per_group_);
#endif
}
#endif

void load_meta_data(int group)
{
  if (block_bitmap[group])	// Already loaded?
    return;
  DoutEntering(dc::notice, "load_meta_data(" << group << ")");
  // Load block bitmap.
  block_bitmap[group] = new bitmap_t[block_size_ / sizeof(bitmap_t)];
  device.seekg(block_to_offset(group_descriptor_table[group].bg_block_bitmap));
  ASSERT(device.good());
  device.read(reinterpret_cast<char*>(block_bitmap[group]), block_size_);
  ASSERT(device.good());
  // Load inode bitmap.
  inode_bitmap[group] = new bitmap_t[block_size_ / sizeof(bitmap_t)];
  device.seekg(block_to_offset(group_descriptor_table[group].bg_inode_bitmap));
  ASSERT(device.good());
  device.read(reinterpret_cast<char*>(inode_bitmap[group]), block_size_);
  ASSERT(device.good());
#if !USE_MMAP
  // Load all inodes into memory.
  load_inodes(group);
#endif
}
