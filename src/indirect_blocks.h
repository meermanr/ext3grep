// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file indirect_blocks.h Declaration of code related to indirect blocks.
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

#ifndef INDIRECT_BLOCKS_H
#define INDIRECT_BLOCKS_H

#ifndef USE_PCH
#include "ext3.h"
#endif

#include "inode.h"

// Constants used with iterate_over_all_blocks_of
unsigned int const direct_bit = 1;		// Call action() for real blocks.
unsigned int const indirect_bit = 2;		// Call action() for (double/tripple) indirect blocks.

void print_directory_action(int blocknr, void*);
bool iterate_over_all_blocks_of(Inode const& inode, void (*action)(int, void*), void* data = NULL, unsigned int indirect_mask = direct_bit, bool diagnose = false);
void find_block_action(int blocknr, void* ptr);

struct find_block_data_st {
  bool found_block;
  int block_looking_for;
};

inline bool iterate_over_all_blocks_of(InodePointer inode, void (*action)(int, void*), void* data = NULL,
    unsigned int indirect_mask = direct_bit, bool diagnose = false)
{
  // inode is dereferenced here in good faith that no reference to it is kept (since there are no structs or classes that do so).
  return iterate_over_all_blocks_of(*inode, action, data, indirect_mask, diagnose);
}

#endif // INDIRECT_BLOCKS_H
