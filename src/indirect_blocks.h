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
// Stanislaw T. Findeisen <sf181257 at students mimuw edu pl>
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
//
// ChangeLog
//
// 2008-07-07  STF
//     * (is_indirect_block): Add.

#ifndef INDIRECT_BLOCKS_H
#define INDIRECT_BLOCKS_H

#ifndef USE_PCH
#include "ext3.h"
#endif

#include "inode.h"

// Constants used with iterate_over_all_blocks_of
unsigned int const direct_bit = 1;		// Call action() for real blocks.
unsigned int const indirect_bit = 2;		// Call action() for (double/tripple) indirect blocks.
unsigned int const hole_bit = 4;		// Call action() for holes (blocknr will be 0).

void print_directory_action(int blocknr, int file_block_nr, void*);
bool iterate_over_all_blocks_of(Inode const& inode, int inode_number, void (*action)(int, int, void*), void* data = NULL, unsigned int indirect_mask = direct_bit, bool diagnose = false);
void find_block_action(int blocknr, int file_block_nr, void* ptr);

struct find_block_data_st {
  bool found_block;
  int block_looking_for;
};

inline bool iterate_over_all_blocks_of(InodePointer inode, int inode_number, void (*action)(int, int, void*), void* data = NULL,
    unsigned int indirect_mask = direct_bit, bool diagnose = false)
{
  // inode is dereferenced here in good faith that no reference to it is kept (since there are no structs or classes that do so).
  return iterate_over_all_blocks_of(*inode, inode_number, action, data, indirect_mask, diagnose);
}

/**
 *  Checks if a block is an indirect one.
 *
 *  WARNING THIS IS A HEURISTIC FUNCTION! A block can be classified as indirect
 *  when in fact it is not. That's because analysis is based solely on this single
 *  block contents.
 *
 *  Parameters:
 *    block_ptr - preloaded block contents (ie, 4096 bytes)
 *
 *  Returns true iff given block is of the form:
 *
 *    [b1], [b2], ... [bi], ... [bk] ZEROES
 *
 *  where 
 *    - 1 <= i <= k
 *    - [bi] are valid block numbers (is_data_block_number() returns true).
 *    - [bi] are all different.
 *    - [bi] != 0 for all i.
 */
bool is_indirect_block(unsigned char* block_ptr, bool verbose = false);

#endif // INDIRECT_BLOCKS_H
