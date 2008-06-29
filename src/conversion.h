// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file conversion.h Conversion functions.
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

#ifndef CONVERSION_H
#define CONVERSION_H

#include "superblock.h"
#include "globals.h"

// Convert byte-offset to block.
// Returns the block number that contains the byte at offset bytes from the start of the device file.
inline int offset_to_block(ext3_super_block const& super_block, off_t offset)
{
  return offset / block_size(super_block);
}

// Convert block number to group.
// Returns the group number of block.
inline int block_to_group(ext3_super_block const& super_block, int block)
{
  return (block - first_data_block(super_block)) / blocks_per_group(super_block);
}

// Convert group to block number.
// Returns the block number of the first block of a group.
inline int group_to_block(ext3_super_block const& super_block, int group)
{
  return first_data_block(super_block) + group * blocks_per_group(super_block);
}

// Convert inode number to group.
// Returns the group number of inode.
inline int inode_to_group(ext3_super_block const& super_block, int inode_number)
{
  return (inode_number - 1) / inodes_per_group(super_block);
}

// Convert block to byte-offset.
// Returns the offset (dd --seek) in the device file to the first byte of the block.
inline off_t block_to_offset(int block)
{
  off_t offset = block;
  offset <<= block_size_log_;
  return offset;
}

#endif // CONVERSION_H

