// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file superblock.h Superblock accessors.
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

#ifndef SUPERBLOCK_H
#define SUPERBLOCK_H

#include "endian_conversion.h"

// Super block accessors.
inline int inode_count(ext3_super_block const& super_block) { return super_block.s_inodes_count; }
inline int block_count(ext3_super_block const& super_block) { return super_block.s_blocks_count; }
inline int reserved_block_count(ext3_super_block const& super_block) { return super_block.s_r_blocks_count; }
inline int first_data_block(ext3_super_block const& super_block) { return super_block.s_first_data_block; }
inline int block_size(ext3_super_block const& super_block) { return EXT3_BLOCK_SIZE(&super_block); }
inline int fragment_size(ext3_super_block const& super_block) { return EXT3_FRAG_SIZE(&super_block); }
inline int blocks_per_group(ext3_super_block const& super_block) { return EXT3_BLOCKS_PER_GROUP(&super_block); }
inline int inodes_per_group(ext3_super_block const& super_block) { return EXT3_INODES_PER_GROUP(&super_block); }
inline int first_inode(ext3_super_block const& super_block) { return EXT3_FIRST_INO(&super_block); }
inline int inode_size(ext3_super_block const& super_block) { return EXT3_INODE_SIZE(&super_block); }
inline int inode_blocks_per_group(ext3_super_block const& super_block) { return inodes_per_group(super_block) * inode_size(super_block) / block_size(super_block); }
inline int groups(ext3_super_block const& super_block) { return inode_count(super_block) / inodes_per_group(super_block); }

// Journal superblock accessor.
inline int block_count(journal_superblock_t const& journal_super_block) { return be2le(journal_super_block.s_maxlen); }

#endif // SUPERBLOCK_H
