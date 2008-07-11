// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file is_blockdetection.h Various is_* test functions.
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

#ifndef IS_BLOCKDETECTION_H
#define IS_BLOCKDETECTION_H

#ifndef USE_PCH
#include <stdint.h>	// Needed for uint32_t
#include <iosfwd>	// Needed for std::ostream
#endif

#include "inode.h"	// Needed for InodePointer

// Return type of is_directory.
enum is_directory_type {
  isdir_no = 0,         // Block is not a directory.
  isdir_start,          // Block is a directory containing "." and "..".
  isdir_extended        // Block is a directory not containing "." and "..".
};

class DirectoryBlockStats {
  private:
    int M_number_of_entries;			// Number of entries in chain to the end.
    __u8 M_unlikely_character_count[256];	// Character count of filenames.
  public:
    DirectoryBlockStats(void) { std::memset(this, 0, sizeof(DirectoryBlockStats)); }

    int number_of_entries(void) const { return M_number_of_entries; }
    void increment_number_of_entries(void) { ++M_number_of_entries; }
    void increment_unlikely_character_count(__u8 c) { ++M_unlikely_character_count[c]; }
};

// Return true if this inode is a directory.
inline bool is_directory(Inode const& inode)
{
  return (inode.mode() & 0xf000) == 0x4000;
}

// Same for an InodePointer.
inline bool is_directory(InodePointer const& inoderef)
{
  // We can dereference inoderef here because it is known that is_directory does not keep a pointer or reference to the inode.
  return is_directory(*inoderef);
}

// Return true if this inode is a symlink.
inline bool is_symlink(Inode const& inode)
{
  return (inode.mode() & 0xf000) == 0xa000;
}

// Same for an InodePointer.
inline bool is_symlink(InodePointer const& inoderef)
{
  // We can dereference inoderef here because it is known that is_symlink does not keep a pointer or reference to the inode.
  return is_symlink(*inoderef);
}

// Return true if this inode is a regular file.
inline bool is_regular_file(Inode const& inode)
{
  return (inode.mode() & 0xf000) == 0x8000;
}

// Same for an InodePointer.
inline bool is_regular_file(InodePointer const& inoderef)
{
  // We can dereference inoderef here because it is known that is_regular_file does not keep a pointer or reference to the inode.
  return is_regular_file(*inoderef);
}

inline bool is_block_number(uint32_t block_number)
{
  return block_number < block_count_;
}

inline bool is_data_block_number(uint32_t block_number)
{
  return block_number < block_count_;	// FIXME: not all blocks contain data (ie, skip at least the inode tables).
}

int block_to_inode(int block);
bool is_inode(int block);
bool is_allocated(int inode);
int inode_to_block(ext3_super_block const& super_block, int inode);
void print_buf_to(std::ostream& os, char const* buf, int len);

#endif // IS_BLOCKDETECTION_H
