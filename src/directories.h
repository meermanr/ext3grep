// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file directories.h Declaration of class Directory and related classes.
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

#ifndef DIRECTORIES_H
#define DIRECTORIES_H

#ifndef USE_PCH
#include <vector>
#include <list>
#include <string>
#include "ext3.h"
#include "debug.h"
#endif

class DirectoryBlock;
class Directory;

struct Index {
  int cur;	// Indicates the order in memory.
  int next;	// The index of the DirEntry that ext3_dir_entry_2::rec_len refers to or zero if it refers to the end.
};

struct DirEntry {
  std::list<DirectoryBlock>::const_iterator M_directory_iterator;	// Pointer to DirectoryBlock containing this entry.
  Directory* M_directory;						// Pointer to Directory, if this is a directory.
  int M_file_type;							// The dir entry file type.
  int M_inode;								// The inode referenced by this DirEntry.
  std::string M_name;							// The file name of this DirEntry.
  union {
    ext3_dir_entry_2 const* dir_entry;					// Temporary pointer into block_buf.
    Index index;							// Ordering index of dir entry.
  };
  bool deleted;								// Copies of values calculated by filter_dir_entry.
  bool allocated;
  bool reallocated;
  bool zero_inode;
  bool linked;
  bool filtered;

  bool exactly_equal(DirEntry const& de) const;
  void print(void) const;
};

class DirectoryBlock {
  private:
    int M_block;
    std::vector<DirEntry> M_dir_entry;
  public:
    void read_block(int block, std::list<DirectoryBlock>::iterator iter);
    void read_dir_entry(ext3_dir_entry_2 const& dir_entry, Inode const& inode,
        bool deleted, bool allocated, bool reallocated, bool zero_inode, bool linked, bool filtered, std::list<DirectoryBlock>::iterator iter);

    bool exactly_equal(DirectoryBlock const& dir) const;
    int block(void) const { return M_block; }
    void print(void) const;

    std::vector<DirEntry> const& dir_entries(void) const { return M_dir_entry; }
    std::vector<DirEntry>& dir_entries(void) { return M_dir_entry; }
};

class Directory {
  private:
    uint32_t M_inode_number;
    std::list<DirectoryBlock> M_blocks;
#ifdef DEBUG
    bool M_extended_blocks_added;
#endif

  public:
    Directory(uint32_t inode_number) : M_inode_number(inode_number)
#ifdef DEBUG
        , M_extended_blocks_added(false)
#endif
        { }
    Directory(uint32_t inode_number, int first_block);

  std::list<DirectoryBlock>& blocks(void) { return M_blocks; }
  std::list<DirectoryBlock> const& blocks(void) const { return M_blocks; }

  uint32_t inode_number(void) const { return M_inode_number; }
  int first_block(void) const { ASSERT(!M_blocks.empty()); return M_blocks.begin()->block(); }
#ifdef DEBUG
  bool extended_blocks_added(void) const { return M_extended_blocks_added; }

  void set_extended_blocks_added(void) { M_extended_blocks_added = true; }
#endif
};

extern int depth;	// Used in print_directory

#endif // DIRECTORIES_H
