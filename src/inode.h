// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file inode.h Declaration of class InodePointer and function get_inode.
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

#ifndef INODE_H
#define INODE_H

#ifndef USE_PCH
#include "ext3.h"	// Needed for Inode
#include "debug.h"
#endif

#include "globals.h"
#include "load_meta_data.h"

#if USE_MMAP
void inode_mmap(int group);
void inode_unmap(int group);
#endif

class InodePointer {
  private:
    Inode const* M_inode;
    int M_group;
    static Inode S_fake_inode;

  public:
    // Default constructor.
    InodePointer(void) : M_inode(NULL), M_group(-1) { }

    // Copy constructor.
    InodePointer(InodePointer const& ref) : M_inode(ref.M_inode), M_group(ref.M_group)
    {
#if USE_MMAP
      if (M_group != -1)
        refs_to_mmap[M_group]++;
#endif
    }

    // Create an InodePointer to a fake inode.
    InodePointer(int) : M_inode(&S_fake_inode), M_group(-1) { }

    // Destructor.
    ~InodePointer()
    {
#if USE_MMAP
      if (M_group != -1)
        refs_to_mmap[M_group]--;
#endif
    }

    InodePointer& operator=(InodePointer const& inode_reference)
    {
      M_inode = inode_reference.M_inode;
#if USE_MMAP
      if (M_group != -1)
	refs_to_mmap[M_group]--;
#endif
      M_group = inode_reference.M_group;
#if USE_MMAP
      if (M_group != -1)
	refs_to_mmap[M_group]++;
#endif
      return *this;
    }

    // Accessors.
    Inode const* operator->(void) const { return M_inode; }
    Inode const& operator*(void) const { return *M_inode; }

  private:
    friend InodePointer get_inode(uint32_t inode);
    InodePointer(Inode const& inode, int group) : M_inode(&inode), M_group(group)
    {
      ASSERT(M_group != -1);
#if USE_MMAP
      refs_to_mmap[M_group]++;
#endif
    }
};

inline unsigned int bit_to_all_inodes_group_index(unsigned int bit)
{
#if USE_MMAP
  // If bit is incremented by one, we need to skip inode_size_ bytes in the (mmap-ed) inode table.
  // Since the type of the table is Inode* the index needs to be incremented with the number of Inode structs that we need to skip.
  // Because both inode_size_ and sizeof(Inode) are a power of 2 and inode_size_ >= sizeof(Inode), this amounts to inode_size_ / sizeof(Inode)
  // index incrementation per bit.
  return bit * (inode_size_ / sizeof(Inode));
#else
  // If no mmap is used, the table only contains the first 128 bytes of each inode.
  return bit;
#endif
}

inline InodePointer get_inode(uint32_t inode)
{
  int group = (inode - 1) / inodes_per_group_;
  unsigned int bit = inode - 1 - group * inodes_per_group_;
  // The bit in the bit mask must fit inside a single block.
  ASSERT(bit < 8U * block_size_);
#if USE_MMAP
  if (all_inodes[group] == NULL)
    inode_mmap(group);
#else
  if (block_bitmap[group] == NULL)
    load_meta_data(group);
#endif
  return InodePointer(all_inodes[group][bit_to_all_inodes_group_index(bit)], group);
}

#endif // INODE_H
