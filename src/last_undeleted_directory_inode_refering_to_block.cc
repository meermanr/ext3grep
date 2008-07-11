// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file last_undeleted_directory_inode_refering_to_block.cc Definition of the function last_undeleted_directory_inode_refering_to_block.
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
#endif

#include "is_blockdetection.h"
#include "inode_refers_to.h"
#include "journal.h"

// Return std::numeric_limits<int>::max() if the inode is still allocated
// and refering to the given block, otherwise return the Journal sequence
// number that contains the last copy of an undeleted inode that refers
// to the given block, or return 0 if none could be found.
int last_undeleted_directory_inode_refering_to_block(uint32_t inode_number, int directory_block_number)
{
  if (is_allocated(inode_number))
  {
    InodePointer real_inode = get_inode(inode_number);
    if (is_directory(*real_inode) && inode_refers_to(*real_inode, inode_number, directory_block_number))
      return std::numeric_limits<int>::max();
  }
  // Get sequence/Inode pairs from the Journal.
  std::vector<std::pair<int, Inode> > inodes;
  get_inodes_from_journal(inode_number, inodes);
  // This runs from high to low sequence numbers, so we'll find the highest matching sequence number.
  for (std::vector<std::pair<int, Inode> >::iterator iter = inodes.begin(); iter != inodes.end(); ++iter)
    if (is_directory(iter->second) && inode_refers_to(iter->second, inode_number, directory_block_number))
      return iter->first;
  // Nothing found.
  return 0;
}
