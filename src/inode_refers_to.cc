// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file inode_refers_to.cc Implementation of function inode_refers_to.
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
#include "ext3.h"
#endif

#include "indirect_blocks.h"

struct inode_refers_to_st
{
  int block_number;
  bool found;
};

void inode_refers_to_action(int blocknr, int, void* ptr)
{
  inode_refers_to_st& data(*reinterpret_cast<inode_refers_to_st*>(ptr));
  if (blocknr == data.block_number)
    data.found = true;
}

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__inode_refers_to_action(void) { inode_refers_to_action(0, 0, NULL); }
#endif

bool inode_refers_to(Inode const& inode, int inode_number, int block_number)
{
  inode_refers_to_st data;
  data.block_number = block_number;
  data.found = false;
#ifdef CPPGRAPH
  // Tell cppgraph that we call inode_refers_to_action from here.
  iterate_over_all_blocks_of__with__inode_refers_to_action();
#endif
  bool reused_or_corrupted_indirect_block9 = iterate_over_all_blocks_of(inode, inode_number, inode_refers_to_action, &data);
  if (data.found)
    return true;
  if (reused_or_corrupted_indirect_block9)
    std::cout << "WARNING: Could not verify if inode " << inode_number << " refers to block " << block_number <<
        " : encountered a reused or corrupted (double/triple) indirect block!\n";
  return false;
}
