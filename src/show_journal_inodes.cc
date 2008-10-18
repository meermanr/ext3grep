// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file show_journal_inodes.cc Implementation of the function show_journal_inodes.
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
#include <vector>
#include <iostream>
#include "ext3.h"
#endif

#include "journal.h"
#include "print_inode_to.h"
#include "forward_declarations.h"

void show_journal_inodes(int inodenr)
{
  std::vector<std::pair<int, Inode> > inodes;
  get_inodes_from_journal(inodenr, inodes);
  std::cout << "Copies of inode " << inodenr << " found in the journal:\n";
  uint32_t last_mtime = std::numeric_limits<uint32_t>::max();
  for (std::vector<std::pair<int, Inode> >::iterator iter = inodes.begin(); iter != inodes.end(); ++iter)
  {
    Inode const& inode(iter->second);
    if (inode.mtime() != last_mtime)
    {
      last_mtime = inode.mtime();
      std::cout << "\n--------------Inode " << inodenr << "-----------------------\n";
      print_inode_to(std::cout, inode);
    }
  }
}

void show_journal_blocks(int blocknr)
{
  std::vector<std::pair<int, unsigned char*> > blocks;
  get_blocks_from_journal(blocknr, blocks);
  std::cout << "Copies of block " << blocknr << " found in the journal:\n";
  for (std::vector<std::pair<int, unsigned char*> >::iterator iter = blocks.begin(); iter != blocks.end(); ++iter)
  {
    std::cout << "\n--------------Block " << blocknr << "------ Sequence# " << iter->first << "-----------------\n";
    print_block_to(std::cout, iter->second);
    delete [] iter->second;
  }
}
