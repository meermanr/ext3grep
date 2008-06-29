// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file print_symlink.cc Definition of the function print_symlink.
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
#include <iostream>
#include "ext3.h"
#include "debug.h"
#endif

#include "endian_conversion.h"
#include "get_block.h"
#include "print_symlink.h"

int print_symlink(std::ostream& os, Inode const& inode)
{
  uint32_t len = 0;
  if (inode.blocks() == 0)
  {
    if (inode.size() == 0)
    {
      std::cout << "<ZERO-LENGTH-SYMLINK>";
      return 0;
    }
    for (int i = 0; i < EXT3_N_BLOCKS; ++i)
    {
      union {
	char chars[4];
	__le32 block;
      } translate;
      translate.block = inode.block()[i];
      for (int j = 0; j < 4; ++j)
      {
	char c = translate.chars[j];
	ASSERT(c != 0);
	os << c;
	if (++len == inode.size())
	  return len;
      }
    }
  }
  else
  {
    ASSERT(inode.block()[0]);
    ASSERT(!inode.block()[1]);			// Name can't be longer than block_size_?!
    unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
    unsigned char* block = get_block(inode.block()[0], block_buf);
    ASSERT(block[block_size_ - 1] == '\0');	// Zero termination exists.
    len = strlen((char*)block);
    os << block;
  }
  return len;
}
