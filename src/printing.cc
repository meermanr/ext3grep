// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file printing.cc Functions that print stuff.
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
#endif

#include "globals.h"
#include "forward_declarations.h"
#include "commandline.h"

//-----------------------------------------------------------------------------
//
// Printing
//

void print_block_to(std::ostream& os, unsigned char* block)
{
  unsigned char buf[16];
  size_t offset = 0;
  bool last_was_star = false;
  for (unsigned char* p = block; p < block + block_size_; p += 16, offset += 16)
  {
    if (offset > 0 && offset + 16 < block_size_ && memcmp(buf, p, 16) == 0)
    {
      if (!last_was_star)
      {
	os << " *\n";
	last_was_star = true;
      }
      continue;
    }
    dump_hex_to(os, p, 16, offset);
    memcpy(buf, p, 16);
    last_was_star = false;
  }
}

void print_restrictions(void)
{
  if (commandline_allocated)
    std::cout << "Only showing entries with allocated inodes.\n";
  if (commandline_unallocated)
    std::cout << "Only showing entries with unallocated inodes.\n";
  if (commandline_deleted)
    std::cout << "Only showing entries that were deleted.\n";
  if (commandline_directory)
    std::cout << "Only showing inodes that are directories.\n";
  if (commandline_before || commandline_after)
  {
    std::cout << "Only show/process deleted entries if they are deleted ";
    if (commandline_after)
      std::cout << "on or after " << commandline_after;
    if (commandline_before && commandline_after)
      std::cout << " and ";
    if (commandline_before)
      std::cout << "before " << commandline_before;
    std::cout << '.' << std::endl;
  }
}
