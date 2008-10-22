// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file dump_hex_to.cc Implementation of the dump_hex_to function.
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
#include <iomanip>
#endif

//-----------------------------------------------------------------------------
//
// dump_hex_to
//

void dump_hex_to(std::ostream& os, unsigned char const* buf, size_t size, size_t addr_offset)
{
  for (size_t addr = 0; addr < size; addr += 16)
  {
    os << std::hex << std::setfill('0') << std::setw(4) << (addr + addr_offset) << " |";
    int offset;
    for (offset = 0; offset < 16 && addr + offset < size; ++offset)
      os << ' ' << std::hex << std::setfill('0') << std::setw(2) << (int)buf[addr + offset];
    for (; offset < 16; ++offset)
      os << "   ";
    os << " | ";
    for (int offset = 0; offset < 16 && addr + offset < size; ++offset)
    {
      unsigned char c = buf[addr + offset];
      if (!std::isprint(c))
	c = '.';
      os << c;
    }
    os << '\n';
  }
  os << std::dec;
}
