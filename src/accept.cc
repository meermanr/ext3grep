// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file accept.cc Implementation of things related to --accept.
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
#include "debug.h"
#endif

#include "is_filename_char.h"
#include "accept.h"

//-----------------------------------------------------------------------------
//
// Accepted filenames and unlikely characters.
//

std::bitset<256> Accept::S_illegal;
std::bitset<256> Accept::S_unlikely;

// Set with all Accept objects.
std::set<Accept> accepted_filenames;

// Global initialization.
void init_accept(void)
{
  Accept::S_illegal.reset();
  Accept::S_unlikely.reset();

  for (int i = 0; i < 256; ++i)
  {
    __s8 c = i;
    filename_char_type res = is_filename_char(c);
    switch(res)
    {
      case fnct_ok:
        break;
      case fnct_illegal:
        Accept::S_illegal.set(i);
        break;
      case fnct_unlikely:
      case fnct_non_ascii:
        Accept::S_unlikely.set(i);
        break;
    }
  }
}
