// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file is_filename_char.h Implementation of function is_filename_char.
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

#ifndef IS_FILENAME_CHAR_H
#define IS_FILENAME_CHAR_H

#ifndef USE_PCH
#include "sys.h"
#endif

//-----------------------------------------------------------------------------
//
// is_filename_char
//

enum filename_char_type {
  fnct_ok,
  fnct_illegal,
  fnct_unlikely,
  fnct_non_ascii
};

inline filename_char_type is_filename_char(__s8 c)
{
  if (c == 0 || c == '/')
    return fnct_illegal;
  // These characters are legal... but unlikely
  // (* They did not appear in any of the files on MY partition).
  static unsigned char hit[128 - 32] = {			// Mark 22 ("), 2a (*), 3b (;), 3c (<), 3e (>), 3f (?), 5c (\), 60 (`), 7c (|)
//  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, // 2
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, // 3
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 4
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, // 5
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 6
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0  // 7
  };
  // These characters are legal, but very unlikely.
  // Don't reject them when a specific block was requested.
  if (c < 32 || c == 127)
    return fnct_non_ascii;
  // These characters are legal ASCII, but unlikely.
  if (hit[c - 32])
    return fnct_unlikely;
  return fnct_ok;
}

#endif // IS_FILENAME_CHAR_H
