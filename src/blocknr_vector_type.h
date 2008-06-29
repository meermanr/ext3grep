// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file blocknr_vector_type.h Declaration of union blocknr_vector_type.
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

#ifndef BLOCKNR_VECTOR_TYPE_H
#define BLOCKNR_VECTOR_TYPE_H

#ifndef USE_PCH
#include "sys.h"
#include <stdint.h>
#include <unistd.h>
#include <vector>
#include "debug.h"
#endif

#define BVASSERT(x) ASSERT(x)

union blocknr_vector_type {
  size_t blocknr;		// This must be a size_t in order to align the least significant bit with the least significant bit of blocknr_vector.
  uint32_t* blocknr_vector;

  void push_back(uint32_t blocknr);
  void remove(uint32_t blocknr);
  void erase(void) { if (is_vector()) delete [] blocknr_vector; blocknr = 0; }
  blocknr_vector_type& operator=(std::vector<uint32_t> const& vec);

  bool empty(void) const { return blocknr == 0; }
  // The rest is only valid if empty() returned false.
  bool is_vector(void) const { BVASSERT(!empty()); return !(blocknr & 1); }
  uint32_t size(void) const { return is_vector() ? blocknr_vector[0] : 1; }
  uint32_t first_entry(void) const { return is_vector() ? blocknr_vector[1] : (blocknr >> 1); }
  uint32_t operator[](int index) const { BVASSERT(index >= 0 && (size_t)index < size()); return (index == 0) ? first_entry() : blocknr_vector[index + 1]; }
};

#endif // BLOCKNR_VECTOR_TYPE_H

