// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file blocknr_vector_type.cc Implementation of union blocknr_vector_type.
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
#endif

#include "blocknr_vector_type.h"

blocknr_vector_type& blocknr_vector_type::operator=(std::vector<uint32_t> const& vec)
{
  if (!empty())
    erase();
  uint32_t size = vec.size();
  if (size > 0)
  {
    if (size == 1)
      blocknr = (vec[0] << 1) | 1; 
    else
    {
      blocknr_vector = new uint32_t [size + 1]; 
      blocknr_vector[0] = size;
      for (uint32_t i = 0; i < size; ++i)
        blocknr_vector[i + 1] = vec[i];
    }
  }
  return *this;
}

void blocknr_vector_type::push_back(uint32_t bnr)
{
  if (empty())
  {
    ASSERT(bnr);
    blocknr = (bnr << 1) | 1;
  }
  else if (is_vector())
  {
    uint32_t size = blocknr_vector[0] + 1;
    uint32_t* ptr = new uint32_t [size + 1]; 
    ptr[0] = size;
    for (uint32_t i = 1; i < size; ++i)
      ptr[i] = blocknr_vector[i];
    ptr[size] = bnr;
    delete [] blocknr_vector;
    blocknr_vector = ptr;
  }
  else
  {
    uint32_t* ptr = new uint32_t [3];
    ptr[0] = 2;
    ptr[1] = blocknr >> 1;
    ptr[2] = bnr;
    blocknr_vector = ptr;
  }
}

void blocknr_vector_type::remove(uint32_t blknr)
{
  ASSERT(is_vector());
  uint32_t size = blocknr_vector[0];
  int found = 0;
  for (uint32_t j = 1; j <= size; ++j)
    if (blocknr_vector[j] == blknr)
    {
      found = j;
      break;
    }
  ASSERT(found);
  blocknr_vector[found] = blocknr_vector[size];
  blocknr_vector[0] = --size;
  if (size == 1)
  {
    int last_block = blocknr_vector[1];
    delete [] blocknr_vector;
    blocknr = (last_block << 1) | 1;
  }
}
