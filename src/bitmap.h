// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file bitmap.h Declarations of bitmap related code.
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

#ifndef BITMAP_H
#define BITMAP_H

// A bitmap (variables ending on _bitmap) is represented as an array of bitmap_t.
typedef unsigned long bitmap_t;

// A bitmap_ptr represents a single bit in a bit map.
struct bitmap_ptr {
  int index;                                    // The index into the array of bitmap_t.
  union {
    bitmap_t mask;                              // The mask for that array element (a single bit).
    unsigned char byte[sizeof(bitmap_t)];       // For byte-level access.
  };
};

// Translate 'bit' into a bitmap_ptr.
inline bitmap_ptr get_bitmap_mask(unsigned int bit)
{
  bitmap_ptr result;
  result.mask = 0;      // Initialize all bits in the mask to zero.

  // From the book "File System Forensic Analysis":
  // Like other bitmaps we have seen in this book, it is organized into bytes,
  // and the least-significant bit corresponds to the block after the most-significant
  // bit of the previous byte. In other words, when we read the bytes we go left to
  // right, but inside each byte we read right to left.

  // Number of bits in bitmap_t.
  static int const bitmap_t_bits = 8 * sizeof(bitmap_t);
  // Higher bit's result in higher indexes. Every bitmap_t_bits the index is incremented by one.
  result.index = bit / bitmap_t_bits;
  // Higher bits means higher bytes. Every 8 bit the byte index is incremented by one.
  // Higher bits means more significant bits. There are 2^3 bits per byte.
  result.byte[(bit & (bitmap_t_bits - 1)) >> 3] = 1 << (bit & 7);
  return result;
}

#endif // BITMAP_H
