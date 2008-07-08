// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file endian_conversion.h Endianess conversion functions.
//
// Copyright (C) 2008, by
// 
// Carlo Wood, Run on IRC <carlo@alinoe.com>
// RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
// Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
// 
// Stanislaw T. Findeisen <sf181257 at students mimuw edu pl>
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
//
// ChangeLog
//
// 2008-07-07  STF
//     * (read_le32): Add. Read 32-bit little endian integers from a
//       chain of bytes.
//     * (__le16_to_cpu, __le32_to_cpu): Add. Convert little endian
//       integers to native integers.

#ifndef ENDIAN_CONVERSION_H
#define ENDIAN_CONVERSION_H

#ifndef USE_PCH
#include <stdint.h>	// Needed for uint16_t and uint32_t
#include "ext3.h"	// Needed for __u8
#endif

// We keep using these types (actually defined in kernel headers) for clarity (to know when something is little endian and when big endian on DISK).
// ext3grep assumes uint16_t and uint32_t to be little endian (intel cpu).
typedef uint16_t __le16;
typedef uint16_t __be16;
typedef uint32_t __le32;
typedef uint32_t __be32;
inline uint32_t __be32_to_cpu(__be32 x) { return x << 24 | x >> 24 | (x & (uint32_t)0x0000ff00UL) << 8 | (x & (uint32_t)0x00ff0000UL) >> 8; }
inline uint16_t __be16_to_cpu(__be16 x) { return x << 8 | x >> 8; }

// Convert Big Endian to Little Endian.
inline __le32 be2le(__be32 v) { return __be32_to_cpu(v); }
inline __le16 be2le(__be16 v) { return __be16_to_cpu(v); }
inline __u8 be2le(__u8 v) { return v; }

// Using the headers from e2fsprogs, the big endian journal structs
// use normal types. However, since WE read raw data into them,
// they are really still big endian. Calling be2le on those
// types therefore still needs to do the conversion.
inline __le32 be2le(__s32 const& v) { return be2le(*reinterpret_cast<__be32 const*>(&v)); }

// ext3grep assumes uint16_t and uint32_t to be little endian (intel cpu).
inline uint32_t __le32_to_cpu(__le32 x) { return x; }
inline uint16_t __le16_to_cpu(__le16 x) { return x; }

/**
 * Reads __le32 from a string.
 */
inline __le32 read_le32(unsigned char* s)
{
  __le32 v = s[3];

  v <<= 8;
  v |= s[2];

  v <<= 8;
  v |= s[1];

  v <<= 8;
  v |= s[0];

  return v;
}

#endif // ENDIAN_CONVERSION_H
