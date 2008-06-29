// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file ostream_operators.h Declaration of various ostream inserter functions.
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

#ifndef OSTREAM_OPERATORS_H
#define OSTREAM_OPERATORS_H

#ifndef USE_PCH
#include <iosfwd>		// Needed for std::ostream
#include "ext3.h"		// Needed for all other types.
#endif

// Print superblock contents.
std::ostream& operator<<(std::ostream& os, ext3_super_block const& super_block);
std::ostream& operator<<(std::ostream& os, journal_superblock_t const& journal_super_block);

// Print group descriptor.
std::ostream& operator<<(std::ostream& os, ext3_group_desc const& group_desc);

// Print journal header.
std::ostream& operator<<(std::ostream& os, journal_header_t const& journal_header);
std::ostream& operator<<(std::ostream& os, journal_block_tag_t const& journal_block_tag);
std::ostream& operator<<(std::ostream& os, journal_revoke_header_t const& journal_revoke_header);

#endif // OSTREAM_OPERATORS_H
