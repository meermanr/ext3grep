// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file init_journal_consts.cc Definition of function init_journal_consts.
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
#include "debug.h"
#endif

#include "globals.h"
#include "endian_conversion.h"
#include "inode.h"

void init_journal_consts(void)
{
  // Initialize journal constants.
  journal_block_size_ = be2le(journal_super_block.s_blocksize);
  ASSERT(journal_block_size_ == block_size_);	// Sorry, I'm trying to recover my own data-- have no time to deal with this.
  journal_maxlen_ = be2le(journal_super_block.s_maxlen);
  journal_first_ = be2le(journal_super_block.s_first);
  journal_sequence_ = be2le(journal_super_block.s_sequence);
  journal_start_ = be2le(journal_super_block.s_start);
  journal_inode = *get_inode(super_block.s_journal_inum);
}
