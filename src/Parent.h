// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file Parent.h Declaration of struct Parent.
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

#ifndef PARENT_H
#define PARENT_H

#ifndef USE_PCH
#include "ext3.h"	// Needed for ext3_dir_entry_2
#include <stdint.h>	// Needed for uint32_t
#include <string>	// Needed for std::string
#endif

#include "inode.h"	// Needed for InodePointer

struct Parent {
  Parent* M_parent;
  ext3_dir_entry_2 const* M_dir_entry;
  InodePointer M_inode;
  uint32_t M_inodenr;

  Parent(InodePointer const& inode, uint32_t inodenr) : M_parent(NULL), M_dir_entry(NULL), M_inode(inode), M_inodenr(inodenr) { }
  Parent(Parent* parent, ext3_dir_entry_2 const* dir_entry, InodePointer const& inode, uint32_t inodenr) :
      M_parent(parent), M_dir_entry(dir_entry), M_inode(inode), M_inodenr(inodenr) { }
  std::string dirname(bool show_inodes) const;
};

#endif // PARENT_H
