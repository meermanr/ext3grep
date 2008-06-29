// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file print_inode_to.h Declaration of function print_inode_to.
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

#ifndef PRINT_INODE_TO_H
#define PRINT_INODE_TO_H

#ifndef USE_PCH
#include <iostream>
#endif

#include "inode.h"

void print_inode_to(std::ostream& os, Inode const& inode);

inline void print_inode_to(std::ostream& os, InodePointer inoderef)
{
  // We can dereference inoderef here because it is known that print_inode_to does not keep a pointer or reference to the inode.
  print_inode_to(os, *inoderef);
}

#endif // PRINT_INODE_TO_H
