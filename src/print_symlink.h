// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file print_symlink.h Declaration of function print_symlink.
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

#ifndef PRINT_SYMLINK_H
#define PRINT_SYMLINK_H

#ifndef USE_PCH
#include <iosfwd>
#endif

#include "inode.h"

int print_symlink(std::ostream& os, Inode const& inode);

// Same for an InodePointer.
inline int print_symlink(std::ostream& os, InodePointer const& inoderef)
{
  // We can dereference inoderef here because it is known that print_symlink does not keep a pointer or reference to the inode.
  return print_symlink(os, *inoderef);
}

#endif // PRINT_SYMLINK_H
