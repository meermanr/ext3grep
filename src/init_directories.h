// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file init_directories.h Declaration of init_directories and its maps.
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

#ifndef INIT_DIRECTORIES_H
#define INIT_DIRECTORIES_H

#ifndef USE_PCH
#include <map>
#include <string>
#include <stdint.h>
#endif

#include "directories.h"

typedef std::map<std::string, Directory> all_directories_type;
extern all_directories_type all_directories;
typedef std::map<uint32_t, all_directories_type::iterator> inode_to_directory_type;
extern inode_to_directory_type inode_to_directory;
void init_directories(void);

#endif
