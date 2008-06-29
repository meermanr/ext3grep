// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file print_directory_inode.cc Definition of functions print_directory_inode.
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

#include "init_directories.h"
#include "dir_inode_to_block.h"
#include "commandline.h"
#include "forward_declarations.h"

void print_directory_inode(int inode)
{
  init_directories();
  int first_block = dir_inode_to_block(inode);
  if (first_block == -1)
  {
    std::cout << "There is no directory block associated with inode " << inode << ".\n";
    return;
  }
  std::cout << "The first block of the directory is " << first_block << ".\n";
  inode_to_directory_type::iterator iter = inode_to_directory.find(inode);
  ASSERT(iter != inode_to_directory.end());
  all_directories_type::iterator directory_iter = iter->second;
  std::cout << "Inode " << inode << " is directory \"" << directory_iter->first << "\".\n";
  if (commandline_dump_names)
    dump_names();
  else
  {
    Directory& directory(directory_iter->second);
    for (std::list<DirectoryBlock>::iterator directory_block_iter = directory.blocks().begin();
	directory_block_iter != directory.blocks().end(); ++directory_block_iter)
    {
      std::cout << "Directory block " << directory_block_iter->block() << ":\n";
      if (feature_incompat_filetype)
	std::cout << "          .-- File type in dir_entry (r=regular file, d=directory, l=symlink)\n";
      std::cout   << "          |          .-- D: Deleted ; R: Reallocated\n";
      std::cout   << "Indx Next |  Inode   | Deletion time                        Mode        File name\n";
      std::cout   << "==========+==========+----------------data-from-inode------+-----------+=========\n";
      directory_block_iter->print();  
    }
  }
}
