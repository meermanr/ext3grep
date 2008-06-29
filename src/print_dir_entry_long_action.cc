// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file print_dir_entry_long_action.cc Definition of the function print_dir_entry_long_action.
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
#include "ext3.h"
#endif

#include "Parent.h"
#include "utils.h"
#include "is_filename_char.h"
#include "is_blockdetection.h"
#include "print_symlink.h"
#include "commandline.h"
#include "conversion.h"
#include "print_inode_to.h"

bool print_dir_entry_long_action(ext3_dir_entry_2 const& dir_entry, Inode const& inode,
    bool UNUSED(deleted), bool UNUSED(allocated), bool reallocated, bool zero_inode, bool linked, bool filtered, Parent*, void*)
{
  std::cout << "\ninode: " << dir_entry.inode << '\n';
  std::cout << "Directory entry length: " << dir_entry.rec_len << '\n';
  std::cout << "Name length: " << (int)dir_entry.name_len << '\n';
  if (feature_incompat_filetype)
    std::cout << "File type: " << dir_entry_file_type(dir_entry.file_type, false);
  int number_of_weird_characters = 0;
  for (int c = 0; c < dir_entry.name_len; ++c)
  {
    filename_char_type fnct = is_filename_char(dir_entry.name[c]);
    if (fnct != fnct_ok)
    {
      ASSERT(fnct != fnct_illegal);
      ++number_of_weird_characters;
    }
  }
  if (number_of_weird_characters < 4 && number_of_weird_characters < dir_entry.name_len)
    std::cout << "\nFile name: \"" << std::string(dir_entry.name, dir_entry.name_len) << "\"\n";
  if (number_of_weird_characters > 0)
  {
    std::cout << "\nEscaped file name: \"";
    print_buf_to(std::cout, dir_entry.name, dir_entry.name_len);
    std::cout << "\"\n";
  }
  if (!reallocated && !zero_inode && feature_incompat_filetype && (dir_entry.file_type & 7) == EXT3_FT_SYMLINK)
  {
    std::cout << "Symbolic link to: ";
    print_symlink(std::cout, inode);
    std::cout << '\n';
  }
  std::cout << "Filtered: " << (filtered ? "Yes" : "No") << '\n';
  if (commandline_group == -1 || inode_to_group(super_block, dir_entry.inode) == commandline_group)
  {
    if (zero_inode)
      std::cout << "Inode: ZERO\n";
    else
    {
      std::cout << "\nInode:\n";
      print_inode_to(std::cout, inode);
    }
    if (zero_inode && linked)
      std::cout << "The directory entry is linked but has a zero inode. This needs to be fixed!\n";
  }
  return false;
}

#ifdef CPPGRAPH
void iterate_over_directory__with__print_dir_entry_long_action(void) { (void)print_dir_entry_long_action(*(ext3_dir_entry_2 const*)NULL, *(Inode const*)NULL, 0, 0, 0, 0, 0, 0, NULL, NULL); }
#endif
