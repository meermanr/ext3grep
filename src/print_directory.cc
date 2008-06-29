// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file print_directory.cc Implementation of the function print_directory.
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
#include <iomanip>
#endif

#include "directories.h"
#include "globals.h"
#include "utils.h"
#include "inode.h"
#include "FileMode.h"
#include "print_symlink.h"
#include "forward_declarations.h"
#include "commandline.h"
#include "print_dir_entry_long_action.h"

//-----------------------------------------------------------------------------
//
// Directory printing
//

void DirEntry::print(void) const
{
  if (filtered)
    return;
  std::cout << std::setfill(' ') << std::setw(4) << index.cur << ' ';
  if (index.next)
    std::cout << std::setfill(' ') << std::setw(4) << index.next << ' ';
  else
    std::cout << " end ";
  if (feature_incompat_filetype)
    std::cout << dir_entry_file_type(M_file_type, true);
  else
    std::cout << '-';
  std::cout << std::setfill(' ') << std::setw(8) << M_inode << "  ";
  std::cout << (zero_inode ? 'Z' : deleted ? reallocated ? 'R' : 'D' : ' ');
  InodePointer inode;
  if (!zero_inode)
  {
    inode = get_inode(M_inode);
    if (deleted && !reallocated)
    {
      time_t dtime = inode->dtime();
      std::string dtime_str(ctime(&dtime));
      std::cout << ' ' << std::setw(10) << dtime << ' ' << dtime_str.substr(0, dtime_str.length() - 1);
    }
  }
  if (zero_inode && linked)
    std::cout << " * LINKED ENTRY WITH ZERO INODE *   ";
  else if (zero_inode || !deleted || reallocated)
    std::cout << std::string(36, ' ');
  if (zero_inode || reallocated)
    std::cout << "  ??????????";
  else
    std::cout << "  " << FileMode(inode->mode());
  std::cout << "  " << M_name;
  if (!(reallocated || zero_inode) && is_symlink(inode))
  {
    std::cout << " -> ";
    print_symlink(std::cout, inode);
  }
  std::cout << '\n';
}

void DirectoryBlock::print(void) const
{
  for (std::vector<DirEntry>::const_iterator iter = M_dir_entry.begin(); iter != M_dir_entry.end(); ++iter)
    iter->print();
}

void print_directory(unsigned char* block, int blocknr)
{
  depth = 1;
  if (commandline_ls)
  {
    if (feature_incompat_filetype)
      std::cout << "          .-- File type in dir_entry (r=regular file, d=directory, l=symlink)\n";
    std::cout   << "          |          .-- D: Deleted ; R: Reallocated\n";
    std::cout   << "Indx Next |  Inode   | Deletion time                        Mode        File name\n";
    std::cout   << "==========+==========+----------------data-from-inode------+-----------+=========\n";
    std::list<DirectoryBlock> db(1);
    db.begin()->read_block(blocknr, db.begin());
    db.begin()->print();
    std::cout << '\n';
  }
  else
  {
#ifdef CPPGRAPH
    // Let cppgraph know that we call print_dir_entry_long_action from here.
    iterate_over_directory__with__print_dir_entry_long_action();
#endif
    ++no_filtering;
    iterate_over_directory(block, blocknr, print_dir_entry_long_action, NULL, NULL);
    --no_filtering;
  }
}
