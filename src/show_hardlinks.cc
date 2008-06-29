// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file show_hardlinks.cc Implementation of --show-hardlinks.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <map>
#include <vector>
#include <cerrno>
#include "debug.h"
#endif

#include "forward_declarations.h"
#include "init_files.h"
#include "init_directories.h"

void show_hardlinks(void)
{
  DoutEntering(dc::notice, "show_hardlinks()");

  init_files();
#if 0 // I added this loop with a plan... but I forgot what it was.
  for (all_directories_type::iterator iter = all_directories.begin(); iter != all_directories.end(); ++iter)
  {
  }
#endif
  typedef std::map<int, std::vector<path_to_inode_map_type::iterator> > inodes_type;
  inodes_type inodes;
  for (path_to_inode_map_type::iterator iter = path_to_inode_map.begin(); iter != path_to_inode_map.end(); ++iter)
  {
    struct stat statbuf;
    if (lstat(iter->first.c_str(), &statbuf) == -1)
    {
      int error = errno;
      if (error != ENOENT)
      {
	std::cout << std::flush;
	std::cerr << "WARNING: lstat: " << iter->first << ": " << strerror(error) << std::endl;
      }
    }
    else if (!S_ISDIR(statbuf.st_mode))
    {
      std::pair<inodes_type::iterator, bool> res = inodes.insert(inodes_type::value_type(iter->second, std::vector<path_to_inode_map_type::iterator>()));
      res.first->second.push_back(iter);
    }
    else
    {
      std::cout << std::flush;
      std::cerr << "WARNING: lstat: " << iter->first << ": is a directory" << std::endl;
    }
  }
  for (inodes_type::iterator iter = inodes.begin(); iter != inodes.end(); ++iter)
  {
    if (iter->second.size() > 1)
    {
      std::cout << "Inode " << iter->first << ":\n";
      for (std::vector<path_to_inode_map_type::iterator>::iterator iter3 = iter->second.begin(); iter3 != iter->second.end(); ++iter3)
      {
	std::string::size_type slash = (*iter3)->first.find_last_of('/');
	ASSERT(slash != std::string::npos);
	std::string dirname = (*iter3)->first.substr(0, slash);
        all_directories_type::iterator iter5 = all_directories.find(dirname);
	ASSERT(iter5 != all_directories.end());
        std::cout << "  " << (*iter3)->first << " (" << iter5->second.inode_number() << ")\n";
      }
#if 0
      // Try to figure out which directory it belongs to.
      inode_to_dir_entry_type::iterator iter2 = inode_to_dir_entry.find(iter->first);
      ASSERT(iter2 != inode_to_dir_entry.end());
      Inode inode;
      int sequence;
      get_undeleted_inode_type res = get_undeleted_inode(iter->first, inode, &sequence);
      if (res == ui_no_inode)
      {
        std::cout << "ok: no inode\n";
      }
      else if (res == ui_inode_too_old)
      {
        std::cout << "ok: inode too old\n";
      }
      else if (res == ui_real_inode)
      {
	for (std::vector<std::vector<DirEntry>::iterator>::iterator iter4 = iter2->second.begin(); iter4 != iter2->second.end(); ++iter4)
	{
	  DirEntry& dir_entry(**iter4);
	  int dirblocknr = dir_entry.M_directory_iterator->block();
	  int group = block_to_group(super_block, dirblocknr);;
	  unsigned int bit = dirblocknr - first_data_block(super_block) - group * blocks_per_group(super_block);
	  ASSERT(bit < 8U * block_size_);
	  bitmap_ptr bmp = get_bitmap_mask(bit);
	  ASSERT(block_bitmap[group]);
	  bool allocated = (block_bitmap[group][bmp.index] & bmp.mask);
	  if (allocated)
	    std::cout << "ok: " << dir_entry.M_directory->inode_number() << '/' << dir_entry.M_name << '\n';
	}
      }
      else if (res == ui_journal_inode)
      {
        Transaction& transaction(sequence_transaction_map.find(sequence)->second);
	for (std::vector<std::vector<DirEntry>::iterator>::iterator iter4 = iter2->second.begin(); iter4 != iter2->second.end(); ++iter4)
	{
	  DirEntry& dir_entry(**iter4);
	  int dirblocknr = dir_entry.M_directory_iterator->block();
	  if (transaction.contains_tag_for_block(dirblocknr))
	    std::cout << "ok: " << dir_entry.M_directory->inode_number() << '/' << dir_entry.M_name << '\n';
        }
      }
#endif
    }
  }
}
