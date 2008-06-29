// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file dump_names.cc Implementation of --dump_names and --restore-all.
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

#include "forward_declarations.h"
#include "init_directories.h"
#include "init_files.h"
#include "commandline.h"

void dump_names(void)
{
  DoutEntering(dc::notice, "dump_names()");

  init_files();
  std::list<std::string> paths;
  for (all_directories_type::iterator iter = all_directories.begin(); iter != all_directories.end(); ++iter)
    paths.push_back(iter->first);
  for (path_to_inode_map_type::iterator iter = path_to_inode_map.begin(); iter != path_to_inode_map.end(); ++iter)
    paths.push_back(iter->first);
  paths.sort();
  for (std::list<std::string>::iterator iter = paths.begin(); iter != paths.end(); ++iter)
    if (!iter->empty())
    {
      if (commandline_restore_all)
	restore_file(*iter);
      else
	std::cout << *iter << '\n';
    }
}
