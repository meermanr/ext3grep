// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file commandline.h Declarations of commandline option variables.
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

#ifndef COMMANDLINE_H
#define COMMANDLINE_H

#ifndef USE_PCH
#include <string>		// Needed for std::string
#include <vector>		// Needed for std::vector
#include <time.h>		// Needed for time_t
#endif

#include "histogram.h"		// Needed for hist_type

// Commandline options.
extern bool commandline_superblock;
extern int commandline_group;
extern int commandline_inode_to_block;
extern int commandline_inode;
extern int commandline_block;
extern int commandline_journal_block;
extern int commandline_journal_transaction;
extern bool commandline_print;
extern bool commandline_ls;
extern bool commandline_journal;
extern bool commandline_dump_names;
extern int commandline_depth;
extern bool commandline_deleted;
extern bool commandline_directory;
extern time_t commandline_before;
extern time_t commandline_after;
extern bool commandline_allocated;
extern bool commandline_unallocated;
extern bool commandline_reallocated;
extern bool commandline_action;
extern bool commandline_search_zeroed_inodes;
extern bool commandline_zeroed_inodes;
extern bool commandline_show_path_inodes;
extern std::string commandline_search;
extern std::string commandline_search_start;
extern int commandline_search_inode;
extern hist_type commandline_histogram;
extern std::string commandline_inode_dirblock_table;
extern int commandline_show_journal_inodes;
extern std::vector<std::string> commandline_restore_file;
extern std::string commandline_restore_inode;
extern bool commandline_restore_all;
extern bool commandline_show_hardlinks;
extern bool commandline_debug;
extern bool commandline_debug_malloc;
extern bool commandline_custom;
extern bool commandline_accept_all;

#endif // COMMANDLINE_H
