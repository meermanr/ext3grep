// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file ext3grep.cc Main implementation.
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
#include <endian.h>
#include <utime.h>
#include <sys/mman.h>
#include <cassert>
#include <ctime>
#include <cstdlib>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <set>
#include <map>
#include <vector>
#include <list>
#include <limits>
#include <sstream>
#include <bitset>
#include <algorithm>
#include "ext3.h"
#include "debug.h"
#endif

#include "commandline.h"
#include "globals.h"
#include "ostream_operators.h"
#include "inode.h"
#include "conversion.h"
#include "init_journal_consts.h"
#include "load_meta_data.h"
#include "forward_declarations.h"
#include "is_blockdetection.h"
#include "indirect_blocks.h"
#include "restore.h"
#include "get_block.h"
#include "init_consts.h"
#include "print_inode_to.h"

//-----------------------------------------------------------------------------
//
// main
//

#ifdef USE_SVN
extern char const* svn_revision;
#endif

extern void custom(void);

void run_program(void)
{
  Debug(if (!commandline_debug) dc::notice.off());
  Debug(if (commandline_debug) while(!dc::notice.is_on()) dc::notice.on());
  Debug(if (!commandline_debug_malloc) dc::malloc.off());
  Debug(if (commandline_debug_malloc) while(!dc::malloc.is_on()) dc::malloc.on());
  Debug(libcw_do.on());

  DoutEntering(dc::notice, "run_program()");

  if (commandline_superblock && !commandline_journal)
  {
    // Print contents of superblock.
    std::cout << super_block << '\n';
  }

  // The features that we support.
  feature_incompat_filetype = super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_FILETYPE;

  // Do we have a journal?
  if (super_block.s_journal_inum != 0)
  {
    InodePointer journal_inode = get_inode(super_block.s_journal_inum);
    int first_block = journal_inode->block()[0];
    ASSERT(first_block);
    // Read the first superblock.
    device.seekg(block_to_offset(first_block));
    ASSERT(device.good());
    // journal_super_block is initialized here.
    device.read(reinterpret_cast<char*>(&journal_super_block), sizeof(journal_superblock_s));
    ASSERT(device.good());
    if (commandline_superblock && commandline_journal)
    {
      // Print contents of superblock.
      std::cout << "Journal Super Block:\n\n";
      std::cout << "Signature: 0x" << be2le(journal_super_block.s_header.h_magic) << std::dec << '\n';
      std::cout << journal_super_block << '\n';
    }
    // Sanity checks.
    ASSERT(be2le(journal_super_block.s_header.h_magic) == JFS_MAGIC_NUMBER);
    init_journal_consts();
  }

  // Check commandline options against superblock contents.
  if (commandline_journal && !super_block.s_journal_inum)
  {
    std::cout << std::flush;
    std::cerr << progname << ": --journal: The journal is on an external device. Please add support for it." << std::endl;
    exit(EXIT_FAILURE);
  }
  if (commandline_custom)
  {
    custom();
    exit(EXIT_SUCCESS);
  }
  if (commandline_inode != -1)
  {
    if ((uint32_t)commandline_inode > inode_count_)
    {
      std::cout << std::flush;
      std::cerr << progname << ": --inode: inode " << commandline_inode << " is out of range. There are only " << inode_count_ << " inodes." << std::endl;
      exit(EXIT_FAILURE);
    }
    commandline_group = inode_to_group(super_block, commandline_inode);
    // std::cout << "Inode " << commandline_inode << " is in group " << commandline_group << '\n';
  }
  if (commandline_block != -1)
  {
    if (commandline_block >= block_count(super_block))
    {
      std::cout << std::flush;
      std::cerr << progname << ": --block: block " << commandline_block << " is out of range. There are only " << block_count(super_block) << " blocks." << std::endl;
      exit(EXIT_FAILURE);
    }
    commandline_group = block_to_group(super_block, commandline_block);
  }
  if (commandline_journal_block != -1)
  {
    if (commandline_journal_block >= block_count(journal_super_block))
    {
      std::cout << std::flush;
      std::cerr << progname << ": --journal-block: block " << commandline_journal_block << " is out of range. There are only " <<
          block_count(journal_super_block) << " blocks in the journal." << std::endl;
      exit(EXIT_FAILURE);
    }
  }
  if (commandline_show_journal_inodes != -1)
  {
    if ((uint32_t)commandline_show_journal_inodes > inode_count_)
    {
      std::cout << std::flush;
      std::cerr << progname << ": --show-journal-inodes: inode " << commandline_show_journal_inodes <<
          " is out of range. There are only " << inode_count_ << " inodes." << std::endl;
      exit(EXIT_FAILURE);
    }
    commandline_group = inode_to_group(super_block, commandline_show_journal_inodes);
    // std::cout << "Inode " << commandline_show_journal_inodes << " is in group " << commandline_group << '\n';
  }

  // Print group summary, if needed.
  if (!commandline_journal && commandline_inode_to_block == -1)
  {
    std::cout << "Number of groups: " << groups_ << '\n';
    if (commandline_group == -1)
    {
      if (!commandline_action)
	for (int group = 0; group < groups_; ++group)
	{
	  std::cout << " Group\t" << group << ": ";
	  std::cout << group_descriptor_table[group] << '\n';
	}
    }
    else if (commandline_group < 0 || commandline_group >= groups_)
    {
      std::cout << std::flush;
      std::cerr << progname << ": --group: group " << commandline_group << " is out of range." << std::endl;
      exit(EXIT_FAILURE);
    }
    else if (!commandline_action)
    {
      std::cout << " Group\t" << commandline_group << ": ";
      std::cout << group_descriptor_table[commandline_group] << '\n';
    }
  }

  if (commandline_action && !commandline_journal)
  {
    if (commandline_inode_to_block != -1)
      commandline_group = inode_to_group(super_block, commandline_inode_to_block);
    if (!commandline_group)
      std::cout << "Loading group metadata.." << std::flush;
    for (int group = 0; group < groups_; ++group)
    {
      if (commandline_group != -1 && group != commandline_group)
	continue;
      if (!commandline_group)
	std::cout << '.' << std::flush;
      load_meta_data(group);
    }
    if (!commandline_group)
      std::cout << " done\n";
  }

  // Needed here?
  init_journal();

  // Handle --inode
  if (commandline_inode != -1)
  {
    InodePointer inode(get_inode(commandline_inode));
    if (commandline_print)
    {
      std::cout << "\nHex dump of inode " << commandline_inode << ":\n";
      dump_hex_to(std::cout, (unsigned char const*)&(*inode), inode_size_);
      std::cout << '\n';
    }
    unsigned int bit = commandline_inode - 1 - commandline_group * inodes_per_group_;
    ASSERT(bit < 8U * block_size_);
    bitmap_ptr bmp = get_bitmap_mask(bit);
    bool allocated = (inode_bitmap[commandline_group][bmp.index] & bmp.mask);
    if (allocated)
      std::cout << "Inode is Allocated\n";
    else
      std::cout << "Inode is Unallocated\n";
    if (commandline_print)
    {
      std::cout << "Group: " << commandline_group << '\n';
      print_inode_to(std::cout, *inode);
    }
    if (is_directory(inode))
      print_directory_inode(commandline_inode);
  }
  // Handle --block
  if (commandline_block != -1 || (commandline_journal_block != -1 && commandline_journal))
  {
    if (commandline_journal && commandline_block != -1)
    {
      print_block_descriptors(commandline_block);
    }
    else
    {
      if (commandline_journal_block != -1 && commandline_journal)
      {
	// Translate block number.
	commandline_block = journal_block_to_real_block(commandline_journal_block);
	commandline_group = block_to_group(super_block, commandline_block);
      }
      unsigned char* block = new unsigned char[block_size_];    
      if (EXTERNAL_BLOCK && commandline_block == 0)
      {
	assert(block_size_ == sizeof(someones_block));
	std::memcpy(block, someones_block, block_size_);
	DirectoryBlockStats stats;
	int blocknr = commandline_block;
	commandline_block = -1;
	inode_count_ = someones_inode_count;
	is_directory_type isdir = is_directory(block, blocknr, stats, false);
	std::cout << "is_directory returned " << isdir << " for someones_block." << std::endl;
	exit(EXIT_SUCCESS);
      }
      else
      {
	device.seekg(block_to_offset(commandline_block));
	ASSERT(device.good());
	device.read(reinterpret_cast<char*>(block), block_size_);
	ASSERT(device.good());
      }
      if (commandline_print)
      {
	std::cout << "Hex dump of block " << commandline_block << ":\n";
	print_block_to(std::cout, block);
	std::cout << '\n';
      }
      std::cout << "Group: " << commandline_group << '\n';
      unsigned int bit = commandline_block - first_data_block(super_block) - commandline_group * blocks_per_group(super_block);
      ASSERT(bit < 8U * block_size_);
      bitmap_ptr bmp = get_bitmap_mask(bit);
      DirectoryBlockStats stats;
      is_directory_type isdir = is_directory(block, commandline_block, stats, false);
      if (block_bitmap[commandline_group] == NULL)
	load_meta_data(commandline_group);
      bool allocated = (block_bitmap[commandline_group][bmp.index] & bmp.mask);
      bool journal = is_journal(commandline_block);
      if (isdir == isdir_no)
      {
	if (allocated)
	{
	  std::cout << "Block " << commandline_block;
	  if (journal)
	  {
	    std::cout << " belongs to the journal.";
	    int real_block;
	    journal_header_t* header = reinterpret_cast<journal_header_t*>(block);
	    if (be2le(header->h_magic) == JFS_MAGIC_NUMBER)
	    {
	      std::cout << "\n\n";
	      switch (be2le(header->h_blocktype))
	      {
		case JFS_DESCRIPTOR_BLOCK:
		{
		  std::cout << *header << '\n';
		  journal_block_tag_t* journal_block_tag = reinterpret_cast<journal_block_tag_t*>(block + sizeof(journal_header_t));
		  int curblock = commandline_block;
		  for (;;)
		  {
		    uint32_t flags = be2le(journal_block_tag->t_flags);
		    ++curblock;
		    while(is_indirect_block_in_journal(curblock))
		      ++curblock;
		    int refered_block = be2le(journal_block_tag->t_blocknr);
		    std::cout << "  " << curblock << ((flags & JFS_FLAG_ESCAPE) ? "(escaped)" : "") << " = " <<
			refered_block << ((flags & JFS_FLAG_DELETED) ? "(deleted)" : "") << '\n';
		    if ((flags & JFS_FLAG_LAST_TAG))
		      break;
		    if (!(flags & JFS_FLAG_SAME_UUID))
		      journal_block_tag = reinterpret_cast<journal_block_tag_t*>((unsigned char*)journal_block_tag + 16);
		    ++journal_block_tag;
		  }
		  break;
		}
		case JFS_COMMIT_BLOCK:
		{
		  std::cout << *header << '\n';
		  break;
		}
		case JFS_SUPERBLOCK_V1:
		case JFS_SUPERBLOCK_V2:
		{
		  std::cout << *reinterpret_cast<journal_superblock_t*>(block) << '\n';
		  break;
		}
		case JFS_REVOKE_BLOCK:
		{
		  std::cout << *reinterpret_cast<journal_revoke_header_t*>(block) << '\n';
		  break;
		}
	      }
	    }
	    else if ((real_block = is_inode_block(commandline_block)))
	    {
	      std::cout << " It contains inode table block " << real_block << ".\n";
	      if (commandline_print)
	      {
		int inodenr = block_to_inode(real_block);
	        for (Inode const* inode = reinterpret_cast<Inode const*>(block); reinterpret_cast<unsigned char const*>(inode) < block + block_size_;
		    inode = reinterpret_cast<Inode const*>(reinterpret_cast<unsigned char const*>(inode) + inode_size_), ++inodenr)
		{
		  std::cout << "\n--------------Inode " << inodenr << "-----------------------\n";
		  print_inode_to(std::cout, *inode);
	        }
	      }
	    }
	    else
	      std::cout << '\n';
	  }
	  else
	  {
	    std::cout << " is Allocated.";
	    if (is_inode(commandline_block))
	    {
	      int inode = block_to_inode(commandline_block);
	      std::cout << " It's inside the inode table of group " << commandline_group <<
		  " (inodes [" << inode << " - " << (inode + block_size_ / inode_size_) << ">).";
	    }
	    std::cout << '\n';
	  }
	}
	else
	{
	  std::cout << "Block " << commandline_block << " is Unallocated.\n";
	  // If this assertion fails, then it is possible that this DATA block looks like an inode,
	  // most likely because the data itself is an ext3 filesystem. For example an ext3 image.
	  // If that is possible, then just comment this assertion out.
	  //ASSERT(!is_inode(commandline_block));	// All inode blocks are allocated.
	  ASSERT(!journal);			// All journal blocks are allocated.
	}
	if (is_indirect_block(block))
	{
	  std::cout << "Block " << commandline_block << " appears to be an (double/tripple) indirect block.\n";
	  if (commandline_print)
	  {
	    std::cout << "It contains the following block numbers:\n";
	    __le32* block_numbers = reinterpret_cast<__le32*>(block);
	    for (int i = 0; i < block_size_ >> 2; ++i)
	    {
	      std::cout << ' ' << std::setw(9) << std::setfill(' ') << block_numbers[i];
	      if ((i + 1) % 10 == 0)
	        std::cout << '\n';
	    }
	    std::cout << '\n';
	  }
	}
      }
      else
      {
	std::cout << "\nBlock " << commandline_block << " is a directory. The block is " <<
	    (allocated ? journal ? "a Journal block" : "Allocated" : "Unallocated") << "\n\n";
	if (commandline_ls)
	  print_restrictions();
	if (isdir == isdir_start)
	{
	  ext3_dir_entry_2* dir_entry = reinterpret_cast<ext3_dir_entry_2*>(block);
	  InodePointer inode = get_inode(dir_entry->inode);
	  if (!is_directory(inode) || (inode->block()[0] && inode->block()[0] != (__le32)commandline_block))
	  {
	    print_directory(block, commandline_block);
	    std::cout << "WARNING: inode " << dir_entry->inode << " was reallocated!\n";
	  }
	  else if (!inode->block()[0])
	  {
	    print_directory(block, commandline_block);
	    if (allocated)	// Is this at all possible?
	      std::cout << "WARNING: inode " << dir_entry->inode << " doesn't contain any blocks. This directory was deleted.\n";
	  }
	  else
	  {
#ifdef CPPGRAPH
            // Tell cppgraph that we call print_directory_action from here.
            iterate_over_all_blocks_of__with__print_directory_action();
#endif
	    // Run over all blocks.
	    bool reused_or_corrupted_indirect_block1 = iterate_over_all_blocks_of(inode, dir_entry->inode, print_directory_action);
	    if (reused_or_corrupted_indirect_block1)
	    {
	      std::cout << "Note: Block " << commandline_block << " is a directory start, it's \".\" entry has inode " << dir_entry->inode <<
		  " which is indeed a directory, but this inode has reused or corrupted (double/triple) indirect blocks so that not all"
		  " directory blocks could be printed!\n";
	    }
	  }
	}
	else
	  print_directory(block, commandline_block);
      }
      delete [] block;
    }
  }
  // Make sure the output directory exists.
  if (!commandline_restore_file.empty() || commandline_restore_all || !commandline_restore_inode.empty())
  {
    struct stat statbuf;
    if (stat(outputdir.c_str(), &statbuf) == -1)
    {
      if (errno != ENOENT)
      {
	int error = errno;
	std::cout << std::flush;
	std::cerr << progname << ": stat: " << outputdir << ": " << strerror(error) << std::endl;
	exit(EXIT_FAILURE);
      }
      else if (mkdir(outputdir.c_str(), 0755) == -1 && errno != EEXIST)
      {
        int error = errno;
	std::cout << std::flush;
	std::cerr << progname << ": failed to create output directory " << outputdir << ": " << strerror(error) << std::endl;
	exit(EXIT_FAILURE);
      }
      std::cout << "Writing output to directory " << outputdir << std::endl;
    }
    else if (!S_ISDIR(statbuf.st_mode))
    {
      std::cout << std::flush;
      std::cerr << progname << ": " << outputdir << " exists but is not a directory!" << std::endl;
      exit(EXIT_FAILURE);
    }
  }
  // Handle --dump-names
  if (commandline_restore_all || commandline_dump_names)
    dump_names();
  // Handle --restore-file
  if (!commandline_restore_file.empty())
    for (std::vector<std::string>::iterator iter = commandline_restore_file.begin(); iter != commandline_restore_file.end(); ++iter)
      restore_file(*iter);
  // Handle --restore-inode
  if (!commandline_restore_inode.empty())
  {
    std::istringstream is(commandline_restore_inode);
    int inodenr;
    char comma;
    while(is >> inodenr)
    {
      InodePointer real_inode = get_inode(inodenr);
      std::ostringstream oss;
      oss << "inode." << inodenr;
      restore_inode(inodenr, real_inode, oss.str());
      is >> comma;
    };
  }
  // Handle --show-hardlinks
  if (commandline_show_hardlinks)
    show_hardlinks();
  // Handle --journal-transaction
  if (commandline_journal_transaction != -1)
    handle_commandline_journal_transaction();
  // Handle --histogram
  if (commandline_histogram)
  {
    std::cout << '\n';
    if (commandline_group != -1)
      std::cout << "Only showing histogram of group " << commandline_group << '\n';
    print_restrictions();
    if (commandline_deleted || commandline_histogram == hist_dtime)
      std::cout << "Only showing deleted entries.\n";
    if (commandline_histogram == hist_atime ||
        commandline_histogram == hist_ctime ||
	commandline_histogram == hist_mtime ||
	commandline_histogram == hist_dtime)
      hist_init(commandline_after, commandline_before);
    else if (commandline_histogram == hist_group)
      hist_init(0, groups_);
    // Run over all (requested) groups.
    for (int group = 0, ibase = 0; group < groups_; ++group, ibase += inodes_per_group_)
    {
      if (commandline_group != -1 && group != commandline_group)
	continue;
      // Run over all inodes.
      for (int bit = 0, inode_number = ibase + 1; bit < inodes_per_group_; ++bit, ++inode_number)
      {
	InodePointer inode(get_inode(inode_number));
	if (commandline_deleted && !inode->is_deleted())
	  continue;
	if ((commandline_histogram == hist_dtime || commandline_histogram == hist_group) && !inode->has_valid_dtime())
          continue;
	if (commandline_directory && !is_directory(inode))
	  continue;
	if (commandline_allocated || commandline_unallocated)
	{
	  bitmap_ptr bmp = get_bitmap_mask(bit);
	  bool allocated = (inode_bitmap[group][bmp.index] & bmp.mask);
	  if (commandline_allocated && !allocated)
	    continue;
	  if (commandline_unallocated && allocated)
	    continue;
	}
	time_t xtime = 0;
	if (commandline_histogram == hist_dtime)
	  xtime = inode->dtime();
	else if (commandline_histogram == hist_atime)
	{
	  xtime = inode->atime();
	  if (xtime == 0)
	    continue;
        }
	else if (commandline_histogram == hist_ctime)
	{
	  xtime = inode->ctime();
	  if (xtime == 0)
	    continue;
	}
	else if (commandline_histogram == hist_mtime)
	{
	  xtime = inode->mtime();
	  if (xtime == 0)
	    continue;
        }
	if (xtime && commandline_after <= xtime && xtime < commandline_before)
	  hist_add(xtime);
	if (commandline_histogram == hist_group)
	{
	  if (commandline_after && commandline_after > (time_t)inode->dtime())
	    continue;
	  if (commandline_before && (time_t)inode->dtime() >= commandline_before)
	    continue;
	  hist_add(group);
        }
      }
    }
    hist_print();
  }
  // Handle --search and --search-start
  if (!commandline_search_start.empty() || !commandline_search.empty())
  {
    bool start = !commandline_search_start.empty();
    size_t len = start ? commandline_search_start.length() : commandline_search.length();
    ASSERT(len <= (size_t)block_size_);
    char* pattern = new char [len];
    strncpy(pattern, start ? commandline_search_start.data() : commandline_search.data(), len);
    static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
    if (commandline_allocated && commandline_unallocated)
      commandline_allocated = commandline_unallocated = false;
    if (commandline_allocated)
      std::cout << "Allocated blocks ";
    else if (commandline_unallocated)
      std::cout << "Unallocated blocks ";
    else
      std::cout << "Blocks ";
    std::cout << (start ? "starting with" : "containing") << " \"" << std::string(pattern, len) << "\":" << std::flush;
    ASSERT((inodes_per_group_ * inode_size_) % block_size_ == 0);
    for (int group = 0; group < groups_; ++group)
    {
      int first_block = group_to_block(super_block, group);  
      int last_block = std::min(first_block + blocks_per_group(super_block), block_count(super_block));
      // Skip inodes.
      int inode_table = group_descriptor_table[group].bg_inode_table;
      first_block = inode_table + inodes_per_group_ * inode_size_ / block_size_;
      unsigned int bit = first_block - first_data_block(super_block) - group * blocks_per_group(super_block);
      for (int block = first_block; block < last_block; ++block, ++bit)
      {
	bitmap_ptr bmp = get_bitmap_mask(bit);
	bool allocated = (block_bitmap[group][bmp.index] & bmp.mask);
	if (commandline_allocated && !allocated)
	  continue;
	if (commandline_unallocated && allocated)
	  continue;
	bool found = false;
        get_block(block, block_buf);
        if (start)
	{
#if 1
	  if (std::memcmp(block_buf, pattern, len) == 0)
	    found = true;
#else
          if (std::isdigit(block_buf[0]) && std::isdigit(block_buf[1]) && std::isdigit(block_buf[2]) && block_buf[3] == ' ' && std::isdigit(block_buf[4]) &&
	      std::isdigit(block_buf[5]) && block_buf[9] == 0 && block_buf[10] == 0 && block_buf[11] == 0 && block_buf[12] == 0 &&
	      block_buf[13] == 0 && block_buf[14] == 0 && block_buf[15] == 0 && block_buf[16] == 0)
	    std::cout << block << " : " << block_buf << '\n';
#endif
	}
        else
	{
	  for (unsigned char* ptr = block_buf; ptr < block_buf + block_size_ - len; ++ptr)
	  {
	    if (*ptr == *pattern &&
	        (len == 1 || (ptr[1] == pattern[1] &&
		(len == 2 || (ptr[2] == pattern[2] && std::memcmp(ptr, pattern, len) == 0)))))
	    {
	      found = true;
	      break;
	    }
	  }
	}
	if (found)
	{
	  if (!commandline_allocated && allocated)
	    std::cout << ' ' << block << " (allocated)" << std::flush;
          else
	    std::cout << ' ' << block << std::flush;
        }
      }
    }
    delete [] pattern;
    std::cout << '\n';
  }
  // Handle --search-inode
  if (commandline_search_inode != -1)
  {
    std::cout << "Inodes refering to block " << commandline_search_inode << ':' << std::flush;
    for (uint32_t inode = 1; inode <= inode_count_; ++inode)
    {
      InodePointer ino = get_inode(inode);
      if (is_symlink(ino))
        continue;		// Does not refer to any block, and indirect blocks to run over.
      find_block_data_st data;
      data.block_looking_for = commandline_search_inode;
      data.found_block = false;
#ifdef CPPGRAPH
      // Tell cppgraph that we call find_block_action from here.
      iterate_over_all_blocks_of__with__find_block_action();
#endif
      bool reused_or_corrupted_indirect_block2 = iterate_over_all_blocks_of(ino, inode, find_block_action, &data);
      if (reused_or_corrupted_indirect_block2)
      {
	std::cout << "\nWARNING: while iterating over all blocks of inode " << inode <<
	    " a reused or corrupt indirect block was encountered; search aborted.\n";
        std::cout << "Inodes refering to block " << commandline_search_inode << " (cont):" << std::flush;
      }
      if (data.found_block)
        std::cout << ' ' << inode << std::flush;
    }
    std::cout << '\n';
  }
  // Handle --search-zeroed-inodes
  if (commandline_search_zeroed_inodes)
  {
    std::cout << "Allocated inodes filled with zeroes:" << std::flush;
    for (uint32_t inode = 1; inode <= inode_count_; ++inode)
    {
      if (commandline_group != -1)
      {
	int group = (inode - 1) / inodes_per_group_;
	if (group != commandline_group)
	  continue;
      }
      InodePointer ino = get_inode(inode);
      static char zeroes[128] = {0, };
      if (is_allocated(inode) && std::memcmp(&ino, zeroes, sizeof(zeroes)) == 0)
        std::cout << ' ' << inode << std::flush;
    }
    std::cout << '\n';
  }
  // Handle --inode-to-block
  if (commandline_inode_to_block != -1)
  {
    if ((uint32_t)commandline_inode_to_block > inode_count_)
    {
      std::cout << std::flush;
      std::cerr << progname << ": --inode-to-block: inode " << commandline_inode_to_block << " is out of range. There are only " << inode_count_ << " inodes." << std::endl;
      exit(EXIT_FAILURE);
    }
    int block = inode_to_block(super_block, commandline_inode_to_block);
    std::cout << "Inode " << commandline_inode_to_block << " resides in block " << block <<
        " at offset 0x" << std::hex << ((commandline_inode_to_block - block_to_inode(block)) * inode_size_) << std::dec << ".\n";
  }
  // Handle --show-journal-inodes
  if (commandline_show_journal_inodes != -1)
    show_journal_inodes(commandline_show_journal_inodes);

  // Print some useful information if no useful information was printed yet.
  if (!commandline_action && !commandline_journal)
  {
    std::cout << "\nNo action was specified. For example, specify one of:\n";
    std::cout << "    --inode ino            Show info on inode 'ino'; inode " << EXT3_ROOT_INO << " is the root.\n";
    std::cout << "    --block blk [--ls]     Show info on block 'blk'.\n";
    std::cout << "    --histogram=dtime --after=1000000000 --before=1400000000\n";
    std::cout << "                           Show deletion-time histogram (zoom in afterwards).\n";
    std::cout << "    --help                 Show all possible command line options.\n";
  }

  // Clean up.
  if (commandline_action)
  {
    delete [] inodes_buf;
    for (int group = 0; group < groups_; ++group)
    {
      if (block_bitmap[group])
      {
	delete [] inode_bitmap[group];
	delete [] block_bitmap[group];
#if !USE_MMAP
	delete [] all_inodes[group];
#endif
      }
#if USE_MMAP
      if (all_inodes[group])
	inode_unmap(group);
#endif
    }
    delete [] inode_bitmap;
    delete [] block_bitmap;
    delete [] all_inodes;
#if USE_MMAP
    ASSERT(nr_mmaps == 0);
    delete [] all_mmaps;
    delete [] refs_to_mmap;
#endif
    delete [] group_descriptor_table;
  }
}

int main(int argc, char* argv[])
{
  Debug(debug::init());

#ifdef USE_SVN
  std::cout << "Running " << svn_revision << '\n';
#else
  std::cout << "Running ext3grep version " VERSION "\n";
#endif

  decode_commandline_options(argc, argv);

  // Sanity checks on the user.

  if (argc != 1)
  {
    if (argc == 0)
      std::cerr << progname << ": Missing device name. Use --help for a usage message." << std::endl;
    else
      std::cerr << progname << ": Too many non-options. Use --help for a usage message." << std::endl;
    exit(EXIT_FAILURE);
  }
  struct stat statbuf;
  if (stat(*argv, &statbuf) == -1)
  {
    int error = errno;
    std::cout << std::flush;
    std::cerr << progname << ": stat \"" << *argv << "\": " << strerror(error) << std::endl;
    exit(EXIT_FAILURE);
  }
  if (S_ISDIR(statbuf.st_mode))
  {
    std::cerr << progname << ": \"" << *argv << "\" is a directory. You need to use the raw ext3 filesystem device (or a copy thereof)." << std::endl;
    exit(EXIT_FAILURE);
  }
  if (!S_ISBLK(statbuf.st_mode) && statbuf.st_size < SUPER_BLOCK_OFFSET + 1024)
  {
    std::cerr << progname << ": \"" << *argv << "\" is not an ext3 fs; it's WAY too small (" << statbuf.st_size << " bytes)." << std::endl;
    exit(EXIT_FAILURE);
  }

  // Open the device.
  device.open(*argv);
  if (!device.good())
  {
    int error = errno;
    std::cout << std::flush;
    std::cerr << progname << ": failed to read-only open device \"" << *argv << "\": " << strerror(error) << std::endl;
    exit(EXIT_FAILURE);
  }
#if USE_MMAP
  device_fd = open(*argv, O_RDONLY);
  if (device_fd == -1)
  {
    int error = errno;
    std::cout << std::flush;
    std::cerr << progname << ": failed to open device \"" << *argv << "\" for reading: " << strerror(error) << std::endl;
    exit(EXIT_FAILURE);
  }
#endif

  // Read the first superblock.

  // The size of a super block is 1024 bytes.
  assert(sizeof(ext3_super_block) == 1024);
  device.seekg(SUPER_BLOCK_OFFSET);
  if (!device.good())
  {
    int error = errno;
    std::cout << std::flush;
    std::cerr << progname << ": failed to seek to position " << SUPER_BLOCK_OFFSET << " of \"" << *argv << "\": " << strerror(error) << std::endl;
    exit(EXIT_FAILURE);
  }
  // super_block is initialized here.
  device.read(reinterpret_cast<char*>(&super_block), sizeof(ext3_super_block));
  if (!device.good())
  {
    int error = errno;
    std::cout << std::flush;
    std::cerr << progname << ": failed to read first superblock from \"" << *argv << "\": " << strerror(error) << std::endl;
    exit(EXIT_FAILURE);
  }

  // Initialize global constants.
  device_name = *argv;
  init_consts();

  try
  {
    run_program();
  }
  catch (std::bad_alloc& error)
  {
    std::cerr << "Caught exception " << error.what() << '\n';
#ifdef CWDEBUG
    // We never get here, because libcwd doesn't throw bad::alloc: it dumps core.
    Dout(dc::malloc, malloc_report << '.');
#else
    std::cerr << "Please install libcwd (http://sourceforge.net/project/showfiles.php?group_id=47536),"
        " reconfigure & recompile ext3grep and rerun the command with --debug." << std::endl;
#endif
    exit(EXIT_FAILURE);
  }

  device.close();
#if USE_MMAP
  close(device_fd);
#endif
}
