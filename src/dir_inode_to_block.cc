// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file dir_inode_to_block.cc Code related to dir_inode_to_block.
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
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#endif

#include "blocknr_vector_type.h"
#include "globals.h"
#include "superblock.h"
#include "get_block.h"
#include "is_blockdetection.h"
#include "forward_declarations.h"
#include "print_inode_to.h"
#include "directories.h"
#include "journal.h"

//-----------------------------------------------------------------------------
//
// dir_inode_to_block
//

// dir_inode_to_block_cache is an array of either
// one block number stored directly, or pointers to an
// array with more than one block (allocated with new).
// The first entry of such an array contains the length
// of the array.
//
// This pseudo vector only stores non-zero block values.
// If 'blocknr' is empty, then the vector is empty.

blocknr_vector_type* dir_inode_to_block_cache;
std::vector<int> extended_blocks;

#define INCLUDE_JOURNAL 1

// Returns true if file 'cachename' does not end
// on '# END\n'.
bool does_not_end_on_END(std::string const& cachename)
{
  // Open the file.
  std::ifstream cache;
  cache.open(cachename.c_str());
  // Seek to the end minus 6 positions.
  cache.seekg(-6, std::ios::end);
  char last_line[6];
  cache.getline(last_line, sizeof(last_line));
  bool does_not = strcmp(last_line, "# END") != 0;
  cache.close();
  return does_not;
}

void init_dir_inode_to_block_cache(void)
{
  if (dir_inode_to_block_cache)
    return;

  DoutEntering(dc::notice, "init_dir_inode_to_block_cache()");

  ASSERT(sizeof(size_t) == sizeof(uint32_t*));	// Used in blocknr_vector_type.
  ASSERT(sizeof(size_t) == sizeof(blocknr_vector_type));

  dir_inode_to_block_cache = new blocknr_vector_type [inode_count_ + 1];
  std::memset(dir_inode_to_block_cache, 0, sizeof(blocknr_vector_type) * (inode_count_ + 1));
  std::string device_name_basename = device_name.substr(device_name.find_last_of('/') + 1);
  std::string cache_stage1 = device_name_basename + ".ext3grep.stage1";
  struct stat sb;
  bool have_cache = !(stat(cache_stage1.c_str(), &sb) == -1);
  if (have_cache)
  {
    if (does_not_end_on_END(cache_stage1))
      have_cache = false;
  }
  else if (errno != ENOENT)
  {
    int error = errno;
    std::cout << std::flush;
    std::cerr << progname << ": failed to open \"" << cache_stage1 << "\": " << strerror(error) << std::endl;
    exit(EXIT_FAILURE);
  }
  if (!have_cache)
  {
    std::cout << "Finding all blocks that might be directories.\n";
    std::cout << "D: block containing directory start, d: block containing more directory entries.\n";
    std::cout << "Each plus represents a directory start that references the same inode as a directory start that we found previously.\n";
    static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
    for (int group = 0; group < groups_; ++group)
    {
      std::cout << "\nSearching group " << group << ": " << std::flush;
      int first_block = first_data_block(super_block) + group * blocks_per_group(super_block);
      int last_block = std::min(first_block + blocks_per_group(super_block), block_count(super_block));
      for (int block = first_block; block < last_block; ++block)
      {
#if !INCLUDE_JOURNAL
	if (is_journal(block))
	  continue;
#endif
	unsigned char* block_ptr = get_block(block, block_buf);
	DirectoryBlockStats stats;
	is_directory_type result = is_directory(block_ptr, block, stats, false);
	if (result == isdir_start)
	{
	  ext3_dir_entry_2* dir_entry = reinterpret_cast<ext3_dir_entry_2*>(block_ptr);
	  ASSERT(dir_entry->name_len == 1 && dir_entry->name[0] == '.');
	  if (dir_inode_to_block_cache[dir_entry->inode].empty())
	    std::cout << 'D' << std::flush;
	  else
	    std::cout << '+' << std::flush;
	  dir_inode_to_block_cache[dir_entry->inode].push_back(block);
	}
	else if (result == isdir_extended)
	{
	  std::cout << 'd' << std::flush;
	  extended_blocks.push_back(block);
        }
      }
    }
    std::cout << '\n';
    std::cout << "Writing analysis so far to '" << cache_stage1 << "'. Delete that file if you want to do this stage again.\n";
    std::ofstream cache;
    cache.open(cache_stage1.c_str());
    cache << "# Stage 1 data for " << device_name << ".\n";
    cache << "# Inodes and directory start blocks that use it for dir entry '.'.\n";
    cache << "# INODE : BLOCK [BLOCK ...]\n";
    for (uint32_t i = 1; i <= inode_count_; ++i)
    {
      blocknr_vector_type const bv = dir_inode_to_block_cache[i];
      if (bv.empty())
	continue;
      cache << i << " :";
      uint32_t const size = bv.size();
      for (uint32_t j = 0; j < size; ++j)
	cache << ' ' << bv[j];
      cache << '\n';
    }
    cache << "# Extended directory blocks.\n";
    for (std::vector<int>::iterator iter = extended_blocks.begin(); iter != extended_blocks.end(); ++iter)
      cache << *iter << '\n';
    cache << "# END\n";
    cache.close();
  }
  else
  {
    std::cout << "Loading " << cache_stage1 << "...\n";
    std::ifstream cache;
    cache.open(cache_stage1.c_str());
    if (!cache.is_open())
    {
      int error = errno;
      std::cout << std::flush;
      std::cerr << progname << ": failed to open " << cache_stage1 << ": " << strerror(error) << std::endl;
      exit(EXIT_FAILURE);
    }
    int inode;
    int block;
    char c;
    for(;;)
    {
      cache.get(c);
      if (c == '#')
        cache.ignore(std::numeric_limits<int>::max(), '\n');
      else
      {
        cache.putback(c);
        break;
      }
    }
    while (cache >> inode)
    {
      cache >> c;
      if (cache.eof())
	break;
      ASSERT(c == ':');
      std::vector<uint32_t> blocknr;
      while(cache >> block)
      {
	blocknr.push_back(block);
	c = cache.get();
	if (c != ' ')
	{
	  ASSERT(c == '\n');
	  break;
	}
      }
      dir_inode_to_block_cache[inode] = blocknr;
    }
    cache.clear();
    for(;;)
    {
      cache.get(c);
      if (c == '#')
        cache.ignore(std::numeric_limits<int>::max(), '\n');
      else
      {
        cache.putback(c);
        break;
      }
    }
    while (cache >> block)
      extended_blocks.push_back(block);
    cache.close();
  }
  int inc = 0, sinc = 0, ainc = 0, asinc = 0, cinc = 0;
  for (uint32_t i = 1; i <= inode_count_; ++i)
  {
    bool allocated = is_allocated(i);
    blocknr_vector_type const bv = dir_inode_to_block_cache[i];
    if (allocated)
    {
      InodePointer inode = get_inode(i);
      if (is_directory(inode))
      {
	++ainc;
	uint32_t first_block = inode->block()[0];
	// If the inode is an allocated directory, it must reference at least one block.
	if (!first_block)
	{
	  std::cout << std::flush;
	  std::cerr << progname << ": inode " << i << " is an allocated inode that does not reference any block. "
	      "This seems to indicate a corrupted file system. Manual investigation is needed." << std::endl;
	}
	ASSERT(first_block);
	// If inode is an allocated directory, then we must have found it's directory block already.
	if (bv.empty())
	{
	  std::cout << std::flush;
	  std::cerr << "---- Mail this to the mailinglist -------------------------------\n";
	  std::cerr << "WARNING: inode " << i << " is an allocated inode without directory block pointing to it!" << std::endl;
	  std::cerr << "         inode_size_ = " << inode_size_ << '\n';
	  std::cerr << "         Inode " << i << ":";
	  print_inode_to(std::cerr, inode);
	  DirectoryBlockStats stats;
	  unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
          get_block(first_block, block_buf);
	  is_directory_type isdir = is_directory(block_buf, first_block, stats, false);
	  std::cerr << "         is_directory(" << first_block << ") returns " << isdir << '\n';
	  if (isdir == isdir_no)
	  {
	    std::cerr << "         Hex dump:\n";
	    print_block_to(std::cerr, block_buf); 
	  }
	  std::cerr << "-----------------------------------------------------------------\n";
	  continue;
	}
	int count = 0;
	uint32_t size = bv.size();
	for (uint32_t j = 0; j < size; ++j)
	  if (bv[j] == first_block)
	  {
	    ++count;
	    break;	// Remaining blocks have different value.
	  }
	// We must have found the actual directory.
	ASSERT(count == 1);
	// Replace the blocks we found with the canonical block.
	dir_inode_to_block_cache[i].erase();
	dir_inode_to_block_cache[i].push_back(first_block);
	++cinc;
      }
    }
    if (bv.empty())
      continue;
    ++inc;
    if (bv.is_vector())
    {
      ++sinc;
      if (allocated)
	++asinc;
    }
  }
  std::cout << "Result of stage one:\n";
  std::cout << "  " << inc << " inodes are referenced by one or more directory blocks, " <<
      ainc << " of those inodes " << ((ainc == 1) ? "is" : "are") << " still allocated.\n";
  std::cout << "  " << sinc << " inodes are referenced by more than one directory block, " <<
      asinc << " of those inodes " << ((asinc == 1) ? "is" : "are") << " still allocated.\n";
  std::cout << "  " << extended_blocks.size() << " blocks contain an extended directory.\n";
  // Resolve shared inodes.
  int esinc = 0, jsinc = 0, hsinc = 0;
  for (uint32_t i = 1; i <= inode_count_; ++i)
  {
    // All blocks refering to this inode.
    blocknr_vector_type const bv = dir_inode_to_block_cache[i];
    // None?
    if (bv.empty())
      continue;
    uint32_t size = bv.size();
    // Only one? Then we're done.
    if (size == 1)
      continue;

    // Make a list of these blocks as DirectoryBlock.
    std::list<DirectoryBlock> dirs(size);
    std::list<DirectoryBlock>::iterator iter = dirs.begin();
    for (uint32_t j = 0; j < size; ++j, ++iter)
      iter->read_block(bv[j], iter);

    // Remove blocks that are part of the journal, except if all blocks
    // are part of the journal: then keep the block with the highest
    // sequence number.
#if INCLUDE_JOURNAL
    uint32_t highest_sequence = 0;
    int min_block = std::numeric_limits<int>::max();
    int journal_block_count = 0;
    int total_block_count = 0;
    iter = dirs.begin();
    while (iter != dirs.end())
    {
      ++total_block_count;
      if (is_journal(iter->block()))
      {
        ++journal_block_count;
	block_in_journal_to_descriptors_map_type::iterator iter2 = block_in_journal_to_descriptors_map.find(iter->block());
	if (iter2 != block_in_journal_to_descriptors_map.end())
	{
	  uint32_t sequence = iter2->second->sequence();
	  highest_sequence = std::max(highest_sequence, sequence);
	}
	else
	  min_block = std::min(min_block, iter->block());
      }
      else
        break;	// No need to continue.
      ++iter;
    }
    bool need_keep_one_journal = (total_block_count == journal_block_count);
#endif
    iter = dirs.begin();
    while (iter != dirs.end())
    {
#if !INCLUDE_JOURNAL
      ASSERT(!is_journal(iter->block()));
#else
      if (is_journal(iter->block()))
      {
        if (need_keep_one_journal)
	{
	  block_in_journal_to_descriptors_map_type::iterator iter2 = block_in_journal_to_descriptors_map.find(iter->block());
	  if (highest_sequence == 0 && iter->block() == min_block)
	  {
	    std::cout << std::flush;
	    std::cerr << "WARNING: More than one directory block references inode " << i <<
	        " but all of them are in the journal and none of them have a descriptor block (the start of the transaction was probably overwritten)."
		" The mostly likely correct directory block would be block " << min_block <<
		" but we're disregarding it because ext3grep can't deal with journal blocks without a descriptor block.";
	    std::cerr << std::endl;
	  }
	  if (iter2 != block_in_journal_to_descriptors_map.end() && iter2->second->sequence() == highest_sequence)
	  {
	    ++iter;
	    continue;
	  }
	}
	if (size > 1)
	  dir_inode_to_block_cache[i].remove(iter->block());
	else
	  dir_inode_to_block_cache[i].erase();
	--size;
	iter = dirs.erase(iter);
      }
      else
#endif
	++iter;
    }
    // Only one left? Then we're done with this inode.
    if (dirs.size() == 1)
    {
      ++jsinc;
      continue;
    }
    ASSERT(dirs.size() > 0);
    ASSERT(size == dirs.size());

    // Find blocks in the journal and select the one with the highest sequence number.
    int best_blocknr = -1;
    uint32_t max_sequence = 0;
    iter = dirs.begin();
    for (iter = dirs.begin(); iter != dirs.end(); ++iter)
    {
      int blocknr = iter->block();
      uint32_t sequence_found = find_largest_journal_sequence_number(blocknr);
      if (sequence_found > max_sequence)
      {
	max_sequence = sequence_found;
	best_blocknr = blocknr;
      }
    }
    if (best_blocknr != -1)
    {
      iter = dirs.begin();
      while (iter != dirs.end())
      {
	if (iter->block() != best_blocknr)
	{
	  dir_inode_to_block_cache[i].remove(iter->block());
	  iter = dirs.erase(iter);
	}
	else
	  ++iter;
      }
    }
    // Only one left? Then we're done with this inode.
    if (dirs.size() == 1)
    {
      ++hsinc;
      continue;
    }

    // Remove blocks that are exactly equal.
    iter = dirs.begin();
    while (iter != dirs.end())
    {
      bool found_duplicate = false;
      for (std::list<DirectoryBlock>::iterator iter2 = dirs.begin(); iter2 != iter; ++iter2)
	if (iter2->exactly_equal(*iter))
	{
	  found_duplicate = true;
	  break;
	}
      if (found_duplicate)
      {
	dir_inode_to_block_cache[i].remove(iter->block());
	iter = dirs.erase(iter);
      }
      else
	++iter;
    }
    // Only one left? Then we're done with this inode.
    if (dirs.size() == 1)
    {
      ++esinc;
      continue;
    }

  }	// Next inode.

  std::cout << "Result of stage two:\n";
  if (cinc > 0)
    std::cout << "  " << cinc << " of those inodes could be resolved because " << ((cinc == 1) ? "it is" : "they are") << " still allocated.\n";
  if (jsinc > 0)
    std::cout << "  " << jsinc << " inodes could be resolved because all refering blocks but one were journal blocks.\n";
  if (hsinc > 0)
    std::cout << "  " << hsinc << " inodes could be resolved because at least one of the blocks was found in the journal.\n";
  if (esinc > 0)
    std::cout << "  " << esinc << " inodes could be resolved because all refering blocks were exactly identical.\n";
  if (sinc - asinc - jsinc - esinc - hsinc > 0)
  {
    std::cout << "  " << sinc - asinc - jsinc - esinc - hsinc << " remaining inodes to solve...\n";
    std::cout << "Blocks sharing the same inode:\n";
    std::cout << "# INODE : BLOCK [BLOCK ...]\n";
    for (uint32_t i = 1; i <= inode_count_; ++i)
    {
      blocknr_vector_type const bv = dir_inode_to_block_cache[i];
      if (bv.empty())
	continue;
      uint32_t size = bv.size();
      if (size == 1)
	continue;
      std::cout << i << " :";
      for (uint32_t j = 0; j < size; ++j)
	std::cout << ' ' << bv[j];
      std::cout << '\n';
    }
  }
  else
    std::cout << "All directory inodes are accounted for!\n";
  std::cout << '\n';
}

void init_directories(void);

int dir_inode_to_block(uint32_t inode)
{
  ASSERT(inode > 0 && inode <= inode_count_);
  if (!dir_inode_to_block_cache)
    init_directories();
  blocknr_vector_type const bv = dir_inode_to_block_cache[inode];
  if (bv.empty())
    return -1;
  // In case of multiple values... return one.
  return bv[0];
}
