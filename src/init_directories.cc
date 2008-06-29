// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file init_directories.cc Implementation of init_directories (stage 2).
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
#include <cerrno>
#include <sstream>
#endif

#include "locate.h"
#include "init_directories.h"
#include "blocknr_vector_type.h"
#include "Parent.h"
#include "forward_declarations.h"
#include "commandline.h"
#include "get_block.h"
#include "journal.h"
#include "dir_inode_to_block.h"

all_directories_type all_directories;
inode_to_directory_type inode_to_directory;

Directory::Directory(uint32_t inode_number, int first_block) : M_inode_number(inode_number), M_blocks(1)
#ifdef DEBUG
    , M_extended_blocks_added(false)
#endif
{
  std::list<DirectoryBlock>::iterator iter = M_blocks.begin();
  iter->read_block(first_block, iter);
}

typedef std::map<uint32_t, blocknr_vector_type> inode_to_extended_blocks_map_type;

bool init_directories_action(ext3_dir_entry_2 const& dir_entry, Inode const&, bool, bool, bool, bool, bool, bool, Parent* parent, void*)
{
  // Get the inode number.
  uint32_t const inode_number = dir_entry.inode;

  // If this is a new directory, skip iterating into it if we already processed it.
  // If it's directory '.' we need to continue with this function.
  if (dir_entry.name_len != 1 || dir_entry.name[0] != '.')
  {
    inode_to_directory_type::iterator iter = inode_to_directory.find(inode_number);
    return iter != inode_to_directory.end();
  }

  // If we get here then that means that 'inode_number' is a directory that
  // we have a first block for (dir_entry is for entry "."). We possibly found
  // more directory start blocks for this inode number in which case we'll
  // get here more than once for this inode number.

  // Get the first block.
  int first_block = dir_inode_to_block(inode_number);
  if (first_block == -1)
  {
    std::cout << std::flush;
    std::cerr << "ERROR: dir_inode_to_block(" << inode_number << ") returned -1.\n";
  }
  ASSERT(first_block != -1);

  // Store a new entry in the all_directories container.
  std::pair<all_directories_type::iterator, bool> res =
      all_directories.insert(all_directories_type::value_type(parent->dirname(false), Directory(inode_number, first_block)));
  if (!res.second)	// Did we already see this path before? Make sure the inode is consistent.
  {
    if (inode_number == res.first->second.inode_number() && first_block == res.first->second.first_block())
    {
      //std::cout << "Aborting recursion of " << parent->dirname(commandline_show_path_inodes) << '\n';
      return true;	// Abort recursion.
    }
    std::cout << "Directory \"" << parent->dirname(commandline_show_path_inodes) << "\" is linked to both inode/block " <<
        inode_number << '/' << first_block << " as well as " << res.first->second.inode_number() << '/' << res.first->second.first_block() << "\n";
    // If we don't do anything here, the assertion `directory.inode_number() == iter->first' in init_directories() will fail.
    // See http://groups.google.com/group/ext3grep/browse_thread/thread/38bbcc9bba214240/987815a7bba17190?hl=en#987815a7bba17190
    
    // Lets call inode_number/first_block 'new', and inode_number()/first_block() 'old'.
    int sequence_number_new = last_undeleted_directory_inode_refering_to_block(inode_number, first_block);
    int sequence_number_old = last_undeleted_directory_inode_refering_to_block(res.first->second.inode_number(), res.first->second.first_block());
    
    if (sequence_number_new == sequence_number_old)
    {
      std::cout << std::endl;
      std::cerr << "WARNING: ext3grep currently does not support this situation:\n";
      std::cerr << "         last_undeleted_directory_inode_refering_to_block(" << inode_number << ", " << first_block << ") = " << sequence_number_new << '\n';
      std::cerr << "         last_undeleted_directory_inode_refering_to_block(" << res.first->second.inode_number() << ", " << res.first->second.first_block() << ") = " << sequence_number_old << '\n';
      std::cerr << "Since most people don't like it if ext3grep aborts; we'll randomly pick one of them. It could be the WRONG one though." << std::endl;
      sequence_number_new = 0;	// Drop the new one.
    }

    if (sequence_number_new > sequence_number_old)
    {
      // The new inode/block pair is newer, therefore we keep 'inode_number' and replace all_directories element.
      std::cout << "Replacing " << res.first->second.inode_number() << '/' << res.first->second.first_block() <<
          " (sequence " << sequence_number_old << ") with " << inode_number << '/' << first_block;
      if (sequence_number_new == std::numeric_limits<int>::max())
	std::cout << " (allocated";
      else
	std::cout << " (sequence " << sequence_number_new;
      std::cout << ").\n";
      inode_to_directory_type::iterator iter = inode_to_directory.find(res.first->second.inode_number());
      ASSERT(iter != inode_to_directory.end());
      ASSERT(iter->second == res.first);
      inode_to_directory.erase(iter);
      all_directories.erase(res.first);
      res = all_directories.insert(all_directories_type::value_type(parent->dirname(false), Directory(inode_number, first_block)));
      ASSERT(res.second);
    }
    else
    {
      // The old inode/block pair is newer, therefore we keep the all_directories element
      // and do not insert the new inode in inode_to_directory. Moreover, we consider
      // the current directory block to unusable, so we abort recursion of it.
      std::cout << "Keeping " << res.first->second.inode_number() << '/' << res.first->second.first_block();
      if (sequence_number_old == std::numeric_limits<int>::max())
        std::cout << " (allocated";
      else
	std::cout << " (sequence " << sequence_number_old;
      std::cout << ") over " << inode_number << '/' << first_block << " (sequence " << sequence_number_new << ").\n";
      return true;	// Abort recursion.
    }

    // Consistency check:
    ASSERT(inode_number == res.first->second.inode_number());
  }
  std::pair<inode_to_directory_type::iterator, bool> res2 =
      inode_to_directory.insert(inode_to_directory_type::value_type(inode_number, res.first));
  if (!res2.second)	// Did we get here with this inode number before? Make sure the path is consistent!
  {
    if (inode_number == res2.first->second->second.inode_number() && res.first == res2.first->second)
    {
      //std::cout << "Aborting recursion of " << parent->dirname(commandline_show_path_inodes) << '\n';
      return true;	// Abort recursion.
    }

    std::cout << "Inode number " << inode_number << " is linked to both, " << parent->dirname(commandline_show_path_inodes) << " as well as " << res2.first->second->first << "!\n";
    bool new_path = path_exists(parent->dirname(false));
    bool old_path = path_exists(res2.first->second->first);
    if (new_path && !old_path)
    {
      std::cout << "Using \"" << parent->dirname(commandline_show_path_inodes) << "\" as \"" << res2.first->second->first << " doesn't exist in the locate database.\n";
      inode_to_directory.erase(res2.first);
      std::pair<inode_to_directory_type::iterator, bool> res3 =
	  inode_to_directory.insert(inode_to_directory_type::value_type(inode_number, res.first));
      ASSERT(res3.second);
    }
    else if (!new_path && old_path)
      std::cout << "Keeping \"" << res2.first->second->first << "\" as \"" << parent->dirname(commandline_show_path_inodes) << " doesn't exist in the locate database.\n";
    else if (!new_path && !old_path)
      std::cout << "WARNING: Neither exist in the locate database (you might want to add one). Keeping \"" << res2.first->second->first << "\".\n";
    ASSERT(!(new_path && old_path));
  }
  return false;
}

struct extended_directory_action_data_st {
  int blocknr;
  std::map<uint32_t, int> linked;	// inode to count (number of times a linked dir_entry refers to it).
  std::map<uint32_t, int> unlinked;	// inode to count (number of times an unlinked dir_entry refers to it).
};

bool filename_heuristics_action(ext3_dir_entry_2 const& dir_entry, Inode const& UNUSED(inode),
    bool UNUSED(deleted), bool UNUSED(allocated), bool UNUSED(reallocated), bool UNUSED(zero_inode), bool UNUSED(linked), bool UNUSED(filtered),
    Parent*, void* data)
{
  std::set<std::string>* filesnames = reinterpret_cast<std::set<std::string>*>(data);
  std::string filename(dir_entry.name, dir_entry.name_len);
  filesnames->insert(filename);
  return false;
}

#ifdef CPPGRAPH
void iterate_over_directory__with__filename_heuristics_action(void) { (void)filename_heuristics_action(*(ext3_dir_entry_2 const*)NULL, *(Inode const*)NULL, 0, 0, 0, 0, 0, 0, NULL, NULL); }
#endif

bool extended_directory_action(ext3_dir_entry_2 const& dir_entry, Inode const& inode,
    bool UNUSED(deleted), bool UNUSED(allocated), bool reallocated, bool zero_inode, bool linked, bool UNUSED(filtered), Parent*, void* ptr)
{
  extended_directory_action_data_st* data = reinterpret_cast<extended_directory_action_data_st*>(ptr);
  bool is_maybe_directory = true;	// Maybe, because if !feature_incompat_filetype then it isn't
  					// garanteed that the contents of the inode still belong to this entry.
  if (feature_incompat_filetype)
    is_maybe_directory = (dir_entry.file_type & 7) == EXT3_FT_DIR;
  else if (!zero_inode && !reallocated)
    is_maybe_directory = is_directory(inode);  
  if (is_maybe_directory && !zero_inode)
  {
    int blocknr2 = dir_inode_to_block(dir_entry.inode);
    if (blocknr2 == -1)
    {
      // Don't print this message if !feature_incompat_filetype && reallocated
      // because it more likely to just not being a directory inode.
      if (feature_incompat_filetype || !reallocated)
	std::cout << "Cannot find a directory block for inode " << dir_entry.inode << ".\n";
      return true;
    }
    static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
    get_block(blocknr2, block_buf);
    ext3_dir_entry_2 const* dir_entry2 = reinterpret_cast<ext3_dir_entry_2 const*>(block_buf);
    ASSERT(dir_entry2->inode == dir_entry.inode);
    dir_entry2 = reinterpret_cast<ext3_dir_entry_2 const*>(block_buf + dir_entry2->rec_len);
    ASSERT(dir_entry2->name_len == 2 && dir_entry2->name[0] == '.' && dir_entry2->name[1] == '.');
    ASSERT(dir_entry2->inode);
    std::map<uint32_t, int>& inode_to_count(linked ? data->linked : data->unlinked);
    std::map<uint32_t, int>::iterator iter = inode_to_count.find(dir_entry2->inode);
    if (iter == inode_to_count.end())
      inode_to_count[dir_entry2->inode] = 1;
    else
      ++(inode_to_count[dir_entry2->inode]);
  }
  return false;
}

#ifdef CPPGRAPH
void iterate_over_directory__with__extended_directory_action(void) { (void)extended_directory_action(*(ext3_dir_entry_2 const*)NULL, *(Inode const*)NULL, 0, 0, 0, 0, 0, 0, NULL, NULL); }
#endif

bool find_inode_number_of_extended_directory_block(int blocknr, unsigned char* block_buf, uint32_t& inode_number, uint32_t& inode_from_journal)
{
  block_to_dir_inode_map_type::iterator iter = block_to_dir_inode_map.find(blocknr);
  inode_from_journal = (iter == block_to_dir_inode_map.end()) ? 0 : iter->second;
  get_block(blocknr, block_buf);
  extended_directory_action_data_st data;
  data.blocknr = blocknr;
#ifdef CPPGRAPH
  // Let cppgraph know that we call extended_directory_action from here.
  iterate_over_directory__with__extended_directory_action();
#endif
  ++no_filtering;
  iterate_over_directory(block_buf, blocknr, extended_directory_action, NULL, &data);
  --no_filtering;
  bool linked = (data.linked.size() > 0);
  std::map<uint32_t, int>& inode_to_count(linked ? data.linked : data.unlinked);
  inode_number = 0;
  if (inode_to_count.size() > 0)
  {
    if (inode_to_count.size() > 1)
    {
      if (inode_from_journal)
	std::cout << "Extended directory at " << blocknr << " has entries that appear to be directories, but their parent directory inode is not consistent.\n";
      else
      {
	std::cout << "WARNING: extended directory at " << blocknr << " has entries that appear to be directories, "
	    "but their parent directory inode is not consistent! I can't make this decision for you. "
	    "You will have to manually pick an inode for this block number. The inodes that I found are (although ALL could be wrong):\n";
	for (std::map<uint32_t, int>::iterator iter = inode_to_count.begin(); iter != inode_to_count.end(); ++iter)
	{
	  std::cout << "  " << iter->first << " (" << iter->second;
	  if (iter->second == 1)
	    std::cout << " time)\n";
	  else
	    std::cout << " times)\n";
	}
      }
    }
    else
    {
      inode_number = inode_to_count.begin()->first;
      bool journal_disagrees_with_found_directory_inodes = inode_from_journal && inode_from_journal != inode_number;
      if (journal_disagrees_with_found_directory_inodes)
      {
	std::cout << "Extended directory at " << blocknr << " appears to contains " << inode_to_count.begin()->second <<
	    ' ' << (linked ? "linked" : "unlinked") << " directory whose parent directory has inode " <<
	    inode_number << " but according to the journal it should be " << inode_from_journal << ". Using the latter.\n";
	// We trust our journal based algorithm more because the content of
	// inodes can hardly be trusted: they can be reused and not refer
	// to this dir entry at all. Especially in the case of !feature_incompat_filetype
	// where even regular files' inodes can have been reused (by directories)
	// this will happen frequently, but independent of the frequency at which
	// it occurs, the journal is simply more reliable.
	inode_number = inode_from_journal;
	// However...
	if (linked)
	  std::cout << "WARNING: We really only expect that to happen for unlinked directory entries. Have a look at block " << blocknr << '\n';
	if (inode_to_count.begin()->second > 1)
	  std::cout << "WARNING: It's suspiciously weird that there are more than one such \"directories\". Have a look at block " << blocknr << '\n';
      }
      else
	std::cout << "Extended directory at " << blocknr << " belongs to inode " << inode_number <<
	    " (from " << inode_to_count.begin()->second << ' ' << (linked ? "linked" : "unlinked") << " directories).\n";
    }
  }
  if (!inode_number)	// Not found yet?
  {
#ifdef CPPGRAPH
    // Let cppgraph know that we call filename_heuristics_action from here.
    iterate_over_directory__with__filename_heuristics_action();
#endif
    // Do some heuristics on the filenames.
    std::set<std::string> filenames;
    ++no_filtering;
    iterate_over_directory(block_buf, blocknr, filename_heuristics_action, NULL, &filenames);
    --no_filtering;
    if (filenames.empty())
    {
      if (inode_from_journal)
      {
	std::cout << "Extended directory at " << blocknr << " belongs to inode " << inode_from_journal << " (empty; from journal)).\n";
	inode_number = inode_from_journal;
      }
      else
	std::cout << "Could not find an inode for empty extended directory at " << blocknr << '\n';
    }
    else
    {
      std::string dir = parent_directory(blocknr, filenames); 
      if (dir.empty())
      {
	if (inode_from_journal)
	{
	  std::cout << "Extended directory at " << blocknr << " belongs to inode " << inode_from_journal << " (from journal).\n";
	  inode_number = inode_from_journal;
	}
	else
	  std::cout << "Could not find an inode for extended directory at " << blocknr << ", disregarding it's contents.\n";
      }
      else
      {
	all_directories_type::iterator directory_iter = all_directories.find(dir);
	if (directory_iter == all_directories.end())
	{
	  std::cout << "Extended directory at " << blocknr << " belongs to directory " << dir << " which isn't in all_directories yet.\n";
	  return true;	// Needs to be processed again later.
	}
	else
	{
	  inode_number = directory_iter->second.inode_number();
	  std::cout << "Extended directory at " << blocknr << " belongs to inode " << inode_number << '\n';
	  if (inode_from_journal && inode_from_journal != inode_number)
	    std::cout << "WARNING: according to the journal it should have been inode " << inode_from_journal << "!?\n";
	}
      }
    }
  }
  return false;	// Done
}

void init_directories(void)
{
  static bool initialized = false;
  if (initialized)
    return;
  initialized = true;

  DoutEntering(dc::notice, "init_directories()");

  std::string device_name_basename = device_name.substr(device_name.find_last_of('/') + 1);
  std::string cache_stage2 = device_name_basename + ".ext3grep.stage2";
  struct stat sb;
  bool have_cache = !(stat(cache_stage2.c_str(), &sb) == -1);
  if (have_cache)
  {
    if (does_not_end_on_END(cache_stage2))
      have_cache = false;
  }
  else if (errno != ENOENT)
  {
    int error = errno;
    std::cout << std::flush;
    std::cerr << progname << ": failed to open " << cache_stage2 << ": " << strerror(error) << std::endl;
    exit(EXIT_FAILURE);
  }
  if (!have_cache)
  {
    init_dir_inode_to_block_cache();
    unsigned char* block_buf = new unsigned char [block_size_];

    inode_to_extended_blocks_map_type inode_to_extended_blocks_map;

    // Run over all extended directory blocks.
    for (std::vector<int>::iterator iter = extended_blocks.begin(); iter != extended_blocks.end(); ++iter)
    {
      int blocknr = *iter;

      uint32_t inode_number;
      uint32_t inode_from_journal;
      bool needs_reprocessing = find_inode_number_of_extended_directory_block(blocknr, block_buf, inode_number, inode_from_journal);

      if (needs_reprocessing)
      {
	// FIXME: should be processed again after adding extended directory blocks to all_directories!
	std::cout << "FIXME: Extended directory at " << blocknr << " belongs to non-existent directory!\n";
	// Fall back to journal.
	if (inode_from_journal)
	{
	  std::cout << "Extended directory at " << blocknr << " belongs to inode " << inode_from_journal << " (fall back to journal).\n";
	  inode_number = inode_from_journal;
	}
      }

      if (inode_number)
      {
	// Add the found inode number of this extended block to inode_to_extended_blocks_map.
	inode_to_extended_blocks_map_type::iterator iter2 = inode_to_extended_blocks_map.find(inode_number);
	if (iter2 != inode_to_extended_blocks_map.end())
	  iter2->second.push_back(blocknr);
	else
	{
	  blocknr_vector_type bv;
	  bv.blocknr = 0;
	  bv.push_back(blocknr);
	  inode_to_extended_blocks_map.insert(inode_to_extended_blocks_map_type::value_type(inode_number, bv));
	}
      }
    }

    // Get root inode.
    InodePointer root_inode(get_inode(EXT3_ROOT_INO));
    Parent parent(root_inode, EXT3_ROOT_INO);
    // Get the block that refers to inode EXT3_ROOT_INO.
    int root_blocknr = dir_inode_to_block(EXT3_ROOT_INO);
    ASSERT(root_blocknr != -1);	// This should be impossible; inode EXT3_ROOT_INO is never wiped(?).

    // Initialize root_extended_blocks to be the extended directory blocks of the root.
    blocknr_vector_type root_extended_blocks;
    int root_extended_blocks_size = 0;
    inode_to_extended_blocks_map_type::iterator root_extended_blocks_iter = inode_to_extended_blocks_map.find(EXT3_ROOT_INO);
    if (root_extended_blocks_iter != inode_to_extended_blocks_map.end())
    {
      root_extended_blocks = root_extended_blocks_iter->second;
      root_extended_blocks_size = root_extended_blocks.size();
      ASSERT(root_extended_blocks_size > 0);
    }

#ifdef CPPGRAPH
    // Let cppgraph know that we call init_directories_action from here.
    iterate_over_directory__with__init_directories_action();
#endif

    // Run over all directory blocks and add all start blocks to all_directories, updating inode_to_directory.
    int last_extended_block_index = root_extended_blocks_size;
    for(int blocknr = root_blocknr;; blocknr = root_extended_blocks[--last_extended_block_index])
    {
      // Get the contents of this block of the root directory.
      get_block(blocknr, block_buf);
      // Iterate over all directory blocks.
      int depth_store = commandline_depth;
      commandline_depth = 10000;
      iterate_over_directory(block_buf, root_blocknr, init_directories_action, &parent, NULL);
      commandline_depth = depth_store;
      if (last_extended_block_index == 0)
        break;
    }

    // Next, add all extended directory blocks.
    for (all_directories_type::iterator dir_iter = all_directories.begin(); dir_iter != all_directories.end(); ++dir_iter)
    {
#ifdef DEBUG
      ASSERT(!dir_iter->second.extended_blocks_added());
#endif
      uint32_t inode_number = dir_iter->second.inode_number();

      inode_to_extended_blocks_map_type::iterator iter = inode_to_extended_blocks_map.find(inode_number);
      if (iter != inode_to_extended_blocks_map.end())
      {
	blocknr_vector_type bv = iter->second;
	int const size = bv.size();
	if (size > 0)
	{
	  std::cout << "Adding extended directory block(s) for directory \"" << dir_iter->first << "\"." << std::endl;
	  unsigned char* block_buf = new unsigned char [block_size_];
	  for (int j = 0; j < size; ++j)
	  {
	    int blocknr = bv[j];
	    get_block(blocknr, block_buf);

	    // Add extended directory as DirectoryBlock to the corresponding Directory.
	    dir_iter->second.blocks().push_back(DirectoryBlock());
	    std::list<DirectoryBlock>::iterator directory_block_iter = dir_iter->second.blocks().end();
	    --directory_block_iter;
	    directory_block_iter->read_block(blocknr, directory_block_iter);

	    // Set up a Parent object that will return the correct dirname.
	    ext3_dir_entry_2 fake_dir_entry;
	    fake_dir_entry.inode = inode_number;
	    fake_dir_entry.rec_len = 0;	// Not used
	    fake_dir_entry.file_type = 0; // Not used
	    fake_dir_entry.name_len = dir_iter->first.size();
	    strncpy(fake_dir_entry.name, dir_iter->first.c_str(), fake_dir_entry.name_len);
	    InodePointer fake_reference(0);
	    Parent dummy_parent(fake_reference, 0);
	    InodePointer inoderef(get_inode(inode_number));
	    Parent parent(&dummy_parent, &fake_dir_entry, inoderef, inode_number);
	    ASSERT(parent.dirname(false) == dir_iter->first);
	    // Iterate over all directory blocks that we can reach.
	    int depth_store = commandline_depth;
	    commandline_depth = 10000;
	    iterate_over_directory(block_buf, blocknr, init_directories_action, &parent, NULL);
	    commandline_depth = depth_store;
	  }
	  delete [] block_buf;
	}
      }
#ifdef DEBUG
      dir_iter->second.set_extended_blocks_added();
#endif
    }
#ifdef DEBUG
    // The block inside the above loop adds new elements to all_directories. If those are
    // added AFTER dir_iter then there is no problem because std::map iterators aren't
    // invalidated by insertion and they will be taken into account later in the
    // same loop. If dir_iter points to a Directory with a path a/b/c then inode_number 
    // is the inode number of that 'c' directory. Extended blocks of that directory
    // only add "." dir entries for recursively found directories, ie a/b/c/d and
    // are therefore inserted after the current element and processed automatically
    // in the same loop. Therefore, the following should hold:
    for (all_directories_type::iterator dir_iter = all_directories.begin(); dir_iter != all_directories.end(); ++dir_iter)
      ASSERT(dir_iter->second.extended_blocks_added());
#endif

    all_directories_type::iterator lost_plus_found_directory_iter = all_directories.find("lost+found");
    ASSERT(lost_plus_found_directory_iter != all_directories.end());

    // Add all remaining extended directory blocks to lost+found.
    // Also free memory of inode_to_extended_blocks_map.
    for (inode_to_extended_blocks_map_type::iterator iter = inode_to_extended_blocks_map.begin(); iter != inode_to_extended_blocks_map.end(); ++iter)
    {
      uint32_t inode_number = iter->first;
      blocknr_vector_type bv = iter->second;
      inode_to_directory_type::iterator directory_iter = inode_to_directory.find(inode_number);
      if (directory_iter == inode_to_directory.end())	// Not added already?
      {
        if (bv.size() == 1)
	  std::cout << "WARNING: Can't link block";
        else
	  std::cout << "WARNING: Can't link blocks";
	for (size_t j = 0; j < bv.size(); ++j)
	  std::cout << ' ' << bv[j];
	std::cout << " to inode " << inode_number << " because that inode cannot be found in the inode_to_directory map. Linking it to lost+found instead!\n";
	// FIXME: namespace polution. These should be put in lost+found/inode_number or something.
	for (size_t j = 0; j < bv.size(); ++j)
	{
	  int blocknr = bv[j];
	  // Add extended directory as DirectoryBlock to lost+found.
	  lost_plus_found_directory_iter->second.blocks().push_back(DirectoryBlock());
	  std::list<DirectoryBlock>::iterator directory_block_iter = lost_plus_found_directory_iter->second.blocks().end();
	  --directory_block_iter;
	  directory_block_iter->read_block(blocknr, directory_block_iter);
	}
      }
      // Free memory.
      bv.erase();
    }

    delete [] block_buf;
    std::cout << '\n';

    std::cout << "Writing analysis so far to '" << cache_stage2 << "'. Delete that file if you want to do this stage again.\n";
    std::ofstream cache;
    cache.open(cache_stage2.c_str());
    cache << "# Stage 2 data for " << device_name << ".\n";
    cache << "# Inodes path and directory blocks.\n";
    cache << "# INODE PATH BLOCK [BLOCK ...]\n";

    for (inode_to_directory_type::iterator iter = inode_to_directory.begin(); iter != inode_to_directory.end(); ++iter)
    {
      cache << iter->first << " '" << iter->second->first << "'";
      Directory& directory(iter->second->second);
      if (directory.inode_number() != iter->first)
      {
        std::cerr << "ERROR: inode_to_directory entry with inode number " << iter->first <<
	    " points to a Directory with inode number " << directory.inode_number() << " (path \"" << iter->second->first << "\")." << std::endl; 
      }
      ASSERT(directory.inode_number() == iter->first);
      for (std::list<DirectoryBlock>::iterator iter2 = directory.blocks().begin(); iter2 != directory.blocks().end(); ++iter2)
        cache << ' ' << iter2->block();
      cache << '\n';
    }

    cache << "# END\n";
    cache.close();
  }
  else
  {
    std::cout << "Loading " << cache_stage2 << "..." << std::flush;
    std::ifstream cache;
    cache.open(cache_stage2.c_str());
    if (!cache.is_open())
    {
      int error = errno;
      std::cout << " error" << std::endl;
      std::cerr << progname << ": failed to open " << cache_stage2 << ": " << strerror(error) << std::endl;
      exit(EXIT_FAILURE);
    }
    int inode;
    int blocknr;
    char c;
    // Skip initial comments.
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
    ASSERT(!dir_inode_to_block_cache);
    dir_inode_to_block_cache = new blocknr_vector_type [inode_count_ + 1];
    std::memset(dir_inode_to_block_cache, 0, sizeof(blocknr_vector_type) * (inode_count_ + 1));
    std::stringstream buf;
    int count = 0;
    while (cache >> inode)
    {
      cache.get(c);
      ASSERT(c == ' ');
      cache.get(c);
      ASSERT(c == '\'');
      buf.clear();
      buf.str("");
      cache.get(*buf.rdbuf(), '\n');
      if (inode == EXT3_ROOT_INO)	// If the function extracts no elements, it calls setstate(failbit).
	cache.clear();
      cache.get(c);	// Extraction stops on end-of-file or on an element that compares equal to delim (which is not extracted).
      ASSERT(c == '\n');
      std::string::size_type pos = buf.str().find_last_of('\'');
      ASSERT(pos != std::string::npos);
      std::pair<all_directories_type::iterator, bool> res = all_directories.insert(all_directories_type::value_type(buf.str().substr(0, pos), Directory(inode)));
      ASSERT(res.second);
      std::pair<inode_to_directory_type::iterator, bool> res2 = inode_to_directory.insert(inode_to_directory_type::value_type(inode, res.first));
      ASSERT(res2.second);
      buf.seekg(pos + 1);
      std::vector<uint32_t> block_numbers;
      while(buf >> blocknr)
      {
        block_numbers.push_back(blocknr);
	c = buf.get();
	if (c != ' ')
	{
	  ASSERT(buf.eof());
	  break;
	}
      }
      dir_inode_to_block_cache[inode] = block_numbers;
      std::list<DirectoryBlock>& blocks(res.first->second.blocks());
      blocks.resize(block_numbers.size());
      std::list<DirectoryBlock>::iterator directory_block_iter = blocks.begin();
      for (std::vector<uint32_t>::iterator block_number_iter = block_numbers.begin();
          block_number_iter != block_numbers.end(); ++block_number_iter, ++directory_block_iter)
	directory_block_iter->read_block(*block_number_iter, directory_block_iter);
      if (++count % 100 == 0)
        std::cout << '.' << std::flush;
    }
    cache.close();
    std::cout << " done\n";
  }
}
