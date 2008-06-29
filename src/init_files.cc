// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file init_files.cc Implementation of init_files.
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

#include "init_files.h"
#include "directories.h"
#include "init_directories.h"
#include "commandline.h"
#include "globals.h"
#include "forward_declarations.h"
#include "journal.h"

//-----------------------------------------------------------------------------
//
// Individual files
//
// Map files to a single inode.
//

path_to_inode_map_type path_to_inode_map;

struct JournalData {
  int last_tag_sequence;
  JournalData(int lts) : last_tag_sequence(lts) { }
};

class Sorter {
  private:
    int M_sequence;
    int M_index;
    DirectoryBlock* M_directory_block;
  public:
    Sorter(int sequence, int index, DirectoryBlock& directory_block) : M_sequence(sequence), M_index(index), M_directory_block(&directory_block) { }
    int sequence(void) const { return M_sequence; }
    int index(void) const { return M_index; }
    DirectoryBlock& directory_block(void) const { return *M_directory_block; }
    friend bool operator<(Sorter const& s1, Sorter const& s2) { return s1.M_sequence > s2.M_sequence; }
};

typedef std::map<int, std::vector<std::vector<DirEntry>::iterator> > inode_to_dir_entry_type;
inode_to_dir_entry_type inode_to_dir_entry;

void init_files(void)
{
  static bool initialized = false;
  if (initialized)
    return;
  initialized = true;

  DoutEntering(dc::notice, "init_files()");

  init_directories();

  bool show_inode_dirblock_table = !commandline_inode_dirblock_table.empty();
  all_directories_type::iterator show_inode_dirblock_table_iter;
  if (show_inode_dirblock_table)
  {
    show_inode_dirblock_table_iter = all_directories.find(commandline_inode_dirblock_table);
    if (show_inode_dirblock_table_iter == all_directories.end())
    {
      std::cout << std::flush;
      std::cerr << progname << ": --inode-dirblock-table: No such directory: " << commandline_inode_dirblock_table << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  // Run over all directories.
  for (all_directories_type::iterator directory_iter = all_directories.begin(); directory_iter != all_directories.end(); ++directory_iter)
  {
    Directory& directory(directory_iter->second);

    // Find all non-journal blocks and fill journal_data_map.
    typedef std::map<int, JournalData> journal_data_map_type;
    journal_data_map_type journal_data_map;
    for (std::list<DirectoryBlock>::iterator directory_block_iter = directory.blocks().begin();
        directory_block_iter != directory.blocks().end(); ++directory_block_iter)
    {
      DirectoryBlock& directory_block(*directory_block_iter);
      if (is_in_journal(directory_block.block()))
        continue;
      // Find related journal information.
      JournalData journal_data(0);
      block_to_descriptors_map_type::iterator iter = block_to_descriptors_map.find(directory_block.block());
      if (iter != block_to_descriptors_map.end())
      {
        std::vector<Descriptor*>& descriptors(iter->second);
	for (std::vector<Descriptor*>::reverse_iterator descriptor_iter = descriptors.rbegin(); descriptor_iter != descriptors.rend(); ++descriptor_iter)
	{
	  Descriptor& descriptor(**descriptor_iter);
	  if (!journal_data.last_tag_sequence && descriptor.descriptor_type() == dt_tag)
	    journal_data.last_tag_sequence = descriptor.sequence();
	  if (journal_data.last_tag_sequence)
	    break;
	}
      }
      journal_data_map.insert(journal_data_map_type::value_type(directory_block.block(), journal_data));
    }
    // Add journal blocks too.
    for (std::list<DirectoryBlock>::iterator directory_block_iter = directory.blocks().begin();
        directory_block_iter != directory.blocks().end(); ++directory_block_iter)
    {
      DirectoryBlock& directory_block(*directory_block_iter);
      if (!is_in_journal(directory_block.block()))
        continue;
      ASSERT(is_journal(directory_block.block()));
      block_in_journal_to_descriptors_map_type::iterator descriptors_iter = block_in_journal_to_descriptors_map.find(directory_block.block());
      if (descriptors_iter == block_in_journal_to_descriptors_map.end())
      {
	std::cout << std::flush;
	std::cerr << "WARNING: Disregarding directory block " << directory_block.block() << " from the journal, "
	    " that appears to belong to a directory with inode number " << directory.inode_number() <<
	    ", because it doesn't have a descriptor block (the start of the transaction was probably overwritten)."
	    " We're disregarding it because ext3grep can't deal with journal blocks without a descriptor block." << std::endl;
        continue;
      }
      Descriptor& descriptor(*descriptors_iter->second);
      ASSERT(descriptor.descriptor_type() == dt_tag);
      //DescriptorTag& descriptor_tag(static_cast<DescriptorTag&>(descriptor));
      //journal_data_map_type::iterator iter = journal_data_map.find(descriptor_tag.block());
      //if (iter != journal_data_map.end())
      //  continue;	// Refers to a block we already have.
      journal_data_map.insert(journal_data_map_type::value_type(directory_block.block(), JournalData(descriptor.sequence())));
    }

    // Run over all directoy blocks and dir_entries and fill DirEntry::M_directory
    for (std::list<DirectoryBlock>::iterator directory_block_iter = directory.blocks().begin();
        directory_block_iter != directory.blocks().end(); ++directory_block_iter)
    {
      DirectoryBlock& directory_block(*directory_block_iter);
      for (std::vector<DirEntry>::iterator dir_entry_iter = directory_block.dir_entries().begin();
          dir_entry_iter != directory_block.dir_entries().end(); ++dir_entry_iter)
      {
        DirEntry& dir_entry(*dir_entry_iter);
	dir_entry.M_directory = &directory;
      }
    }

    // Count the number of different filenames and directory blocks in this directory.
    int number_of_directory_blocks = 0;
    int number_of_files = 0;
    typedef std::map<std::string, int> filename_to_index_map_type;
    filename_to_index_map_type filename_to_index_map;
    // Run over all directoy blocks and dir_entries.
    for (std::list<DirectoryBlock>::iterator directory_block_iter = directory.blocks().begin();
        directory_block_iter != directory.blocks().end(); ++directory_block_iter)
    {
      DirectoryBlock& directory_block(*directory_block_iter);
      journal_data_map_type::iterator iter = journal_data_map.find(directory_block.block());
      if (iter == journal_data_map.end())
        continue;
      // Count the number of directory blocks.
      ++number_of_directory_blocks;
      for (std::vector<DirEntry>::iterator dir_entry_iter = directory_block.dir_entries().begin();
          dir_entry_iter != directory_block.dir_entries().end(); ++dir_entry_iter)
      {
        DirEntry& dir_entry(*dir_entry_iter);
	if (dir_entry.zero_inode || dir_entry.reallocated)
	  continue;
	if (dir_entry.M_file_type == EXT3_FT_DIR)
	  continue;
	// Count the number of different files.
	std::pair<filename_to_index_map_type::iterator, bool> res = filename_to_index_map.insert(filename_to_index_map_type::value_type(dir_entry.M_name, number_of_files));
	if (res.second)
	  ++number_of_files;
        // Fill inode_to_dir_entry
	inode_to_dir_entry_type::iterator iter2 = inode_to_dir_entry.find(dir_entry.M_inode);
	if (iter2 == inode_to_dir_entry.end())
	  inode_to_dir_entry.insert(inode_to_dir_entry_type::value_type(dir_entry.M_inode, std::vector<std::vector<DirEntry>::iterator>(1, dir_entry_iter)));
	else
	  iter2->second.push_back(dir_entry_iter);
      }
    }
    ASSERT((size_t)number_of_files == filename_to_index_map.size());

    // Create a two-dimensional array of number_of_directory_blocks x number_of_files.
    std::vector<std::vector<int> > file_dirblock_matrix(number_of_directory_blocks, std::vector<int>(number_of_files, 0));
    std::vector<std::string> index_to_filename(number_of_files);
    // Fill the array with inode numbers corresponding to filename / directory block.
    int dirblock_index = -1;
    size_t longest_filename_size = 19;
    // Run over all directoy blocks and dir_entries.
    for (std::list<DirectoryBlock>::iterator directory_block_iter = directory.blocks().begin();
        directory_block_iter != directory.blocks().end(); ++directory_block_iter)
    {
      DirectoryBlock& directory_block(*directory_block_iter);
      journal_data_map_type::iterator iter = journal_data_map.find(directory_block.block());
      if (iter == journal_data_map.end())
        continue;
      ++dirblock_index;
      for (std::vector<DirEntry>::iterator dir_entry_iter = directory_block.dir_entries().begin();
          dir_entry_iter != directory_block.dir_entries().end(); ++dir_entry_iter)
      {
        DirEntry& dir_entry(*dir_entry_iter);
	if (dir_entry.zero_inode || dir_entry.reallocated)
	  continue;
	if (dir_entry.M_file_type == EXT3_FT_DIR)
	  continue;
	int inode = dir_entry.M_inode;
	// Get our filename index.
	int filename_index = filename_to_index_map[dir_entry.M_name];
	index_to_filename[filename_index] = dir_entry.M_name;
	// Find the size of the longest filename.
	longest_filename_size = std::max(longest_filename_size, dir_entry.M_name.size());
	// Fill the array.
	file_dirblock_matrix[dirblock_index][filename_index] = inode;
      }
    }

    std::vector<Sorter> sort_array;
    dirblock_index = -1;
    for (std::list<DirectoryBlock>::iterator directory_block_iter = directory.blocks().begin();
        directory_block_iter != directory.blocks().end(); ++directory_block_iter)
    {
      DirectoryBlock& directory_block(*directory_block_iter);
      journal_data_map_type::iterator iter = journal_data_map.find(directory_block.block());
      if (iter == journal_data_map.end())
        continue;
      ++dirblock_index;
      sort_array.push_back(Sorter(iter->second.last_tag_sequence, dirblock_index, directory_block));
    }
    ASSERT(sort_array.size() == (size_t)number_of_directory_blocks);
    std::sort(sort_array.begin(), sort_array.end());

    if (show_inode_dirblock_table && directory_iter == show_inode_dirblock_table_iter)
    {
      std::cout << "Possible inodes for files in \"" << directory_iter->first << "\":\n";
      // Print a header.
      std::cout << std::right << std::setw(longest_filename_size) << "Directory block nr:";
      for (std::vector<Sorter>::iterator iter = sort_array.begin(); iter != sort_array.end(); ++iter)
      {
	DirectoryBlock& directory_block(iter->directory_block());
	std::cout << " |" << std::setfill(' ') << std::setw(7) << directory_block.block();
      }
      std::cout << '\n';
      int prev_sequence = max_sequence;
      std::cout << std::right << std::setw(longest_filename_size) << "Last tag sequence: ";
      for (std::vector<Sorter>::iterator iter = sort_array.begin(); iter != sort_array.end(); ++iter)
      {
	//DirectoryBlock& directory_block(iter->directory_block());
	int sequence = iter->sequence();
	ASSERT(sequence <= prev_sequence);
	std::cout << " |" << std::setfill(' ') << std::setw(7) << sequence;
	prev_sequence = sequence;
      }
      std::cout << '\n';
      std::cout << std::string(longest_filename_size, '-');
      for (int dirblock_index = 0; dirblock_index < number_of_directory_blocks; ++dirblock_index)
        std::cout << "-+-------";
      std::cout << '\n';
      // Print the array.
      for (int filename_index = 0; filename_index < number_of_files; ++filename_index)
      {
	std::string filename = index_to_filename[filename_index];
	std::cout << std::setfill(' ') << std::left << std::setw(longest_filename_size) << filename;
	for (int dirblock_index = 0; dirblock_index < number_of_directory_blocks; ++dirblock_index)
	{
	  int inode = file_dirblock_matrix[sort_array[dirblock_index].index()][filename_index];
	  if (inode == 0)
	    std::cout << " |       ";
	  else
	    std::cout << " |" << std::setfill(' ') << std::right << std::setw(7) << inode;
	}
	std::cout << '\n';
      }
    }

    // Fill path_to_inode_map.
    for (int filename_index = 0; filename_index < number_of_files; ++filename_index)
    {
      std::string full_path = directory_iter->first;
      if (!full_path.empty())
        full_path += '/';
      full_path += index_to_filename[filename_index];
      int inode = 0;
      for (int dirblock_index = 0; dirblock_index < number_of_directory_blocks; ++dirblock_index)
        if ((inode = file_dirblock_matrix[sort_array[dirblock_index].index()][filename_index]))
	  break;
      if (inode == 0)
        continue;
      path_to_inode_map.insert(path_to_inode_map_type::value_type(full_path, inode));
    }
  }
}
