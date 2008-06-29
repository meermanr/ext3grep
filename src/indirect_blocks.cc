// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file indirect_blocks.cc Implementation dealing with (double/tripple) indirect blocks.
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

#include "indirect_blocks.h"
#include "get_block.h"
#include "is_blockdetection.h"
#include "forward_declarations.h"
#include "endian_conversion.h"

//-----------------------------------------------------------------------------
//
// Indirect blocks
//

void find_block_action(int blocknr, void* ptr)
{
  find_block_data_st& data(*reinterpret_cast<find_block_data_st*>(ptr));
  if (blocknr == data.block_looking_for)
    data.found_block = true;
}

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__find_block_action(void) { find_block_action(0, NULL); }
#endif

void print_directory_action(int blocknr, void*)
{
  static bool using_static_buffer = false;
  ASSERT(!using_static_buffer);
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  unsigned char* block = get_block(blocknr, block_buf);
  using_static_buffer = true;
  ext3_dir_entry_2* dir_entry = reinterpret_cast<ext3_dir_entry_2*>(block);
  if (dir_entry->rec_len < block_size_)	// The directory could be entirely empty (unused).
    print_directory(block, blocknr);
  using_static_buffer = false;
}

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__print_directory_action(void) { print_directory_action(0, NULL); }
#endif

bool iterate_over_all_blocks_of_indirect_block(int block, void (*action)(int, void*), void* data, unsigned int, bool diagnose)
{
  if (diagnose)
    std::cout << "Processing indirect block " << block << ": " << std::flush;
  unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  __le32* block_ptr = (__le32*)get_block(block, block_buf);
  unsigned int i = 0;
  while (i < block_size_ / sizeof(__le32))
  {
    if (block_ptr[i])
    {
      if (!is_block_number(block_ptr[i]))
      {
        if (diagnose)
	  std::cout << "entry " << i << " contains block number " << block_ptr[i] << ", which is too large." << std::endl;
        break;
      }
      if (!diagnose)
	action(block_ptr[i], data);
    }
    ++i;
  }
  bool result = (i < block_size_ / sizeof(__le32));
  if (diagnose && !result)
    std::cout << "OK" << std::endl;
  return result;
}

bool iterate_over_all_blocks_of_double_indirect_block(int block, void (*action)(int, void*), void* data, unsigned int indirect_mask, bool diagnose)
{
  if (diagnose)
    std::cout << "Start processing double indirect block " << block << '.' << std::endl;
  unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  __le32* block_ptr = (__le32*)get_block(block, block_buf);
  unsigned int i = 0;
  while (i < block_size_ / sizeof(__le32))
  {
    if (block_ptr[i])
    {
      if (!is_block_number(block_ptr[i]))
      {
        if (diagnose)
	  std::cout << "Entry " << i << " of double indirect block " << block << " contains block number " << block_ptr[i] << ", which is too large." << std::endl;
        break;
      }
      if ((indirect_mask & indirect_bit) && !diagnose)
        action(block_ptr[i], data);
      if ((indirect_mask & direct_bit))
        if (iterate_over_all_blocks_of_indirect_block(block_ptr[i], action, data, indirect_mask, diagnose))
	  break;
    }
    ++i;
  }
  if (diagnose)
    std::cout << "End processing double indirect block " << block << '.' << std::endl;
  return i < block_size_ / sizeof(__le32);
}

bool iterate_over_all_blocks_of_tripple_indirect_block(int block, void (*action)(int, void*), void* data, unsigned int indirect_mask, bool diagnose)
{
  if (diagnose)
    std::cout << "Start processing tripple indirect block " << block << '.' << std::endl;
  unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  __le32* block_ptr = (__le32*)get_block(block, block_buf);
  unsigned int i = 0;
  while (i < block_size_ / sizeof(__le32))
  {
    if (block_ptr[i])
    {
      if (!is_block_number(block_ptr[i]))
      {
        if (diagnose)
	  std::cout << "Entry " << i << " of tripple indirect block " << block << " contains block number " << block_ptr[i] << ", which is too large." << std::endl;
        break;
      }
      if ((indirect_mask & indirect_bit) && !diagnose)
        action(block_ptr[i], data);
      if (iterate_over_all_blocks_of_double_indirect_block(block_ptr[i], action, data, indirect_mask, diagnose))
        break;
    }
    ++i;
  }
  if (diagnose)
    std::cout << "End processing tripple indirect block " << block << '.' << std::endl;
  return i < block_size_ / sizeof(__le32);
}

// Returns true if an indirect block was encountered that doesn't look like an indirect block anymore.
bool iterate_over_all_blocks_of(Inode const& inode, void (*action)(int, void*), void* data, unsigned int indirect_mask, bool diagnose)
{
  if (is_symlink(inode) && inode.blocks() == 0)
    return false;		// Block pointers contain text.
  __le32 const* block_ptr = inode.block();
  if (diagnose)
    std::cout << "Processing direct blocks..." << std::flush;
  if ((indirect_mask & direct_bit))
    for (int i = 0; i < EXT3_NDIR_BLOCKS; ++i)
      if (block_ptr[i])
      {
        if (diagnose)
	  std::cout << ' ' << block_ptr[i] << std::flush;
	else
	  action(block_ptr[i], data);
      }
  if (diagnose)
    std::cout << std::endl;
  if (block_ptr[EXT3_IND_BLOCK])
  {
    ASSERT(is_block_number(block_ptr[EXT3_IND_BLOCK]));
    if ((indirect_mask & indirect_bit) && !diagnose)
      action(block_ptr[EXT3_IND_BLOCK], data);
    if ((indirect_mask & direct_bit))
      if (iterate_over_all_blocks_of_indirect_block(block_ptr[EXT3_IND_BLOCK], action, data, indirect_mask, diagnose))
        return true;
  }
  if (block_ptr[EXT3_DIND_BLOCK])
  {
    ASSERT(is_block_number(block_ptr[EXT3_DIND_BLOCK]));
    if ((indirect_mask & indirect_bit) && !diagnose)
      action(block_ptr[EXT3_DIND_BLOCK], data);
    if (iterate_over_all_blocks_of_double_indirect_block(block_ptr[EXT3_DIND_BLOCK], action, data, indirect_mask, diagnose))
      return true;
  }
  if (block_ptr[EXT3_TIND_BLOCK])
  {
    ASSERT(is_block_number(block_ptr[EXT3_TIND_BLOCK]));
    if ((indirect_mask & indirect_bit) && !diagnose)
      action(block_ptr[EXT3_TIND_BLOCK], data);
    if (iterate_over_all_blocks_of_tripple_indirect_block(block_ptr[EXT3_TIND_BLOCK], action, data, indirect_mask, diagnose))
      return true;
  }
  return false;
}
