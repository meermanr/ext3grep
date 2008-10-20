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
// Stanislaw T. Findeisen <sf181257 at students mimuw edu pl>
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
//
// ChangeLog
//
// 2008-07-07  STF
//     * (is_indirect_block): Add. Heuristic detection of indirect
//       blocks based solely on their content.
//
// 2008-07-10  Carlo Wood  <carlo@alinoe.com>
//     * (is_indirect_block):
//       -Add SKIPZEROES.
//       - Call is_data_block_number.
//       - Return false if there are only ZEROES.
//       - Bug fix: Abort loops when reaching the ZEROES.
//       - Only use an array on the stack if the block numbers are less than the
//         size of one group apart (instead of allocating and clearing 32 MB on
//         the stack every time).
//	- Use return value of std::set<>::insert instead of calling std::set<>::count.
//
// 2008-10-13  Carlo Wood  <carlo@alinoe.com>
//     * (is_indirect_block):
//       - SKIPZEROES must be 0: zeroes a completely legal in any indirect block.

#ifndef USE_PCH
#include "sys.h"
#endif

#include "indirect_blocks.h"
#include "get_block.h"
#include "is_blockdetection.h"
#include "forward_declarations.h"
#include "endian_conversion.h"
#include "superblock.h"

//-----------------------------------------------------------------------------
//
// Indirect blocks
//

void find_block_action(int blocknr, int, void* ptr)
{
  find_block_data_st& data(*reinterpret_cast<find_block_data_st*>(ptr));
  if (blocknr == data.block_looking_for)
    data.found_block = true;
}

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__find_block_action(void) { find_block_action(0, 0, NULL); }
#endif

void print_directory_action(int blocknr, int, void*)
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
void iterate_over_all_blocks_of__with__print_directory_action(void) { print_directory_action(0, 0, NULL); }
#endif

bool iterate_over_all_blocks_of_indirect_block(int block, int& file_block_nr, void (*action)(int, int, void*), void* data, unsigned int indirect_mask, bool diagnose)
{
  if (diagnose)
    std::cout << "Processing indirect block " << block << ": " << std::flush;
  unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  __le32* block_ptr = (__le32*)get_block(block, block_buf);
  unsigned int i = 0;
  while (i < block_size_ / sizeof(__le32))
  {
    if (block_ptr[i] || (indirect_mask & hole_bit))
    {
      if (!is_block_number(block_ptr[i]))
      {
        if (diagnose)
	  std::cout << "entry " << i << " contains block number " << block_ptr[i] << ", which is too large." << std::endl;
        break;
      }
      if (!diagnose)
	action(block_ptr[i], file_block_nr, data);
    }
    ++i;
    ++file_block_nr;
  }
  bool result = (i < block_size_ / sizeof(__le32));
  if (diagnose && !result)
    std::cout << "OK" << std::endl;
  return result;
}

bool iterate_over_all_blocks_of_double_indirect_block(int block, int& file_block_nr, void (*action)(int, int, void*), void* data, unsigned int indirect_mask, bool diagnose)
{
  if (diagnose)
    std::cout << "Start processing double indirect block " << block << '.' << std::endl;
  unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  __le32* block_ptr = (__le32*)get_block(block, block_buf);
  unsigned int i = 0;
  unsigned int const limit = block_size_ >> 2;
  while (i < limit)
  {
    if (block_ptr[i] || (indirect_mask & hole_bit))
    {
      if (!is_block_number(block_ptr[i]))
      {
        if (diagnose)
	  std::cout << "Entry " << i << " of double indirect block " << block << " contains block number " << block_ptr[i] << ", which is too large." << std::endl;
        break;
      }
      if ((indirect_mask & indirect_bit) && !diagnose)
        action(block_ptr[i], -1, data);
      if ((indirect_mask & direct_bit))
      {
        if (iterate_over_all_blocks_of_indirect_block(block_ptr[i], file_block_nr, action, data, indirect_mask, diagnose))
	  break;
      }
      else
	file_block_nr += limit;
    }
    else
      file_block_nr += limit;
    ++i;
  }
  if (diagnose)
    std::cout << "End processing double indirect block " << block << '.' << std::endl;
  return i < block_size_ / sizeof(__le32);
}

bool iterate_over_all_blocks_of_tripple_indirect_block(int block, int& file_block_nr, void (*action)(int, int, void*), void* data, unsigned int indirect_mask, bool diagnose)
{
  if (diagnose)
    std::cout << "Start processing tripple indirect block " << block << '.' << std::endl;
  unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  __le32* block_ptr = (__le32*)get_block(block, block_buf);
  unsigned int i = 0;
  unsigned int const limit = block_size_ >> 2;
  while (i < limit)
  {
    if (block_ptr[i] || (indirect_mask & hole_bit))
    {
      if (!is_block_number(block_ptr[i]))
      {
        if (diagnose)
	  std::cout << "Entry " << i << " of tripple indirect block " << block << " contains block number " << block_ptr[i] << ", which is too large." << std::endl;
        break;
      }
      if ((indirect_mask & indirect_bit) && !diagnose)
        action(block_ptr[i], -1, data);
      if (iterate_over_all_blocks_of_double_indirect_block(block_ptr[i], file_block_nr, action, data, indirect_mask, diagnose))
        break;
    }
    else
      file_block_nr += limit * limit;
    ++i;
  }
  if (diagnose)
    std::cout << "End processing tripple indirect block " << block << '.' << std::endl;
  return i < limit;
}

// Returns true if an indirect block was encountered that doesn't look like an indirect block anymore.
bool iterate_over_all_blocks_of(Inode const& inode, int inode_number, void (*action)(int, int, void*), void* data, unsigned int indirect_mask, bool diagnose)
{
  if (is_symlink(inode) && inode.blocks() == 0)
    return false;		// Block pointers contain text.
  __le32 const* block_ptr = inode.block();
  if (diagnose)
    std::cout << "Processing direct blocks..." << std::flush;
  int file_block_nr = 0;
  unsigned int const limit = block_size_ >> 2;
  if ((indirect_mask & direct_bit))
  {
    for (int i = 0; i < EXT3_NDIR_BLOCKS; ++i, ++file_block_nr)
      if (block_ptr[i] || (indirect_mask & hole_bit))
      {
        if (diagnose)
	  std::cout << ' ' << block_ptr[i] << std::flush;
	else
	  action(block_ptr[i], file_block_nr, data);
      }
  }
  else
    file_block_nr += EXT3_NDIR_BLOCKS;
  if (diagnose)
    std::cout << std::endl;
  if (block_ptr[EXT3_IND_BLOCK] || (indirect_mask & hole_bit))
  {
    if (!is_block_number(block_ptr[EXT3_IND_BLOCK]))
    {
      std::cout << std::flush;
      std::cerr << "\nWARNING: The indirect block number of inode " << inode_number <<
          " (or a journal copy thereof) doesn't look like a block number (it is too large, "
	  "block number " << EXT3_IND_BLOCK << " in it's block list is too large (" <<
	  block_ptr[EXT3_IND_BLOCK] << ")). Treating this as if one of the indirect blocks "
	  "were overwritten, although this is a more serious corruption." << std::endl;
      return true;
    }
    if ((indirect_mask & indirect_bit) && !diagnose)
      action(block_ptr[EXT3_IND_BLOCK], -1, data);
    if ((indirect_mask & direct_bit))
    {
      if (iterate_over_all_blocks_of_indirect_block(block_ptr[EXT3_IND_BLOCK], file_block_nr, action, data, indirect_mask, diagnose))
	return true;
    }
  }
  else
    file_block_nr += limit;
  if (block_ptr[EXT3_DIND_BLOCK] || (indirect_mask & hole_bit))
  {
    if (!is_block_number(block_ptr[EXT3_DIND_BLOCK]))
    {
      std::cout << std::flush;
      std::cerr << "WARNING: The double indirect block number of inode " << inode_number <<
          " (or a journal copy thereof) doesn't look like a block number (it is too large, "
	  "block number " << EXT3_DIND_BLOCK << " in it's block list is too large (" <<
	  block_ptr[EXT3_DIND_BLOCK] << ")). Treating this as if one of the indirect blocks "
	  "were overwritten, although this is a more serious corruption." << std::endl;
      return true;
    }
    if ((indirect_mask & indirect_bit) && !diagnose)
      action(block_ptr[EXT3_DIND_BLOCK], -1, data);
    if (iterate_over_all_blocks_of_double_indirect_block(block_ptr[EXT3_DIND_BLOCK], file_block_nr, action, data, indirect_mask, diagnose))
      return true;
  }
  else
    file_block_nr += limit * limit;
  if (block_ptr[EXT3_TIND_BLOCK] || (indirect_mask & hole_bit))
  {
    if (!is_block_number(block_ptr[EXT3_TIND_BLOCK]))
    {
      std::cout << std::flush;
      std::cerr << "WARNING: The tripple indirect block number of inode " << inode_number <<
          " (or a journal copy thereof) doesn't look like a block number (it is too large, "
	  "block number " << EXT3_TIND_BLOCK << " in it's block list is too large (" <<
	  block_ptr[EXT3_TIND_BLOCK] << ")). Treating this as if one of the indirect blocks "
	  "were overwritten, although this is a more serious corruption." << std::endl;
      return true;
    }
    if ((indirect_mask & indirect_bit) && !diagnose)
      action(block_ptr[EXT3_TIND_BLOCK], -1, data);
    if (iterate_over_all_blocks_of_tripple_indirect_block(block_ptr[EXT3_TIND_BLOCK], file_block_nr, action, data, indirect_mask, diagnose))
      return true;
  }
  return false;
}

// See header file for description.
// Define this to return false if any [bi] is zero, otherwise
// only false is returned when the first block is zero.

// This must be 0.
#define SKIPZEROES 0
bool is_indirect_block(unsigned char* block_ptr, bool verbose)
{
  // Number of 32-bit values per block.
  int const values_per_block = block_size_ / sizeof(__le32);

  // Block values.
  uint32_t blockVals[values_per_block];

  uint32_t vmin = 0xffffffff;
  uint32_t vmax = 0;
  bool hasZero = false;

  // Search for zeroes, min and max.
  for (int i = 0, offset = 0; i < values_per_block; ++i, offset += sizeof(__le32))
  {
    uint32_t v = __le32_to_cpu(read_le32(block_ptr + offset));
    blockVals[i] = v;

    if (v)
    {
#if SKIPZEROES
      if (hasZero)
      {
	if (verbose)
	  std::cout << "Found non-zero after zero!" << std::endl;
        // There already was 0, now it is not 0 --- this might be an indirect block of a file with 'holes'.
	// However, fail and return false.
        return false;
      }
#endif
      if (!is_data_block_number(v))
      {
        // This is not a valid block pointer.
	if (verbose)
	  std::cout << "Invalid block pointer!" << std::endl;
        return false;
      }

#if !SKIPZEROES
      if (hasZero)
        continue;
#endif

      if (v < vmin)
        vmin = v;
      if (vmax < v)
        vmax = v;
    }
    else
      hasZero = true;
  }

  if (vmax == 0)
  {
    if (verbose)
    {
      std::cout << "Block with only zeroes!" << std::endl;
      std::cout << std::flush;
      std::cerr << "WARNING: is_indirect_block() was called for a block with ONLY zeroes. "
	  "The correct return value depends on where we were called from. This is not "
	  "implemented yet!" << std::endl;
    }
    // This should return 'true' if we're called from is_double_indirect_block or is_tripple_indirect_block:
    // it should not lead to failure namely. In any case, we can definitely not be sure we return the
    // correct value; a block with only zeroes can theoretically be anything.
    return false;	// Only zeroes.
  }

  // Maximum number of bytes to allocate in an array.
  uint32_t const max_array_size = blocks_per_group(super_block);

  // [2] Search for duplicate entries.
  if (vmax - vmin < max_array_size)
  {
    char t[max_array_size];
    std::memset(t, 0, sizeof(t));

    for (int i = 0; i < values_per_block; ++i)
    {
      uint32_t v = blockVals[i];
      if (!v)
        break;
      if (t[v - vmin])
      {
        // Value already present!
	if (verbose)
	  std::cout << "Duplicated values!" << std::endl;
        return false;
      }
      t[v - vmin] = 1;
    }

    return true;
  }
  else
  {
    // Block is of the form [b1], [b2], ... [bk] ZEROES, but
    // [b1] ... [bk] spans more than one group.
    // Use a set<> to check if they are all different.
    std::set<uint32_t> bvSet;
    for (int i = 0; i < values_per_block; ++i)
    {
      uint32_t v = blockVals[i];
      if (!v)
        break;
      if (!bvSet.insert(v).second)	// Was already inserted?
      {
	if (verbose)
	  std::cout << "Duplicated values!" << std::endl;
        return false;
      }
    }
    return true;
  }
}
