// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file is_blockdetection.cc Implementation of various is_* functions that detect the type of blocks.
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
#include <sstream>
#include "debug.h"
#endif

#include "globals.h"
#include "conversion.h"
#include "load_meta_data.h"
#include "is_blockdetection.h"
#include "is_filename_char.h"
#include "commandline.h"
#include "accept.h"
#include "forward_declarations.h"

//-----------------------------------------------------------------------------
//
// Block type detection: is_*
//

bool is_inode(int block)
{
  int group = block_to_group(super_block, block);
  if (block_bitmap[group] == NULL)
    load_meta_data(group);
  int inode_table = group_descriptor_table[group].bg_inode_table;
  return block >= inode_table &&										    // The first block of the inode table.
         (size_t)block_size_ * (block + 1) <= (size_t)block_size_ * inode_table + inodes_per_group_ * inode_size_;  // The first byte after the block/inode table.
}

// Only valid when is_inode returns true.
// Returns the number of the first inode in the block.
int block_to_inode(int block)
{
  int group = block_to_group(super_block, block);
  ASSERT(block_bitmap[group]);
  int inode_table = group_descriptor_table[group].bg_inode_table;
  ASSERT(block >= inode_table && (size_t)block_size_ * (block + 1) <= (size_t)block_size_ * inode_table + inodes_per_group_ * inode_size_);
  return 1 + group * inodes_per_group_ + (size_t)block_size_ * (block - inode_table) / inode_size_;
}

// Convert inode number to block number.
// Return the block number that contains the inode.
int inode_to_block(ext3_super_block const& super_block, int inode)
{
  int group = inode_to_group(super_block, inode);
  return group_descriptor_table[group].bg_inode_table + (size_t)(inode - 1 - group * inodes_per_group_) * inode_size_ / block_size_;
}

struct DelayedWarning {
  std::ostringstream* delayed_warning;

  DelayedWarning() : delayed_warning(NULL) { }
  ~DelayedWarning() { if (delayed_warning) delete delayed_warning; }

  void init(void) { if (!delayed_warning) delayed_warning = new std::ostringstream; }
  operator bool(void) const { return delayed_warning; }
  std::string str(void) const { ASSERT(delayed_warning); return delayed_warning->str(); }
  std::ostream& stream(void) { init(); return *delayed_warning; }
};

// Print string, escaping non ASCII characters.
void print_buf_to(std::ostream& os, char const* buf, int len)
{
  for (int i = 0; i < len; ++i)
  {
    __s8 c = buf[i];
    if (c > 31 && c != 92 && c != 127)	// Only print pure ASCII (and therefore UTF8) characters.
      os.put(c);
    else
    {
      static char const c2s_tab[7] = { 'a', 'b', 't', 'n', 'v', 'f', 'r' };
      os.put('\\');
      if (c > 6 && c < 14)
      {
	os.put(c2s_tab[c - 7]);
	return;
      }
      else if (c == '\e')
      {
	os.put('e');
	return;
      }
      else if (c == '\\')
      {
	os.put('\\');
	return;
      }
      short old_fill = os.fill('0');
      std::ios_base::fmtflags old_flgs = os.flags();
      os.width(3);
      os << std::oct << (int)((unsigned char)c);
      os.setf(old_flgs);
      os.fill(old_fill);
    }
  }
}

// Return true if this block looks like it contains a directory.
is_directory_type is_directory(unsigned char* block, int blocknr, DirectoryBlockStats& stats, bool start_block, bool certainly_linked, int offset)
{
  ASSERT(!start_block || offset == 0);
  // Must be aligned to 4 bytes.
  if ((offset & EXT3_DIR_ROUND))
    return isdir_no;
  // A minimal ext3_dir_entry_2 must fit.
  if (offset + EXT3_DIR_REC_LEN(1) > block_size_)
    return isdir_no;
  ext3_dir_entry_2* dir_entry = reinterpret_cast<ext3_dir_entry_2*>(block + offset);
  // The first block has the "." and ".." directories at the start.
  bool is_start = false;
  if (offset == 0)
  {
    ext3_dir_entry_2* parent_dir_entry = reinterpret_cast<ext3_dir_entry_2*>(block + EXT3_DIR_REC_LEN(1));
    is_start = (dir_entry->name_len == 1 &&
                dir_entry->name[0] == '.' &&
		dir_entry->rec_len == EXT3_DIR_REC_LEN(1) &&
		(!feature_incompat_filetype || dir_entry->file_type == EXT3_FT_DIR) &&
		parent_dir_entry->name_len == 2 &&
		parent_dir_entry->name[0] == '.' &&
		parent_dir_entry->name[1] == '.' &&
		(!feature_incompat_filetype || parent_dir_entry->file_type == EXT3_FT_DIR));
  }      
  if (start_block)
  {
    // If a start block is requested, return isdir_no when it is NOT isdir_start,
    // even though it might still really be isdir_extended, in order to speed
    // up the test.
    if (!is_start)
      return isdir_no;
  }
  // The inode is not overwritten when a directory is deleted (except
  // for the first inode of an extended directory block).
  // So even for deleted directories we can check the inode range.
  DelayedWarning delayed_warning;
  if (dir_entry->inode == 0 && dir_entry->name_len > 0)
  {
    // If the inode is zero and the filename makes no sense, reject the directory.
    bool non_ascii = false;
    for (int c = 0; c < dir_entry->name_len; ++c)
    {
      filename_char_type result = is_filename_char(dir_entry->name[c]);
      if (result == fnct_illegal)
	return isdir_no;
      if (result == fnct_non_ascii)
	non_ascii = true;
    }
    // If the inode is zero, but the filename makes sense, print a warning
    // only when the inode really wasn't expected to be zero. Do not reject
    // the directory though.
    if (certainly_linked && (offset != 0 || start_block) &&
        (blocknr != 4745500 && blocknr != 6546132 && blocknr != 6549681 && blocknr != 6550057 && blocknr != 6582345 && blocknr != 6582333 && blocknr != 6583272))
    {
      delayed_warning.stream() << "WARNING: zero inode (name: ";
      if (non_ascii)
        delayed_warning.stream() << "*contains non-ASCII characters* ";
      delayed_warning.stream() << "\"";
      print_buf_to(delayed_warning.stream(), dir_entry->name, dir_entry->name_len);
      delayed_warning.stream() << "\"; block: " << blocknr << "; offset 0x" << std::hex << offset << std::dec << ")\n";
    }
  }
  if (dir_entry->inode > inode_count_)
    return isdir_no;	// Inode out of range.
  // File names are at least 1 character long.
  if (dir_entry->name_len == 0)
    return isdir_no;
  // The record length must make sense.
  if ((dir_entry->rec_len & EXT3_DIR_ROUND) ||
      dir_entry->rec_len < EXT3_DIR_REC_LEN(dir_entry->name_len) ||
      offset + dir_entry->rec_len > block_size_)
    return isdir_no;
  // Add some extra paranoia in the case that the whole block appears to exist of a single direntry (for an extended block).
  if (dir_entry->rec_len == block_size_ &&
      ((feature_incompat_filetype && dir_entry->file_type == EXT3_FT_UNKNOWN) ||
       dir_entry->file_type >= EXT3_FT_MAX ||
       dir_entry->name_len == 1 ||
       (dir_entry->name[0] == '_' && dir_entry->name[1] == 'Z')))	// Symbol table entry?
    return isdir_no;
  // The record length must point to the end of the block or chain to it.
  offset += dir_entry->rec_len;
  // NOT USED; int previous_number_of_entries = stats.number_of_entries();
  if (offset != block_size_ && is_directory(block, blocknr, stats, false, certainly_linked, offset) == isdir_no)
    return isdir_no;
  // The file name may only exist of certain characters.
  bool illegal = false;
  bool ok = true;
  int number_of_weird_characters = 0;
  for (int c = 0; c < dir_entry->name_len; ++c)
  {
    filename_char_type fnct = is_filename_char(dir_entry->name[c]);
    if (fnct != fnct_ok)
    {
      if (fnct == fnct_illegal)
      {
        ok = false;
        illegal = true;
	break;
      }
      ++number_of_weird_characters;
      stats.increment_unlikely_character_count(dir_entry->name[c]);
    }
  }
  // If the user asks for a specific block, don't suppress anything.
  if (commandline_block != -1)
    number_of_weird_characters = 0;
#if 1
  // Accept everything at this point, except filenames existing of a single unlikely character.
  // If --accept-all is given, accept even those.
  if (!commandline_accept_all && dir_entry->name_len == 1 && number_of_weird_characters > 0)
    ok = false;
#else
  // Setting ok to false means we reject this entry. Also setting illegal will reject it silently.
  // The larger the number of previous entries, the larger the chance that this is really a good dir entry.
  // Therefore, accept weird characters to a certain extend.
  if (number_of_weird_characters > previous_number_of_entries || number_of_weird_characters > dir_entry->name_len / 2)
    ok = false;
  // If a filenames exists of exclusively weird characters (most notably filenames of length 1), don't believe this can be a real entry.
  if (!illegal && number_of_weird_characters == dir_entry->name_len)
  {
    if (dir_entry->name_len > 1)
    {
      // But you never know, so let the user know about it.
      std::cout << "Note: Rejecting '";
      print_buf_to(std::cout, dir_entry->name, dir_entry->name_len);
      std::cout << "' as possibly legal filename.\n";
    }
    illegal = true;
    ok = false;
  }
#endif
  if (ok && delayed_warning)
  {
    std::cout << std::flush;
    std::cerr << delayed_warning.str();
    std::cerr << std::flush;
  }
  if (!ok && !illegal)
  {
    std::ostringstream escaped_name;
    print_buf_to(escaped_name, dir_entry->name, dir_entry->name_len);
    Accept const accept(escaped_name.str(), false);
    std::set<Accept>::iterator accept_iter = accepted_filenames.find(accept);
    if (accept_iter != accepted_filenames.end())
      ok = accept_iter->accepted();
    else
    {
      // Add this entry to avoid us printing this again.
      accepted_filenames.insert(accept);
      std::cout << std::flush;
      if (certainly_linked)
	std::cerr << "\nWARNING: Rejecting possible directory (block " << blocknr << ") because an entry contains legal but unlikely characters.\n";
      else // Aparently we're looking for deleted entries.
	std::cerr << "\nWARNING: Rejecting a dir_entry (block " << blocknr << ") because it contains legal but unlikely characters.\n";
      std::cerr     << "         Use --ls --block " << blocknr << " to examine this possible directory block.\n";
      std::cerr     << "         If it looks like a directory to you, and '" << escaped_name.str() << "'\n";
      std::cerr     << "         looks like a filename that might belong in that directory, then add\n";
      std::cerr     << "         --accept='" << escaped_name.str() << "' as commandline parameter AND remove both stage* files!" << std::endl;
    }
  }
  if (ok)
    stats.increment_number_of_entries();
  return ok ? (is_start ? isdir_start : isdir_extended) : isdir_no;
}

// Returns true if the block is inside an inode table,
// or part of the journal, containing inodes.
int is_inode_block(int block)
{
  if (is_inode(block))
    return block;
  if (!is_journal(block) || is_indirect_block_in_journal(block))
    return 0;
  return journal_block_contains_inodes(block);
}

bool is_allocated(int inode)
{
  int group = (inode - 1) / inodes_per_group_;
  if (!block_bitmap[group])
    load_meta_data(group);
  unsigned int bit = inode - 1 - group * inodes_per_group_;
  ASSERT(bit < 8U * block_size_);
  bitmap_ptr bmp = get_bitmap_mask(bit);
  return (inode_bitmap[group][bmp.index] & bmp.mask);
}
