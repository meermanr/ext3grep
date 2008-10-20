// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file ostream_operators.cc Implementation of various ostream inserter functions.
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
#include <iostream>
#include <iomanip>
#include "debug.h"
#endif

#include "endian_conversion.h"
#include "superblock.h"
#include "globals.h"

//-----------------------------------------------------------------------------
//
// ostream operator<<'s
//

struct FileSystemState {
  private:
    __le16 M_state;
  public:
    FileSystemState(__le16 state) : M_state(state) { }
    friend std::ostream& operator<<(std::ostream& os, FileSystemState const& state)
	{
	  if ((state.M_state & EXT3_VALID_FS))
	    os << "'Unmounted cleanly'";
	  else
	    os << "Not clean";
	  if ((state.M_state & EXT3_ERROR_FS))
	    os << " 'Errors detected'";
	  return os;
	}
};

std::ostream& operator<<(std::ostream& os, ext3_super_block const& super_block)
{
  // This was generated with:
  // awk 'BEGIN { decode=0 } /^struct ext3_super_block/ { decode=1 } /^};/ { decode=0 } { if (decode) print; }' /usr/include/linux/ext3_fs.h | sed -rn 's/^[[:space:]]*(|\/\*[0-9A-F]*\*\/[[:space:]]*)__[[:alnum:]_]*[[:space:]]*(s_[[:alnum:]_]*)(;|\[[0-9]+\];)[[:space:]]*\/\*[[:space:]](.*)[[:space:]]\*\/.*/  os << "\4: " << super_block.\2 << '"'"'\\n'"'"';/p'
  os << "Inodes count: " << inode_count(super_block) << '\n';
  os << "Blocks count: " << block_count(super_block) << '\n';
  os << "Reserved blocks count: " << reserved_block_count(super_block) << '\n';
  os << "Free blocks count: " << super_block.s_free_blocks_count << '\n';
  os << "Free inodes count: " << super_block.s_free_inodes_count << '\n';
  os << "First Data Block: " << first_data_block(super_block) << '\n';
  os << "Block size: " << block_size(super_block) << '\n';
  os << "Fragment size: " << fragment_size(super_block) << '\n';
  os << "Number of blocks per group: " << blocks_per_group(super_block) << '\n';
  os << "Number of fragments per group: " << super_block.s_frags_per_group << '\n';
  os << "Number of inodes per group: " << inodes_per_group(super_block) << '\n';
  time_t mtime = super_block.s_mtime;
  os << "Mount time: " << std::ctime(&mtime);
  time_t wtime = super_block.s_wtime;
  os << "Write time: " << std::ctime(&wtime);
  os << "Mount count: " << super_block.s_mnt_count << '\n';
  os << "Maximal mount count: " << super_block.s_max_mnt_count << '\n';
  os << "Magic signature: " << std::hex << "0x" << super_block.s_magic << std::dec << '\n';
  os << "File system state: " << FileSystemState(super_block.s_state) << '\n';
  // os << "Behaviour when detecting errors: " << super_block.s_errors << '\n';
  // os << "minor revision level: " << super_block.s_minor_rev_level << '\n';
  // os << "time of last check: " << super_block.s_lastcheck << '\n';
  // os << "max. time between checks: " << super_block.s_checkinterval << '\n';
  // os << "OS: " << super_block.s_creator_os << '\n';
  // os << "Revision level: " << super_block.s_rev_level << '\n';
  // os << "Default uid for reserved blocks: " << super_block.s_def_resuid << '\n';
  // os << "Default gid for reserved blocks: " << super_block.s_def_resgid << '\n';
  // os << "First non-reserved inode: " << super_block.s_first_ino << '\n';
  os << "Size of inode structure: " << super_block.s_inode_size << '\n';
  os << "Block group # of this superblock: " << super_block.s_block_group_nr << '\n';
  os << "compatible feature set:";
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_DIR_PREALLOC))
    os << " DIR_PREALLOC";
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_IMAGIC_INODES))
    os << " IMAGIC_INODES";
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL))
    os << " HAS_JOURNAL";
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_EXT_ATTR))
    os << " EXT_ATTR";
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_RESIZE_INODE))
    os << " RESIZE_INODE";
  if ((super_block.s_feature_compat & EXT3_FEATURE_COMPAT_DIR_INDEX))
    os << " DIR_INDEX";
  os << '\n';
  os << "incompatible feature set:";
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_COMPRESSION))
    os << " COMPRESSION";
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_FILETYPE))
    os << " FILETYPE";
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER))
    os << " RECOVER";
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_JOURNAL_DEV))
    os << " JOURNAL_DEV";
  if ((super_block.s_feature_incompat & EXT3_FEATURE_INCOMPAT_META_BG))
    os << " META_BG";
  os << '\n';
  os << "readonly-compatible feature set:";
  if ((super_block.s_feature_ro_compat & EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER))
    os << " SPARSE_SUPER";
  if ((super_block.s_feature_ro_compat & EXT3_FEATURE_RO_COMPAT_LARGE_FILE))
    os << " LARGE_FILE";
  if ((super_block.s_feature_ro_compat & EXT3_FEATURE_RO_COMPAT_BTREE_DIR))
    os << " BTREE_DIR";
  os << '\n';
  // os << "128-bit uuid for volume: " << super_block.s_uuid << '\n';
  // os << "For compression: " << super_block.s_algorithm_usage_bitmap << '\n';
  // os << "Nr to preallocate for dirs: " << super_block.s_prealloc_dir_blocks << '\n';
  os << "Per group desc for online growth: " << super_block.s_reserved_gdt_blocks << '\n';
  os << "UUID of journal superblock:";
  for (int i = 0; i < 16; ++i)
    os << " 0x" << std::hex << std::setfill('0') << std::setw(2) << (int)super_block.s_journal_uuid[i];
  os << std::dec << '\n';
  os << "Inode number of journal file: " << super_block.s_journal_inum << '\n';
  os << "Device number of journal file: " << super_block.s_journal_dev << '\n';
  os << "Start of list of inodes to delete: " << super_block.s_last_orphan << '\n';
  // os << "HTREE hash seed: " << super_block.s_hash_seed << '\n';
  // os << "Default hash version to use: " << super_block.s_def_hash_version << '\n';
  os << "First metablock block group: " << super_block.s_first_meta_bg << '\n';
  // os << "Padding to the end of the block: " << super_block.s_reserved << '\n';
  return os;
}

std::ostream& operator<<(std::ostream& os, ext3_group_desc const& group_desc)
{
  os << "block bitmap at " << group_desc.bg_block_bitmap <<
        ", inodes bitmap at " << group_desc.bg_inode_bitmap <<
	", inode table at " << group_desc.bg_inode_table << '\n';
  os << "\t   " << group_desc.bg_free_blocks_count << " free blocks, " <<
                   group_desc.bg_free_inodes_count << " free inodes, " <<
		   group_desc.bg_used_dirs_count << " used directory";
  return os;
}

std::ostream& operator<<(std::ostream& os, journal_header_t const& journal_header)
{
  os << "Block type: ";
  switch (be2le(journal_header.h_blocktype))
  {
    case JFS_DESCRIPTOR_BLOCK:
      os << "Descriptor block";
      break;
    case JFS_COMMIT_BLOCK:
      os << "Commit block";
      break;
    case JFS_SUPERBLOCK_V1:
      os << "Superblock version 1";
      break;
    case JFS_SUPERBLOCK_V2:
      os << "Superblock version 2";
      break;
    case JFS_REVOKE_BLOCK:
      os << "Revoke block";
      break;
    default:
      os << "*UNKNOWN* (0x" << std::hex << be2le(journal_header.h_blocktype) << std::dec << ')';
      break;
  }
  os << '\n';
  os << "Sequence Number: " << be2le(journal_header.h_sequence);
  return os;
}

std::ostream& operator<<(std::ostream& os, journal_superblock_t const& journal_super_block)
{
  os << journal_super_block.s_header << '\n';
  os << "Journal block size: " << be2le(journal_super_block.s_blocksize) << '\n';
  os << "Number of journal blocks: " << be2le(journal_super_block.s_maxlen) << '\n';
  os << "Journal block where the journal actually starts: " << be2le(journal_super_block.s_first) << '\n';
  os << "Sequence number of first transaction: " << be2le(journal_super_block.s_sequence) << '\n';
  os << "Journal block of first transaction: " << be2le(journal_super_block.s_start) << '\n';
  os << "Error number: " << be2le(journal_super_block.s_errno) << '\n';
  if (be2le(journal_super_block.s_header.h_blocktype) != JFS_SUPERBLOCK_V2)
    return os;
  os << "Compatible Features: " << be2le(journal_super_block.s_feature_compat) << '\n';
  os << "Incompatible features: " << be2le(journal_super_block.s_feature_incompat) << '\n';
  os << "Read only compatible features: " << be2le(journal_super_block.s_feature_ro_compat) << '\n';
  os << "Journal UUID:";
  for (int i = 0; i < 16; ++i)
    os << std::hex << " 0x" << std::setfill('0') << std::setw(2) << (int)be2le(journal_super_block.s_uuid[i]);
  os << std::dec << '\n';
  int32_t nr_users = be2le(journal_super_block.s_nr_users);
  os << "Number of file systems using journal: " << nr_users << '\n';
  ASSERT(nr_users <= 48);
  os << "Location of superblock copy: " << be2le(journal_super_block.s_dynsuper) << '\n';
  os << "Max journal blocks per transaction: " << be2le(journal_super_block.s_max_transaction) << '\n';
  os << "Max file system blocks per transaction: " << be2le(journal_super_block.s_max_trans_data) << '\n';
  os << "IDs of all file systems using the journal:\n";
  for (int u = 0; u < nr_users; ++u)
  {
    os << (u + 1) << '.';
    for (int i = 0; i < 16; ++i)
      os << std::hex << " 0x" << std::setfill('0') << std::setw(2) << (int)be2le(journal_super_block.s_users[u * 16 + i]);
    os << std::dec << '\n';
  }
  return os;
}

std::ostream& operator<<(std::ostream& os, journal_block_tag_t const& journal_block_tag)
{
  os << "File system block: " << be2le(journal_block_tag.t_blocknr) << '\n';
  os << "Entry flags:";
  uint32_t flags = be2le(journal_block_tag.t_flags);
  if ((flags & JFS_FLAG_ESCAPE))
    os << " ESCAPED";
  if ((flags & JFS_FLAG_SAME_UUID))
    os << " SAME_UUID";
  if ((flags & JFS_FLAG_DELETED))
    os << " DELETED";
  if ((flags & JFS_FLAG_LAST_TAG))
    os << " LAST_TAG";
  os << '\n';
  return os;
}

std::ostream& operator<<(std::ostream& os, journal_revoke_header_t const& journal_revoke_header)
{
  os << journal_revoke_header.r_header << '\n';
  uint32_t count = be2le(journal_revoke_header.r_count);
  os << "Bytes used: " << count << '\n';
  ASSERT(sizeof(journal_revoke_header_t) <= count && count <= (size_t)block_size_);
  count -= sizeof(journal_revoke_header_t);
  ASSERT(count % sizeof(__be32) == 0);
  count /= sizeof(__be32);
  __be32 const* ptr = reinterpret_cast<__be32 const*>((unsigned char const*)&journal_revoke_header + sizeof(journal_revoke_header_t));
  int c = 0;
  if (count > 0)
    std::cout << "Revoked blocks:\n";
  for (uint32_t b = 0; b < count; ++b)
  {
    std::cout << std::setfill(' ') << std::setw(9) << be2le(ptr[b]);
    ++c;
    c &= 7;
    if (c == 0)
      std::cout << '\n';
    else
      std::cout << ' ';
  }
  return os;
}
