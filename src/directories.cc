// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file directories.cc Implementation of class Directory and iteration over directories.
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
#endif

#include "Parent.h"
#include "commandline.h"
#include "is_blockdetection.h"
#include "forward_declarations.h"
#include "indirect_blocks.h"
#include "get_block.h"
#include "directories.h"

//-----------------------------------------------------------------------------
//
// Directories
// Iterating over directories
//

static int const mode_map[8] = {
  0x10000, // EXT3_FT_UNKNOWN
   0x8000, // EXT3_FT_REG_FILE
   0x4000, // EXT3_FT_DIR
   0x2000, // EXT3_FT_CHRDEV
   0x6000, // EXT3_FT_BLKDEV
   0x1000, // EXT3_FT_FIFO
   0xC000, // EXT3_FT_SOCK
   0xA000  // EXT3_FT_SYMLINK
};

struct iterate_data_st {
  bool (*action)(ext3_dir_entry_2 const&, Inode const&, bool, bool, bool, bool, bool, bool, Parent*, void*);
  Parent* parent;
  void* data;
  unsigned char* block_buf;

  iterate_data_st(void) : block_buf(NULL) { }
  ~iterate_data_st() { if (block_buf) delete [] block_buf; }
};

int depth;
bool read_block_action(ext3_dir_entry_2 const& dir_entry, Inode const& inode,
    bool deleted, bool allocated, bool reallocated, bool zero_inode, bool linked, bool filtered, Parent* parent, void* data);
#ifdef CPPGRAPH
void iterate_over_directory__with__read_block_action(void) { (void)read_block_action(*(ext3_dir_entry_2 const*)NULL, *(Inode const*)NULL, 0, 0, 0, 0, 0, 0, NULL, NULL); }
#endif
bool init_directories_action(ext3_dir_entry_2 const& dir_entry, Inode const&, bool, bool, bool, bool, bool, bool, Parent* parent, void*);

static void filter_dir_entry(ext3_dir_entry_2 const& dir_entry,
                             bool deleted, bool linked,
			     bool (*action)(ext3_dir_entry_2 const&, Inode const&, bool, bool, bool, bool, bool, bool, Parent*, void*),
			     Parent* parent, void* data)
{
  InodePointer inode;
  int file_type = (dir_entry.file_type & 7);
  bool zero_inode = (dir_entry.inode == 0);
  bool filtered = (zero_inode && !commandline_zeroed_inodes);
  bool allocated = false;
  bool reallocated = false;
  if (!zero_inode)
  {
    inode = get_inode(dir_entry.inode);
    allocated = is_allocated(dir_entry.inode);
    reallocated = (deleted && allocated) || (deleted && !inode->is_deleted()) || (feature_incompat_filetype && mode_map[file_type] != (inode->mode() & 0xf000));
    deleted = deleted || inode->is_deleted();
    // Block pointers are erased on ext3 on deletion (that is the whole point of writing this tool!),
    // however - in the case of symlinks, the name of the symlink is (still) in this place.
    // Only printing this for regular files and directories, as also char/block devices seem to
    // sometimes have a non-zero block list, and we don't "recover" those anyway.
    if (inode->has_valid_dtime() && inode->block()[0] != 0 && (is_regular_file(inode) || is_directory(inode)))
    {
      time_t dtime = inode->dtime();
      std::string dtime_str(std::ctime(&dtime));
      std::cout << "Note: Inode " << dir_entry.inode << " has non-zero dtime (" << inode->dtime() <<
	  "  " << dtime_str.substr(0, dtime_str.length() - 1) << ") but non-zero block list (" << inode->block()[0] <<
	  ") [ext3grep does" << (inode->is_deleted() ? "" : " not") << " consider this inode to be deleted]\n";
    }
    filtered = !(
	(!commandline_allocated || allocated) &&
	(!commandline_unallocated || !allocated) &&
	(!commandline_deleted || deleted) &&
	(!commandline_directory || is_directory(inode)) &&
	(!reallocated || commandline_reallocated) &&
	(reallocated ||
	    (!inode->is_deleted() && !commandline_deleted) ||
	    (inode->has_valid_dtime() && commandline_after <= (time_t)inode->dtime() && (!commandline_before || (time_t)inode->dtime() < commandline_before))));
  }
  if (no_filtering)	// Also no recursion.
    // inode is dereferenced here in good faith that no reference to it is kept (since there are no structs or classes that do so).
    action(dir_entry, *inode, deleted, allocated, reallocated, zero_inode, linked, filtered, parent, data);
  else if (!filtered)
  {
    // inode is dereferenced here in good faith that no reference to it is kept (since there are no structs or classes that do so).
    if (action(dir_entry, *inode, deleted, allocated, reallocated, zero_inode, linked, filtered, parent, data))
      return;	// Recursion aborted.
    // Handle recursion.
    if (parent && is_directory(inode) && depth < commandline_depth)
    {
      // Skip "." and ".." when iterating recursively.
      if ((dir_entry.name_len == 1 && dir_entry.name[0] == '.') ||
	  (dir_entry.name_len == 2 && dir_entry.name[0] == '.' && dir_entry.name[1] == '.'))
        return;
      iterate_data_st idata;
      idata.action = action;
      idata.data = data;
      Parent new_parent(parent, &dir_entry, inode, dir_entry.inode);
      idata.parent = &new_parent;
      // Break possible loops as soon as we see an inode number that we encountered before.
      static std::vector<uint32_t> inodes(64);
      if (inodes.size() < (size_t)depth + 1)
        inodes.resize(inodes.size() * 2);
      for (int d = 1; d < depth; ++d)
      {
        if (inodes[d] == dir_entry.inode)
	{
	  std::cout << "Detected loop for inode " << dir_entry.inode << " (" << idata.parent->dirname(commandline_show_path_inodes) << ").\n";
	  return;
	}
      }
      inodes[depth] = dir_entry.inode;
      ++depth;
      if (!deleted && allocated && !reallocated)	// Existing directory?
      {
        InodePointer inoderef(get_inode(dir_entry.inode));
	bool reused_or_corrupted_indirect_block3 = iterate_over_all_blocks_of(inoderef, dir_entry.inode, iterate_over_existing_directory_action, &idata);
	ASSERT(!reused_or_corrupted_indirect_block3);
      }
      else
      {
        // We only know the first block, but that is enough to construct the directory tree.
	int blocknr = dir_inode_to_block(dir_entry.inode);
	if (blocknr != -1)
	{
	  // There could be loops if we linked the wrong directory to an inode.
	  // In any case we have to break those loops. Try to be smart about it:

	  // Find the dtime of the parent, or a parent of the parent.
	  uint32_t dtime = 0;
	  Parent* parent_iter = parent;
          while (!dtime)
	  {
	    if (!parent_iter)
	      break;
	    if (parent_iter->M_inode->has_valid_dtime())
	      dtime = parent_iter->M_inode->dtime();
	    parent_iter = parent_iter->M_parent;
	  }
	  // It turns out that a parent can be time-stamped as deleted before
	  // it's subdirectories when using rm -rf (?). Allow for 60 seconds
	  // of time difference.
	  if (!dtime || !inode->has_valid_dtime() || dtime + 60 >= inode->dtime())
	  {
	    // Now, before actually processing this new directory, check if the inode it contains for ".." is equal to the inode
	    // of it's parent directory!
	    idata.block_buf = new unsigned char [block_size_];
	    get_block(blocknr, idata.block_buf);
	    ext3_dir_entry_2* dir_entry = reinterpret_cast<ext3_dir_entry_2*>(idata.block_buf);
	    ASSERT(dir_entry->name_len == 1 && dir_entry->name[0] == '.');
	    dir_entry = reinterpret_cast<ext3_dir_entry_2*>(idata.block_buf + dir_entry->rec_len);
	    ASSERT(dir_entry->name_len == 2 && dir_entry->name[0] == '.' && dir_entry->name[1] == '.');
	    if (dir_entry->inode == parent->M_inodenr)
	      iterate_over_directory_action(blocknr, &idata);
	    else
	      std::cout << "The directory \"" << idata.parent->dirname(commandline_show_path_inodes) << "\" is lost.\n";
	  }
	}
	else
	  std::cout << "Cannot find a directory block for inode " << dir_entry.inode << ".\n";
      }
      --depth;
    }
  }
}

#ifdef CPPGRAPH
void iterate_over_directory__with__init_directories_action(void) { (void)init_directories_action(*(ext3_dir_entry_2 const*)NULL, *(Inode const*)NULL, 0, 0, 0, 0, 0, 0, NULL, NULL); }
#endif

void iterate_over_directory_action(int blocknr, void* data)
{
  iterate_data_st* idata = reinterpret_cast<iterate_data_st*>(data);
  iterate_over_directory(idata->block_buf, blocknr, idata->action, idata->parent, idata->data);
}

void iterate_over_existing_directory_action(int blocknr, int, void* data)
{
  iterate_data_st* idata = reinterpret_cast<iterate_data_st*>(data);
  unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  get_block(blocknr, block_buf);
  iterate_over_directory(block_buf, blocknr, idata->action, idata->parent, idata->data);
}

void iterate_over_directory(unsigned char* block, int blocknr,
    bool (*action)(ext3_dir_entry_2 const&, Inode const&, bool, bool, bool, bool, bool, bool, Parent*, void*), Parent* parent, void* data)
{
  ext3_dir_entry_2 const* dir_entry;
  ext3_dir_entry_2 const* map[EXT3_MAX_BLOCK_SIZE / EXT3_DIR_PAD];
  std::memset(map, 0, sizeof(map));

  if (action == read_block_action)
    ++no_filtering;

  int offset = 0;
  while (offset < block_size_)
  {
    dir_entry = reinterpret_cast<ext3_dir_entry_2 const*>(block + offset);
    filter_dir_entry(*dir_entry, false, true, action, parent, data);
    map[offset / EXT3_DIR_PAD] = dir_entry;
    offset += dir_entry->rec_len;
  }

  // Search for deleted entries.
  offset = block_size_ - EXT3_DIR_REC_LEN(1);
  while (offset > 0)
  {
    dir_entry = reinterpret_cast<ext3_dir_entry_2 const*>(block + offset);
    if (!map[offset / EXT3_DIR_PAD])
    {
      DirectoryBlockStats stats;
      if (is_directory(block, blocknr, stats, false, false, offset))
        filter_dir_entry(*dir_entry, true, false, action, parent, data);
    }
    offset -= EXT3_DIR_PAD;
  }

  if (action == read_block_action)
    --no_filtering;
}

bool DirEntry::exactly_equal(DirEntry const& de) const
{
  ASSERT(index.cur == de.index.cur);
  return M_inode == de.M_inode && M_name == de.M_name && M_file_type == de.M_file_type && index.next == de.index.next;
}

bool DirectoryBlock::exactly_equal(DirectoryBlock const& dir) const
{
  if (M_dir_entry.size() != dir.M_dir_entry.size())
    return false;
  std::vector<DirEntry>::const_iterator iter1 = M_dir_entry.begin();
  std::vector<DirEntry>::const_iterator iter2 = dir.M_dir_entry.begin();
  for (;iter1 != M_dir_entry.end(); ++iter1, ++iter2)
    if (!iter1->exactly_equal(*iter2))
      return false;
  return true;
}

bool read_block_action(ext3_dir_entry_2 const& dir_entry, Inode const& inode,
    bool deleted, bool allocated, bool reallocated, bool zero_inode, bool linked, bool filtered, Parent*, void* data)
{
  std::list<DirectoryBlock>::iterator* iter_ptr = reinterpret_cast<std::list<DirectoryBlock>::iterator*>(data);
  DirectoryBlock* directory = &**iter_ptr;
  directory->read_dir_entry(dir_entry, inode, deleted, allocated, reallocated, zero_inode, linked, filtered, *iter_ptr);
  return false;
}

void DirectoryBlock::read_dir_entry(ext3_dir_entry_2 const& dir_entry, Inode const& UNUSED(inode),
    bool deleted, bool allocated, bool reallocated, bool zero_inode, bool linked, bool filtered, std::list<DirectoryBlock>::iterator iter)
{
  DirEntry new_dir_entry;
  new_dir_entry.M_directory_iterator = iter;
  new_dir_entry.M_directory = NULL;
  new_dir_entry.M_file_type = dir_entry.file_type & 7;	// Only the last 3 bits are used.
  new_dir_entry.M_inode = dir_entry.inode;
  new_dir_entry.M_name = std::string(dir_entry.name, dir_entry.name_len);
  new_dir_entry.dir_entry = &dir_entry;		// This points directy into the block_buf that we are processing.
  						// It will be replaced with the indices before that buffer is destroyed.
  new_dir_entry.deleted = deleted;
  new_dir_entry.allocated = allocated;
  new_dir_entry.reallocated = reallocated;
  new_dir_entry.zero_inode = zero_inode;
  new_dir_entry.linked = linked;
  new_dir_entry.filtered = filtered;
  M_dir_entry.push_back(new_dir_entry);
}

struct DirEntrySortPred {
  bool operator()(DirEntry const& de1, DirEntry const& de2) const { return de1.dir_entry < de2.dir_entry; }
};

void DirectoryBlock::read_block(int block, std::list<DirectoryBlock>::iterator list_iter)
{
  M_block = block;
  static bool using_static_buffer = false;
  ASSERT(!using_static_buffer);
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  get_block(block, block_buf);
  using_static_buffer = true;
#ifdef CPPGRAPH
  // Let cppgraph know that we call read_block_action from here.
  iterate_over_directory__with__read_block_action();
#endif
  iterate_over_directory(block_buf, block, read_block_action, NULL, &list_iter);
  // Sort the vector by dir_entry pointer.
  std::sort(M_dir_entry.begin(), M_dir_entry.end(), DirEntrySortPred());
  int size = M_dir_entry.size();
  ASSERT(size > 0);	// Every directory has at least one entry.
  // Make a temporary backup of the dir_entry pointers.
  // At the same time, overwrite the pointers in the vector with with the index.
  ext3_dir_entry_2 const** index_to_dir_entry = new ext3_dir_entry_2 const* [size];
  int i = 0;
  for (std::vector<DirEntry>::iterator iter = M_dir_entry.begin(); iter != M_dir_entry.end(); ++iter, ++i)
  {
    index_to_dir_entry[i] = iter->dir_entry;
    iter->index.cur = i;
  }
  // Assign a value to index.next, if any.
  for (std::vector<DirEntry>::iterator iter = M_dir_entry.begin(); iter != M_dir_entry.end(); ++iter)
  {
    ext3_dir_entry_2 const* dir_entry = index_to_dir_entry[iter->index.cur];
    ext3_dir_entry_2 const* next_dir_entry = (ext3_dir_entry_2 const*)(reinterpret_cast<char const*>(dir_entry) + dir_entry->rec_len);
    int next = 0;
    for (int j = 0; j < size; ++j)
      if (index_to_dir_entry[j] == next_dir_entry)
      {
        next = j;
        break;
      }
    // Either this entry points to another that we found, or it should point to the end of this block.
    ASSERT(next > 0 || (unsigned char*)next_dir_entry == block_buf + block_size_);
    // If we didn't find anything, use the value 0.
    iter->index.next = next;
  }
  delete [] index_to_dir_entry;
  using_static_buffer = false;
}
