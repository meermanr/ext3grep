// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file journal.cc Journal related code.
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
#include <stdint.h>
#include <iostream>
#include "ext3.h"
#include "debug.h"
#endif

#include "journal.h"
#include "endian_conversion.h"
#include "globals.h"
#include "forward_declarations.h"
#include "superblock.h"
#include "indirect_blocks.h"
#include "get_block.h"
#include "commandline.h"

//-----------------------------------------------------------------------------
//
// Journal
//

class Descriptor;
static void add_block_descriptor(uint32_t block, Descriptor*);
static void add_block_in_journal_descriptor(Descriptor* descriptor);

std::ostream& operator<<(std::ostream& os, descriptor_type_nt descriptor_type)
{
  switch (descriptor_type)
  {
    case dt_unknown:
      os << "*UNKNOWN*";
      break;
    case dt_tag:
      os << "TAG";
      break;
    case dt_revoke:
      os << "REVOKE";
      break;
    case dt_commit:
      os << "COMMIT";
      break;
  }
  return os;
}

class DescriptorTag : public Descriptor {
  private:
    uint32_t M_blocknr;		// Block number on the file system.
    uint32_t M_flags;
  public:
    DescriptorTag(uint32_t block, uint32_t sequence, journal_block_tag_t* block_tag) :
        Descriptor(block, sequence), M_blocknr(be2le(block_tag->t_blocknr)), M_flags(be2le(block_tag->t_flags)) { }
    virtual descriptor_type_nt descriptor_type(void) const { return dt_tag; }
    virtual void print_blocks(void) const;
    virtual void add_block_descriptors(void) { add_block_descriptor(M_blocknr, this); add_block_in_journal_descriptor(this); }
    uint32_t block(void) const { return M_blocknr; }
};

void DescriptorTag::print_blocks(void) const
{
  std::cout << ' ' << Descriptor::block() << '=' << M_blocknr;
  if ((M_flags & (JFS_FLAG_ESCAPE|JFS_FLAG_DELETED)))
  {
    std::cout << '(';
    uint32_t flags = M_flags;
    if ((flags & JFS_FLAG_ESCAPE))
    {
      std::cout << "ESCAPED";
      flags &= ~JFS_FLAG_ESCAPE;
    }
    if (flags)
      std::cout << '|';
    if ((flags & JFS_FLAG_DELETED))
    {
      std::cout << "DELETED";
      flags &= ~JFS_FLAG_DELETED;
    }
    std::cout << ')';
  }
}

class DescriptorRevoke : public Descriptor {
  private:
    std::vector<uint32_t> M_blocks;
  public:
    DescriptorRevoke(uint32_t block, uint32_t sequence, journal_revoke_header_t* revoke_header);
    virtual descriptor_type_nt descriptor_type(void) const { return dt_revoke; }
    virtual void print_blocks(void) const;
    virtual void add_block_descriptors(void);
};

void DescriptorRevoke::add_block_descriptors(void)
{
  for (std::vector<uint32_t>::iterator iter = M_blocks.begin(); iter != M_blocks.end(); ++iter)
    add_block_descriptor(*iter, this);
  add_block_in_journal_descriptor(this);
}

DescriptorRevoke::DescriptorRevoke(uint32_t block, uint32_t sequence, journal_revoke_header_t* revoke_header) : Descriptor(block, sequence)
{
  uint32_t count = be2le(revoke_header->r_count);
  ASSERT(sizeof(journal_revoke_header_t) <= count && count <= (size_t)block_size_);
  count -= sizeof(journal_revoke_header_t);
  ASSERT(count % sizeof(__be32) == 0);
  count /= sizeof(__be32);
  __be32* ptr = reinterpret_cast<__be32*>((unsigned char*)revoke_header + sizeof(journal_revoke_header_t));
  for (uint32_t b = 0; b < count; ++b)
    M_blocks.push_back(be2le(ptr[b]));
}

void DescriptorRevoke::print_blocks(void) const
{
  for (std::vector<uint32_t>::const_iterator iter = M_blocks.begin(); iter != M_blocks.end(); ++iter)
    std::cout << ' ' << *iter;
}

class DescriptorCommit : public Descriptor {
  public:
    DescriptorCommit(uint32_t block, uint32_t sequence) : Descriptor(block, sequence) { }
    virtual descriptor_type_nt descriptor_type(void) const { return dt_commit; }
    virtual void print_blocks(void) const { }
    virtual void add_block_descriptors(void) { add_block_in_journal_descriptor(this); };
};

class Transaction {
  private:
    int M_block;
    int M_sequence;
    bool M_committed;
    std::vector<Descriptor*> M_descriptor;
  public:
    void init(int block, int sequence) { M_block = block; M_sequence = sequence; M_committed = false; }
    void set_committed(void) { ASSERT(!M_committed); M_committed = true; }
    void append(Descriptor* descriptor) { M_descriptor.push_back(descriptor); }

    void print_descriptors(void) const;
    int block(void) const { return M_block; }
    int sequence(void) const { return M_sequence; }
    bool committed(void) const { return M_committed; }
    bool contains_tag_for_block(int block);
};

bool Transaction::contains_tag_for_block(int block)
{
  for (std::vector<Descriptor*>::iterator iter = M_descriptor.begin(); iter != M_descriptor.end(); ++iter)
  {
    if ((*iter)->descriptor_type() == dt_tag)
    {
      DescriptorTag& tag(*static_cast<DescriptorTag*>(*iter));
      if (tag.block() == (uint32_t)block)
        return true;
    }
  }
  return false;
}

void Transaction::print_descriptors(void) const
{
  descriptor_type_nt dt = dt_unknown;
  for (std::vector<Descriptor*>::const_iterator iter = M_descriptor.begin(); iter != M_descriptor.end(); ++iter)
  {
    if ((*iter)->descriptor_type() != dt)
    {
      if (dt != dt_unknown)
	std::cout << '\n';
      dt = (*iter)->descriptor_type();
      std::cout << dt << ':';
    }
    (*iter)->print_blocks();
  }
  std::cout << '\n';
}

std::vector<Descriptor*> all_descriptors;
typedef std::map<int, Transaction> sequence_transaction_map_type;
sequence_transaction_map_type sequence_transaction_map;
block_to_descriptors_map_type block_to_descriptors_map;
block_in_journal_to_descriptors_map_type block_in_journal_to_descriptors_map;
block_to_dir_inode_map_type block_to_dir_inode_map;

static unsigned int number_of_descriptors;
static uint32_t min_sequence;
uint32_t max_sequence;

static void add_block_descriptor(uint32_t block, Descriptor* descriptor)
{
  block_to_descriptors_map_type::iterator iter = block_to_descriptors_map.find(block);
  if (iter == block_to_descriptors_map.end())
  {
    std::pair<block_to_descriptors_map_type::iterator, bool> res =
        block_to_descriptors_map.insert(block_to_descriptors_map_type::value_type(block, std::vector<Descriptor*>()));
    ASSERT(res.second);
    res.first->second.push_back(descriptor);
  }
  else
    iter->second.push_back(descriptor);
}

static void add_block_in_journal_descriptor(Descriptor* descriptor)
{
  std::pair<block_in_journal_to_descriptors_map_type::iterator, bool> res =
      block_in_journal_to_descriptors_map.insert(block_in_journal_to_descriptors_map_type::value_type(descriptor->block(), descriptor));
  ASSERT(res.second);
}

void print_block_descriptors(uint32_t block)
{
  block_to_descriptors_map_type::iterator iter = block_to_descriptors_map.find(block);
  if (iter == block_to_descriptors_map.end())
  {
    std::cout << "There are no descriptors in the journal referencing block " << block << ".\n";
    return;
  }
  std::cout << "Journal descriptors referencing block " << block << ":\n";
  for (std::vector<Descriptor*>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); ++iter2)
  {
    std::cout << (*iter2)->sequence() << ' ' << (*iter2)->block() << '\n';
  }
}

uint32_t find_largest_journal_sequence_number(int block)
{
  block_to_descriptors_map_type::iterator iter = block_to_descriptors_map.find(block);
  if (iter == block_to_descriptors_map.end())
    return 0;
  return (*iter->second.rbegin())->sequence();
}

bool action_tag_count(uint32_t, uint32_t sequence, journal_block_tag_t*, void*)
{
  min_sequence = std::min(sequence, min_sequence);
  max_sequence = std::max(sequence, max_sequence);
  ++number_of_descriptors;
  return false;
}

bool action_revoke_count(uint32_t, uint32_t sequence, journal_revoke_header_t*, void*)
{
  min_sequence = std::min(sequence, min_sequence);
  max_sequence = std::max(sequence, max_sequence);
  ++number_of_descriptors;
  return false;
}

bool action_commit_count(uint32_t, uint32_t sequence, void*)
{
  min_sequence = std::min(sequence, min_sequence);
  max_sequence = std::max(sequence, max_sequence);
  ++number_of_descriptors;
  return false;
}

void count_descriptors(void)
{
  number_of_descriptors = 0;
  min_sequence = 0xffffffff;
  max_sequence = 0;
  iterate_over_journal(action_tag_count, action_revoke_count, action_commit_count, NULL);
}

bool action_tag_fill(uint32_t block, uint32_t sequence, journal_block_tag_t* block_tag, void* data)
{
  uint32_t& descriptor_count = *reinterpret_cast<uint32_t*>(data);
  all_descriptors[descriptor_count++] = new DescriptorTag(block, sequence, block_tag);
  return false;
}

bool action_revoke_fill(uint32_t block, uint32_t sequence, journal_revoke_header_t* revoke_header, void* data)
{
  uint32_t& descriptor_count = *reinterpret_cast<uint32_t*>(data);
  all_descriptors[descriptor_count++] = new DescriptorRevoke(block, sequence, revoke_header);
  return false;
}

bool action_commit_fill(uint32_t block, uint32_t sequence, void* data)
{
  uint32_t& descriptor_count = *reinterpret_cast<uint32_t*>(data);
  all_descriptors[descriptor_count++] = new DescriptorCommit(block, sequence);
  return false;
}

struct AllDescriptorsPred {
  bool operator()(Descriptor* d1, Descriptor* d2) const { return d1->sequence() < d2->sequence(); }
};

static int smallest_block_nr;
static int largest_block_nr;
static bitmap_t* journal_block_bitmap = NULL;
static int min_journal_block;
static int max_journal_block;		// One more than largest block belonging to the journal.
static bitmap_t* is_indirect_block_in_journal_bitmap = NULL;

void find_blocknr_range_action(int blocknr, int, void*)
{
  if (blocknr > largest_block_nr)
    largest_block_nr = blocknr;
  if (blocknr < smallest_block_nr)
    smallest_block_nr = blocknr;
}

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__find_blocknr_range_action(void) { find_blocknr_range_action(0, 0, NULL); }
#endif

void fill_journal_bitmap_action(int blocknr, int, void*)
{
  bitmap_ptr bmp = get_bitmap_mask(blocknr - min_journal_block);
  journal_block_bitmap[bmp.index] |= bmp.mask;
}

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__fill_journal_bitmap_action(void) { fill_journal_bitmap_action(0, 0, NULL); }
#endif

void indirect_journal_block_action(int blocknr, int, void*)
{
  bitmap_ptr bmp = get_bitmap_mask(blocknr - min_journal_block);
  is_indirect_block_in_journal_bitmap[bmp.index] |= bmp.mask;
}

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__indirect_journal_block_action(void) { indirect_journal_block_action(0, 0, NULL); }
#endif

void directory_inode_action(int blocknr, int, void* data)
{
  int inode_number = *reinterpret_cast<int*>(data);
  block_to_dir_inode_map_type::iterator iter = block_to_dir_inode_map.find(blocknr);
  if (iter == block_to_dir_inode_map.end())
    block_to_dir_inode_map.insert(block_to_dir_inode_map_type::value_type(blocknr, inode_number));
  else
    iter->second = inode_number;	// We're called with ascending sequence numbers. Therefore, keep the last.
}

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__directory_inode_action(void) { directory_inode_action(0, 0, NULL); }
#endif

void init_journal(void)
{
  DoutEntering(dc::notice, "init_journal()");

  // Determine which blocks belong to the journal.
  ASSERT(is_allocated(super_block.s_journal_inum));	// Maybe this is the way to detect external journals?
  InodePointer journal_inode = get_inode(super_block.s_journal_inum);
  // Find the block range used by the journal.
  smallest_block_nr = block_count(super_block);
  largest_block_nr = 0;
#ifdef CPPGRAPH
  // Tell cppgraph that we call find_blocknr_range_action from here.
  iterate_over_all_blocks_of__with__find_blocknr_range_action();
#endif
  bool reused_or_corrupted_indirect_block4 =
      iterate_over_all_blocks_of(journal_inode, super_block.s_journal_inum, find_blocknr_range_action, NULL, indirect_bit | direct_bit);
  ASSERT(!reused_or_corrupted_indirect_block4);
  ASSERT(smallest_block_nr < largest_block_nr);		// A non-external journal must have a size.
  min_journal_block = smallest_block_nr;
  max_journal_block = largest_block_nr + 1;
  std::cout << "Minimum / maximum journal block: " << min_journal_block << " / " << max_journal_block << '\n';
  // Allocate and fill the bitmaps.
  int size = (max_journal_block - min_journal_block + 8 * sizeof(bitmap_t) - 1) / (8 * sizeof(bitmap_t));
  is_indirect_block_in_journal_bitmap = new bitmap_t [size];
  memset(is_indirect_block_in_journal_bitmap, 0, size * sizeof(bitmap_t));
#ifdef CPPGRAPH
  // Tell cppgraph that we call indirect_journal_block_action from here.
  iterate_over_all_blocks_of__with__indirect_journal_block_action();
#endif
  bool reused_or_corrupted_indirect_block5 =
      iterate_over_all_blocks_of(journal_inode, super_block.s_journal_inum, indirect_journal_block_action, NULL, indirect_bit);
  ASSERT(!reused_or_corrupted_indirect_block5);
  journal_block_bitmap = new bitmap_t [size];
  memset(journal_block_bitmap, 0, size * sizeof(bitmap_t));
#ifdef CPPGRAPH
  // Tell cppgraph that we call fill_journal_bitmap_action from here.
  iterate_over_all_blocks_of__with__fill_journal_bitmap_action();
#endif
  bool reused_or_corrupted_indirect_block6 =
      iterate_over_all_blocks_of(journal_inode, super_block.s_journal_inum, fill_journal_bitmap_action, NULL, indirect_bit | direct_bit);
  ASSERT(!reused_or_corrupted_indirect_block6);
  // Initialize the Descriptors.
  std::cout << "Loading journal descriptors..." << std::flush;
  wrapped_journal_sequence = 0;
  count_descriptors();
  all_descriptors.clear();
  all_descriptors.resize(number_of_descriptors);
  uint32_t descriptor_count = 0;
  iterate_over_journal(action_tag_fill, action_revoke_fill, action_commit_fill, &descriptor_count);
  ASSERT(all_descriptors.size() == number_of_descriptors);
  ASSERT(number_of_descriptors == 0 || all_descriptors[number_of_descriptors - 1]->descriptor_type() != dt_unknown);
  // Sort the descriptors in ascending sequence number.
  std::cout << " sorting..." << std::flush;
  std::sort(all_descriptors.begin(), all_descriptors.end(), AllDescriptorsPred());
  for (std::vector<Descriptor*>::iterator iter = all_descriptors.begin(); iter != all_descriptors.end(); ++iter)
  {
    int sequence = (*iter)->sequence();
    std::pair<sequence_transaction_map_type::iterator, bool> res =
        sequence_transaction_map.insert(sequence_transaction_map_type::value_type(sequence, Transaction()));
    switch((*iter)->descriptor_type())
    {
      case dt_tag:
      case dt_revoke:
        if (res.second)						// Did we just create this Transaction object?
	  res.first->second.init((*iter)->block(), sequence);	// Initialize it.
	res.first->second.append(*iter);
	(*iter)->add_block_descriptors();
        break;
      case dt_commit:
        if (res.second)						// Did we just create this Transaction object?
	  sequence_transaction_map.erase(res.first);		// We're not interested in a descriptor that exists of only a commit block.
	  							// FIXME: could be a wrapped around commit.
        else
	  res.first->second.set_committed();
        break;
      case dt_unknown:
        ASSERT((*iter)->descriptor_type() != dt_unknown);	// Fail; this should really never happen.
	break;
    }
  }
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  Inode const* inode = reinterpret_cast<Inode const*>(block_buf);
  // Run over all descriptors, in increasing sequence number.
  time_t oldtime = 0;
  for (std::vector<Descriptor*>::iterator iter = all_descriptors.begin(); iter != all_descriptors.end(); ++iter)
  {
    // Skip non-tags.
    if ((*iter)->descriptor_type() != dt_tag)
      continue;
    DescriptorTag* tag = static_cast<DescriptorTag*>(*iter);
    // Only process those that contain inodes.
    uint32_t block_nr = tag->block();
    if (!is_block_number(block_nr))
    {
      std::cout << block_nr << " is not a block number.\n";
      std::cout << "Sequence number: " << tag->sequence() << "; ";
      tag->print_blocks();
      std::cout << '\n';
      exit(EXIT_FAILURE);
    }
    if (is_inode(block_nr))
    {
      int inode_number = block_to_inode(block_nr);
      // Run over all inodes in the journal block.
      get_block(tag->Descriptor::block(), block_buf);
      __le32 lasttime = 0;
      for (unsigned int i = 0; i < block_size_ / sizeof(Inode); i += inode_size_ / sizeof(Inode), ++inode_number)
      {
        // REMOVE THIS:
	// print the inode number:
	//std::cout << "INODE IN JOURNAL: " << inode_number << std::endl;
	if (inode[i].atime() > lasttime || lasttime == 0)
	  lasttime = inode[i].atime(); 
	if (inode[i].ctime() > lasttime)
	  lasttime = inode[i].ctime();
	if (inode[i].mtime() > lasttime)
	  lasttime = inode[i].mtime();
	if (inode[i].dtime() > lasttime)
	  lasttime = inode[i].dtime();

        // Skip non-directories.
	if (!is_directory(inode[i]))
	  continue;
        // Skip deleted inodes.
        if (inode[i].is_deleted())
	  continue;
#ifdef CPPGRAPH
        // Tell cppgraph that we call directory_inode_action from here.
        iterate_over_all_blocks_of__with__directory_inode_action();
#endif
	// Run over all blocks of the directory inode.
	bool reused_or_corrupted_indirect_block7 = iterate_over_all_blocks_of(inode[i], inode_number, directory_inode_action, &inode_number);
	if (reused_or_corrupted_indirect_block7)
	{
	  std::cout << "Note: Block " << tag->Descriptor::block() << " in the journal contains a copy of inode " << inode_number <<
	      " which is a directory, but this directory has reused or corrupted (double/triple) indirect blocks.\n";
	}
      }
      // Normally a lasttime != 0 should do. But I ran into a case where the supposedly inode block
      // didn't contain inodes at all, but block numbers?! Therefore, check that lasttime > inode_count_,
      // which will be the case in 99.999% of the cases for a real time_t.
      if ((uint32_t)lasttime > inode_count_ && (__le32_to_cpu(lasttime) < (uint32_t)oldtime || oldtime == 0))
	oldtime = __le32_to_cpu(lasttime);
    }
  }
  std::cout << " done\n";
  std::cout << "The oldest inode block that is still in the journal, appears to be from " << oldtime << " = " << std::ctime(&oldtime);
  if (wrapped_journal_sequence)
  {
    static bool printed = false;
    if (!printed)
    {
      printed = true;
      std::cout << "Journal transaction " << wrapped_journal_sequence << " wraps around, some data blocks might have been lost of this transaction.\n";
    }
  }
  std::cout << "Number of descriptors in journal: " << number_of_descriptors << "; min / max sequence numbers: " << min_sequence << " / " << max_sequence << '\n';
}

bool is_in_journal(int blocknr)
{
  if (!journal_block_bitmap)
    init_journal();
  return blocknr >= min_journal_block && blocknr < max_journal_block;
}

bool is_journal(int blocknr)
{
  if (!super_block.s_journal_inum)
  {
    ASSERT(!commandline_journal);
    return false;
  }
  if (!is_in_journal(blocknr))
    return false;
  bitmap_ptr bmp = get_bitmap_mask(blocknr - min_journal_block);
  return (journal_block_bitmap[bmp.index] & bmp.mask);
}

bool is_indirect_block_in_journal(int blocknr)
{
  ASSERT(is_indirect_block_in_journal_bitmap);
  if (blocknr >= max_journal_block || blocknr < min_journal_block)
    return false;
  bitmap_ptr bmp = get_bitmap_mask(blocknr - min_journal_block);
  return (is_indirect_block_in_journal_bitmap[bmp.index] & bmp.mask);
}

int journal_block_contains_inodes(int blocknr)
{
  block_in_journal_to_descriptors_map_type::iterator iter = block_in_journal_to_descriptors_map.find(blocknr);
  if (iter == block_in_journal_to_descriptors_map.end())
    return 0;
  Descriptor& descriptor(*iter->second);
  if (descriptor.descriptor_type() != dt_tag)
    return 0;
  DescriptorTag& descriptor_tag(static_cast<DescriptorTag&>(descriptor));
  return is_inode(descriptor_tag.block()) ? descriptor_tag.block() : 0;
}

// This is the only function that accepts "journal block numbers",
// as opposed to "file system block numbers".
int journal_block_to_real_block(int blocknr)
{
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  ASSERT(blocknr >= 0 && blocknr < journal_maxlen_);
  if (blocknr < 12)
    return journal_inode.block()[blocknr];
  blocknr -= 12;
  int const vpb = block_size_ / sizeof(__le32);	// Values Per Block.
  if (blocknr < vpb)
  {
    get_block(journal_inode.block()[EXT3_IND_BLOCK], block_buf);
    __le32* indirect_block = reinterpret_cast<__le32*>(block_buf);
    return indirect_block[blocknr];
  }
  blocknr -= vpb;
  if (blocknr < vpb * vpb)
  {
    get_block(journal_inode.block()[EXT3_DIND_BLOCK], block_buf);
    __le32* double_indirect_block = reinterpret_cast<__le32*>(block_buf);
    get_block(double_indirect_block[blocknr / vpb], block_buf);
    __le32* indirect_block = reinterpret_cast<__le32*>(block_buf);
    return indirect_block[blocknr % vpb];
  }
  blocknr -= vpb * vpb;
  ASSERT(blocknr < vpb * vpb * vpb);
  get_block(journal_inode.block()[EXT3_TIND_BLOCK], block_buf);
  __le32* tripple_indirect_block = reinterpret_cast<__le32*>(block_buf);
  get_block(tripple_indirect_block[blocknr / (vpb * vpb)], block_buf);
  __le32* double_indirect_block = reinterpret_cast<__le32*>(block_buf);
  get_block(double_indirect_block[(blocknr / vpb) % vpb], block_buf);
  __le32* indirect_block = reinterpret_cast<__le32*>(block_buf);
  return indirect_block[blocknr % vpb];
}

void iterate_over_journal(
    bool (*action_tag)(uint32_t block, uint32_t sequence, journal_block_tag_t*, void* data),
    bool (*action_revoke)(uint32_t block, uint32_t sequence, journal_revoke_header_t*, void* data),
    bool (*action_commit)(uint32_t block, uint32_t sequence, void* data),
    void* data)
{
  uint32_t jbn = be2le(journal_super_block.s_first);
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  while(jbn < (uint32_t)journal_maxlen_)
  {
    // bn is the real block number inside the journal.
    uint32_t bn = journal_block_to_real_block(jbn);
    unsigned char* block = get_block(bn, block_buf);
    journal_header_t* descriptor = reinterpret_cast<journal_header_t*>(block);
    if (be2le(descriptor->h_magic) == JFS_MAGIC_NUMBER)
    {
      uint32_t blocktype = be2le(descriptor->h_blocktype);
      uint32_t sequence = be2le(descriptor->h_sequence);
      switch (blocktype)
      {
	case JFS_DESCRIPTOR_BLOCK:
	{
	  journal_block_tag_t* ptr = reinterpret_cast<journal_block_tag_t*>((unsigned char*)descriptor + sizeof(journal_header_t));
	  uint32_t flags;
	  do
	  {
	    ++jbn;
	    if (jbn >= (uint32_t)journal_maxlen_)
	    {
	      // This could be cheched by checking that the wrapped around block starts with JFS_MAGIC_NUMBER (which thus overwrote the data block).
	      wrapped_journal_sequence = sequence;
	      return;
	    }
	    else if (action_tag(journal_block_to_real_block(jbn), sequence, ptr, data))
	      return;
	    flags = be2le(ptr->t_flags);
	    if (!(flags & JFS_FLAG_SAME_UUID))
	      ptr = reinterpret_cast<journal_block_tag_t*>((char*)ptr + 16);
	    ++ptr;
	  }
	  while(!(flags & JFS_FLAG_LAST_TAG));
	  break;
	}
	case JFS_COMMIT_BLOCK:
	{
	  if (action_commit && action_commit(bn, sequence, data))
	    return;
	  break;
	}
	case JFS_REVOKE_BLOCK:
	{
	  if (action_revoke(bn, sequence, (journal_revoke_header_t*)descriptor, data))
	    return;
	  break;
	}
	default:
	{
	  std::cout << std::flush;
	  std::cerr << "WARNING: iterate_over_journal: unexpected blocktype (" << blocktype << "). Journal corrupt?" << std::endl;
	  return;
	}
      }
    }
    ++jbn;
  }
}

void handle_commandline_journal_transaction(void)
{
  sequence_transaction_map_type::iterator iter = sequence_transaction_map.find(commandline_journal_transaction);
  int prev = -1;
  int next = -1;
  if (iter == sequence_transaction_map.end())
  {
    std::cout << "There is no transaction in the journal with sequence number " << commandline_journal_transaction << '\n';
    if ((size_t)commandline_journal_transaction > max_sequence ||
        (size_t)commandline_journal_transaction < min_sequence)
      std::cout << "The sequences numbers found are in the range [" << min_sequence << ", " << max_sequence << "].\n";
    if ((size_t)commandline_journal_transaction < max_sequence)
    {
      if ((size_t)commandline_journal_transaction > min_sequence)
      {
	prev = commandline_journal_transaction;
	do
	{
	  --prev;
	  iter = sequence_transaction_map.find(prev);
	}
	while(iter == sequence_transaction_map.end());
      }
    }
    else if ((size_t)commandline_journal_transaction > min_sequence)
      prev = max_sequence;
    if ((size_t)commandline_journal_transaction > min_sequence)
    {
      if ((size_t)commandline_journal_transaction < max_sequence)
      {
	next = commandline_journal_transaction;
	do
	{
	  ++next;
	  iter = sequence_transaction_map.find(next);
	}
	while(iter == sequence_transaction_map.end());
      }
    }
    else if ((size_t)commandline_journal_transaction < max_sequence)
      next = min_sequence;
    if (prev != -1 && next != -1)
      std::cout << "Prev / Next sequences numbers: " << prev << ' ' << next << '\n';
    else if (prev != -1)
      std::cout << "Prev sequence number: " << prev << '\n';
    else if (next != -1)
      std::cout << "Next sequence number: " << next << '\n';
  }
  else
  {
    sequence_transaction_map_type::iterator store = iter;
    ++iter;
    if (iter != sequence_transaction_map.end())
      next = iter->second.sequence();
    iter = store;
    if (iter != sequence_transaction_map.begin())
    {
      --iter;
      prev = iter->second.sequence();
      iter = store;
    }
    Transaction& transaction(iter->second);
    if (prev != -1 && next != -1)
      std::cout << "Prev / Current / Next sequences numbers: " << prev << ' ' << transaction.sequence() << ' ' << next << '\n';
    else if (prev != -1)
      std::cout << "Prev / Current sequences numbers: " << prev << ' ' << transaction.sequence() << '\n';
    else if (next != -1)
      std::cout << "Current / Next sequences numbers: " << transaction.sequence() << ' ' << next << '\n';
    else
      std::cout << "Sequence number: " << transaction.sequence() << '\n';
    if (!transaction.committed())
      std::cout << "Transaction was NOT COMMITTED!\n";
    transaction.print_descriptors();
  }
}

void get_inodes_from_journal(int inode, std::vector<std::pair<int, Inode> >& inodes)
{
  uint32_t block = inode_to_block(super_block, inode);
  int offset = (inode - block_to_inode(block)) * inode_size_;
  block_to_descriptors_map_type::iterator descriptors_iter = block_to_descriptors_map.find(block);
  if (descriptors_iter != block_to_descriptors_map.end())
  {
    std::vector<Descriptor*>& descriptors(descriptors_iter->second);
    for (std::vector<Descriptor*>::reverse_iterator descriptor_iter = descriptors.rbegin(); descriptor_iter != descriptors.rend(); ++descriptor_iter)
    {
      Descriptor& descriptor(**descriptor_iter);
      if (descriptor.descriptor_type() != dt_tag)
        continue;
      DescriptorTag& tag(static_cast<DescriptorTag&>(descriptor));
      ASSERT(tag.block() == block);
      static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
      get_block(descriptor.block(), block_buf);
      Inode const* inode_ptr = reinterpret_cast<Inode const*>(block_buf + offset);
      inodes.push_back(std::pair<int, Inode>(descriptor.sequence(), *inode_ptr));
    }
  }
}
