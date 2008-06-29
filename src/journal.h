// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file journal.h Journal access related declarations.
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

#ifndef JOURNAL_H
#define JOURNAL_H

#ifndef USE_PCH
#include <map>
#include <stdint.h>
#include <vector>
#endif

enum descriptor_type_nt {
  dt_unknown,
  dt_tag,
  dt_revoke,
  dt_commit
};

class Descriptor {
  private:
    uint32_t const M_block;			// Block number in the journal.
    uint32_t const M_sequence;
  public:
    Descriptor(uint32_t block, uint32_t sequence) : M_block(block), M_sequence(sequence) { }
    uint32_t block(void) const { return M_block; }
    uint32_t sequence(void) const { return M_sequence; }
    virtual descriptor_type_nt descriptor_type(void) const = 0;
    virtual void print_blocks(void) const = 0;
    virtual void add_block_descriptors(void) = 0;
  protected:
    virtual ~Descriptor() { }
};

typedef std::map<int, Descriptor*> block_in_journal_to_descriptors_map_type;
extern block_in_journal_to_descriptors_map_type block_in_journal_to_descriptors_map;
typedef std::map<int, int> block_to_dir_inode_map_type;
extern block_to_dir_inode_map_type block_to_dir_inode_map;
typedef std::map<int, std::vector<Descriptor*> > block_to_descriptors_map_type;
extern block_to_descriptors_map_type block_to_descriptors_map;
extern uint32_t max_sequence;

uint32_t find_largest_journal_sequence_number(int block);
void get_inodes_from_journal(int inode, std::vector<std::pair<int, Inode> >& inodes);

#endif // JOURNAL_H
