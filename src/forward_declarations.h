// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file forward_declarations.h Various forward declarations.
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

#ifndef FORWARD_DECLARATIONS_H
#define FORWARD_DECLARATIONS_H

#ifndef USE_PCH
#include <iosfwd>		// Needed for std::ostream
#include <string>		// Needed for std::string
#endif

#include "is_blockdetection.h"	// Needed for is_directory_type

// Forward declarations.
struct Parent;
class DirectoryBlockStats;
void decode_commandline_options(int& argc, char**& argv);
void dump_hex_to(std::ostream& os, unsigned char const* buf, size_t size, size_t addr_offset = 0);
void print_block_to(std::ostream& os, unsigned char* block);
void iterate_over_directory(unsigned char* block, int blocknr,
    bool (*action)(ext3_dir_entry_2 const&, Inode const&, bool, bool, bool, bool, bool, bool, Parent*, void*), Parent* parent, void* data);
void iterate_over_directory_action(int blocknr, void* data);
void iterate_over_existing_directory_action(int blocknr, int, void* data);
void iterate_over_journal(
    bool (*action_tag)(uint32_t block, uint32_t sequence, journal_block_tag_t*, void* data),
    bool (*action_revoke)(uint32_t block, uint32_t sequence, journal_revoke_header_t*, void* data),
    bool (*action_commit)(uint32_t block, uint32_t sequence, void* data), void* data);
void print_directory(unsigned char* block, int blocknr);
void print_restrictions(void);
bool is_directory(Inode const& inode);
is_directory_type is_directory(unsigned char* block, int blocknr, DirectoryBlockStats& stats,
    bool start_block = true, bool certainly_linked = true, int offset = 0);
bool is_journal(int blocknr);
bool is_in_journal(int blocknr);
int is_inode_block(int blocknr);
bool is_indirect_block_in_journal(int blocknr);
bool is_symlink(Inode const& inode);
void hist_init(size_t min, size_t max);
void hist_add(size_t val);
void hist_print(void);
int dir_inode_to_block(uint32_t inode);
int journal_block_to_real_block(int blocknr);
void init_journal(void);
int journal_block_contains_inodes(int blocknr);
void handle_commandline_journal_transaction(void);
void print_block_descriptors(uint32_t block);
void print_directory_inode(int inode);
void dump_names(void);
void init_files(void);
void show_journal_inodes(int inode);
void restore_file(std::string const& outfile);
void show_hardlinks(void);
void init_accept(void);
int last_undeleted_directory_inode_refering_to_block(uint32_t inode_number, int directory_block_number);

#endif // FORWARD_DECLARATIONS_H
