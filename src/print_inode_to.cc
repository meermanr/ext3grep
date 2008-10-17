// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file print_inode_to.cc Definition of the function print_inode_to.
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
#include "ext3.h"
#endif

#include "FileMode.h"
#include "globals.h"
#include "print_symlink.h"

void print_inode_to(std::ostream& os, Inode const& inode)
{
  os << "Generation Id: " << inode.generation() << '\n';
  union {
    uid_t uid;
    uint16_t uid_word[2];
  };
  uid_word[0] = inode.uid_low();
  uid_word[1] = inode.uid_high();
  union {
    uid_t gid;
    uint16_t gid_word[2];
  };
  gid_word[0] = inode.gid_low();
  gid_word[1] = inode.gid_high();
  os << "uid / gid: " << uid << " / " << gid << '\n';
  os << "mode: " << FileMode(inode.mode()) << '\n';
  os << "size: " << inode.size() << '\n';
  os << "num of links: " << inode.links_count() << '\n';
  os << "sectors: " << inode.blocks();
  // A sector is 512 bytes. Therefore, we are using 'inode.i_blocks * 512 / block_size_' blocks.
  // 'inode.i_size / block_size_' blocks are used for the content, thus
  // '(inode.i_blocks * 512 - inode.i_size) / block_size_' blocks should
  // be used for indirect blocks.
  if ((inode.mode() & 0xf000) != 0xa000 || inode.blocks() != 0)		// Not an inline symlink?
  {
    unsigned int number_of_indirect_blocks = (inode.blocks() * 512 - inode.size()) / block_size_;
    os << " (--> " << number_of_indirect_blocks << " indirect " << ((number_of_indirect_blocks == 1) ? "block" : "blocks") << ").\n";
  }
  time_t atime = inode.atime();
  os << "\nInode Times:\n";
  os << "Accessed:       ";
  if (atime > 0)
    os << atime << " = " << std::ctime(&atime);
  else
    os << "0\n";
  time_t ctime = inode.ctime();
  os << "File Modified:  ";
  if (ctime > 0)
    os << ctime << " = " << std::ctime(&ctime);
  else
    os << "0\n";
  time_t mtime = inode.mtime();
  os << "Inode Modified: ";
  if (mtime > 0)
    os << mtime << " = " << std::ctime(&mtime);
  else
    os << "0\n";
  os << "Deletion time:  ";
  if (inode.has_valid_dtime())
  {
    time_t dtime = inode.dtime();
    os << dtime << " = " << std::ctime(&dtime);
  }
  else if (inode.is_orphan())
    os << "ORPHAN (next inode: " << inode.dtime() << ")\n";
  else
    os << "0\n";
  //os << "File flags: " << inode.flags() << '\n';
  if ((inode.mode() & 0xf000) != 0xa000 || inode.blocks() != 0)		// Not an inline symlink?
  {
    os << "\nDirect Blocks:";
    long sb = (inode.size() + block_size_ - 1) / block_size_;	// Size in blocks.
    for (int n = 0; n < EXT3_NDIR_BLOCKS; ++n)
    {
      os << ' ' << inode.block()[n];
      --sb;
      if (sb <= 0)
	break;
    }
    os << '\n';
    if (sb > 0)
      os << "Indirect Block: " << inode.block()[EXT3_IND_BLOCK] << '\n';
    sb -= block_size_ >> 2;
    if (sb > 0)
      os << "Double Indirect Block: " << inode.block()[EXT3_DIND_BLOCK] << '\n';
    sb -= (block_size_ >> 2) * (block_size_ >> 2);
    if (sb > 0)
      os << "Tripple Indirect Block: " << inode.block()[EXT3_TIND_BLOCK] << '\n';
  }
  else
  {
    os << "Symbolic link target name: ";
    print_symlink(os, inode);
    os << '\n';
  }
  //os << "File ACL: " << inode.file_acl() << '\n';
  //os << "Directory ACL: " << inode.dir_acl() << '\n';
  //os << "Fragment address: " << inode.faddr() << '\n';
  //os << "Fragment number: " << (int)inode.osd2.linux2.l_i_frag << '\n';
  //os << "Fragment size: " << (int)inode.osd2.linux2.l_i_fsize << '\n';
}
