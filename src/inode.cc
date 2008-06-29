// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file inode.cc Inode related code.
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
#include "debug.h"
#include <sys/mman.h>
#include <cerrno>
#include "ext3.h"
#endif

#include "load_meta_data.h"
#include "globals.h"
#include "conversion.h"
#include "inode.h"

#if USE_MMAP
void inode_unmap(int group)
{
  if (all_inodes[group])
  {
    DoutEntering(dc::notice, "inode_unmap(" << group << ")");

    ASSERT(refs_to_mmap[group] == 0 && nr_mmaps > 0);
    --nr_mmaps;
    munmap(all_mmaps[group], inodes_per_group_ * inode_size_ + ((char*)all_inodes[group] - (char*)all_mmaps[group]));
    all_inodes[group] = NULL;
  }
}

// Maximum number of simultaneously mmapped inode tables.
// One inode table is roughly 4 MB: 32768 inodes times 128 bytes.
// If we want to maximally use 1 GB of address space for those,
// we should map at most 1024/4 = 256 inode tables.
// On 64-bit machines, this can be infinitely higher.
int const max_mmaps = (sizeof(void*) == 4) ? 256 : std::numeric_limits<int>::max();

void inode_mmap(int group)
{
  if (all_inodes[group])
    return;

  DoutEntering(dc::notice, "inode_mmap(" << group << ")");

  if (nr_mmaps >= max_mmaps)
  {
    // FIXME: This can be done more intelligent I guess.
    // For now, just munmap all inode tables that are not in use.
    for (int grp = 0; grp < groups_; ++grp)
    {
      if (!all_inodes[grp])		// Not mapped at all?
        continue;
      if (refs_to_mmap[grp] > 0)	// Referenced?
        continue;
      inode_unmap(grp);
      if (nr_mmaps == 0)
        break;
    }
  }

  int block_number = group_descriptor_table[group].bg_inode_table;
  int const blocks_per_page = page_size_ / block_size_;
  off_t page = block_number / blocks_per_page;
  off_t page_aligned_offset = page * page_size_;
  off_t offset = block_to_offset(block_number);

  all_mmaps[group] = mmap(NULL, inodes_per_group_ * inode_size_ + (offset - page_aligned_offset),
      PROT_READ, MAP_PRIVATE | MAP_NORESERVE, device_fd, page_aligned_offset);
  if (all_mmaps[group] == MAP_FAILED)
  {
    int error = errno;
    all_mmaps[group] = NULL;
    std::cerr << progname << ": mmap: " << strerror(error) << std::endl;
    // Fail.
    ASSERT(all_mmaps[group] != MAP_FAILED);
  }

  all_inodes[group] = reinterpret_cast<Inode const*>((char*)all_mmaps[group] + (offset - page_aligned_offset));
  ASSERT(refs_to_mmap[group] == 0);
  ++nr_mmaps;
}
#endif

Inode InodePointer::S_fake_inode;	// This will be filled with zeroes.

