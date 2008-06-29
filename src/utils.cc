// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file utils.cc Various utility functions.
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
#include <sys/stat.h>
#include "debug.h"
#endif

#include "globals.h"

char const* dir_entry_file_type(int file_type, bool ls)
{
  ASSERT(feature_incompat_filetype);
  switch ((file_type & 7))
  {
    case EXT3_FT_UNKNOWN:
      return (ls ? "?" : "EXT3_FT_UNKNOWN");
    case EXT3_FT_REG_FILE:
      return (ls ? "r" : "EXT3_FT_REG_FILE");
    case EXT3_FT_DIR:
      return (ls ? "d" : "EXT3_FT_DIR");
    case EXT3_FT_CHRDEV:
      return (ls ? "c" : "EXT3_FT_CHRDEV");
    case EXT3_FT_BLKDEV:
      return (ls ? "b" : "EXT3_FT_BLKDEV");
    case EXT3_FT_FIFO:
      return (ls ? "p" : "EXT3_FT_FIFO");
    case EXT3_FT_SOCK:
      return (ls ? "s" : "EXT3_FT_SOCK");
    case EXT3_FT_SYMLINK:
      return (ls ? "l" : "EXT3_FT_SYMLINK");
  }
  exit(EXIT_FAILURE); // Suppress compiler warning.
}

mode_t inode_mode_to_mkdir_mode(uint16_t mode)
{
  mode_t result = 0;
  if ((mode & 04000))
    result |= S_ISUID;
  if ((mode & 02000))
    result |= S_ISGID;
  if ((mode & 01000))
    result |= S_ISVTX;
  if ((mode & 0400))
    result |= S_IRUSR;
  if ((mode & 0200))
    result |= S_IWUSR;
  if ((mode & 0100))
    result |= S_IXUSR;
  if ((mode & 040))
    result |= S_IRGRP;
  if ((mode & 020))
    result |= S_IWGRP;
  if ((mode & 010))
    result |= S_IXGRP;
  if ((mode & 04))
    result |= S_IROTH;
  if ((mode & 02))
    result |= S_IWOTH;
  if ((mode & 01))
    result |= S_IXOTH;
  return result;
}

char const* mode_str(int16_t i_mode)
{
  switch ((i_mode & 0xf000))
  {
    case 0x1000:
      return "FIFO";
    case 0x2000:
      return "Character device";
    case 0x4000:
      return "Directory";
    case 0x6000:
      return "Block device";
    case 0x8000:
      return "Regular file";
    case 0xA000:
      return "Symbolic link";
    case 0xC000:
      return "UNIX socket";
  }
  // To prevent a compiler warning.
  return "*UNKNOWN*";
}
