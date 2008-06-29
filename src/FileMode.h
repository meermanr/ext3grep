// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file FileMode.h Declaration of class FileMode.
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

#ifndef FILEMODE_H
#define FILEMODE_H

#ifndef USE_PCH
#include <iostream>		// Needed for std::ostream and several operator<<'s.
#endif

#include "endian_conversion.h"	// Needed for __le16

class FileMode {
  private:
    __le16 M_mode;
  public:
    FileMode(__le16 mode) : M_mode(mode) { } 
    friend std::ostream& operator<<(std::ostream& os, FileMode const& file_mode)
	{
	  __le16 mode(file_mode.M_mode);
	  switch ((mode & 0xf000))
	  {
	    case 0x1000:
	      os << 'p'; // "FIFO";
	      break;
	    case 0x2000:
	      os << 'c'; // "Character device";
	      break;
	    case 0x4000:
	      os << 'd'; // "Directory";
	      break;
	    case 0x6000:
	      os << 'b'; // "Block device";
	      break;
	    case 0x8000:
	      os << 'r'; // "Regular file";
	      break;
	    case 0xA000:
	      os << 'l'; // "Symbolic link";
	      break;
	    case 0xC000:
	      os << 's'; // "UNIX socket";
	      break;
	  }
	  static char const* s[4] = {
	    "rwxrwxrwx",
	    "rwsrwsrwt",
	    "---------",
	    "--S--S--T"
	  };
	  int i = 0;
	  __le16 smask = 04000;
	  for (__le16 mask = 0400; mask; mask >>= 1, ++i)
	  {
	    int k = (mode & (smask >> (i / 3))) ? 1 : 0;
	    if ((mode & mask))
	      os << s[k][i];
	    else
	      os << s[k + 2][i];
	  }
	  return os;
	}
};

#endif // FILEMODE_H
