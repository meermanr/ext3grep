// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file accept.h Declaration class Accept.
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

#ifndef ACCEPT_H
#define ACCEPT_H

#ifndef USE_PCH
#include <set>
#include <bitset>
#endif

struct Accept {
  static std::bitset<256> S_illegal;	// Bit mask reflecting illegal characters.
  static std::bitset<256> S_unlikely;	// Bit mask reflecting unlikely characters.

private:
  std::string M_filename;	// The filename.
  std::bitset<256> M_mask;	// Bit mask reflecting unlikely characters in filename.
  bool M_accept;		// True if this filename should be accepted.

public:
  Accept(std::string const& filename, bool accept) : M_filename(filename), M_accept(accept)
  {
    M_mask.reset();
    for (std::string::const_iterator iter = M_filename.begin(); iter != M_filename.end(); ++iter)
    {
      __u8 c = *iter;
      ASSERT(!S_illegal[c]);
      if (S_unlikely[c])
        M_mask.set(c);
    }
  }

  std::string const& filename(void) const { return M_filename; }
  bool accepted(void) const { return M_accept; }

  friend bool operator<(Accept const& a1, Accept const& a2) { return a1.M_filename < a2.M_filename; }
};

extern std::set<Accept> accepted_filenames;

#endif // ACCEPT_H
