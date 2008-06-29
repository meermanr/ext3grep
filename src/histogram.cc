// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file histogram.cc Implementation of --histogram.
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
#include <sys/types.h>
#include <iomanip>
#include "debug.h"
#endif

#include "commandline.h"

//-----------------------------------------------------------------------------
//
// Histogram
//

int const histsize = 100;
static size_t S_min;
static size_t S_max;
static size_t S_bs;
static int histo[histsize];
static int S_maxcount;

void hist_init(size_t min, size_t max)
{
  S_min = min;
  S_max = max;

  ASSERT(max > min);

  S_bs = 1;
  while ((max - 1 - min) / S_bs > histsize - 1)
    ++S_bs;
  std::memset(histo, 0, sizeof(histo));
  S_maxcount = 0;
}

void hist_add(size_t val)
{
  ASSERT(val >= S_min && val < S_max);
  histo[(val - S_min) / S_bs] += 1;
  S_maxcount = std::max(S_maxcount, histo[(val - S_min) / S_bs]);
}

void hist_print(void)
{
  if (S_maxcount == 0)
  {
    std::cout << "No counts\n";
    return;
  }
  static char const line[] = "===============================================================================================================================================================END!";
  int i = 0;
  size_t total_count = 0;
  for (size_t val = S_min;; val += S_bs, ++i)
  {
    if (commandline_histogram == hist_atime ||
        commandline_histogram == hist_ctime ||
	commandline_histogram == hist_mtime ||
	commandline_histogram == hist_dtime)
    {
      time_t time_val = val;
      std::string time_str(ctime(&time_val));
      std::cout << time_str.substr(0, time_str.length() - 1) << "  ";
    }
    std::cout << std::setfill(' ') << std::setw(8) << val << ' ';
    if (val >= S_max)
      break;
    std::cout << std::setfill(' ') << std::setw(8) << histo[i] << ' ';
    std::streamsize tower = static_cast<std::streamsize>(histo[i] * 100.0 / S_maxcount);
    std::cout.write(line, tower);
    std::cout << '\n';
    total_count += histo[i];
  }
  std::cout << "\nTotals:\n";
  std::cout << std::setw(8) << S_min << " - " << std::setfill(' ') << std::setw(8) << (S_max - 1) << ' ';
  std::cout << std::setfill(' ') << std::setw(8) << total_count << '\n';
}
