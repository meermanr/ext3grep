// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file histogram.h Declarations for histogram.cc
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

#ifndef HISTOGRAM_H
#define HISTOGRAM_H

// The type of commandline_histogram.
enum hist_type {
  hist_none = 0,        // No histogram.
  hist_atime,           // Request histogram of access times.
  hist_ctime,           // Request histogram of file modification times.
  hist_mtime,           // Request histogram of inode modification times.
  hist_dtime,           // Request histogram of deletion times.
  hist_group            // Request histogram of deletions per group.
};

#endif // HISTOGRAM_H
