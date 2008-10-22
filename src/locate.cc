// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file location.cc Implementation of heuristic functions parent_directory and path_exists that use an (old) locate database output file.
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
#include <regex.h>
#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <vector>
#include <map>
#include <cassert>
#endif

#include "locate.h"

class LocatePath {
  private:
    std::string M_path;
    mutable bool M_is_certainly_directory;

  public:
    LocatePath(void) : M_is_certainly_directory(false) { }
    LocatePath(std::string const& path, bool is_certainly_directory = false) : M_path(path), M_is_certainly_directory(is_certainly_directory) { }

    std::string const& path(void) const { return M_path; }
    bool is_certainly_directory(void) const { return M_is_certainly_directory; }

    void set_certainly_directory(void) const { M_is_certainly_directory = true; }
};

struct LocatePathPred {
  bool operator()(LocatePath const& lp1, LocatePath const& lp2) const { return lp1.path() < lp2.path(); }
};

typedef std::set<LocatePath, LocatePathPred> locatepaths_type;
typedef std::vector<locatepaths_type::iterator> filename_to_locatepath_map_info_type;
typedef std::map<std::string, filename_to_locatepath_map_info_type> filename_to_locatepath_map_type;

locatepaths_type locatepaths;
filename_to_locatepath_map_type filename_to_locatepath_map;

static bool initialized = false;

void load_locate_data(void)
{
  std::ifstream infile;
  infile.open("locate_output");
  if (!infile)
    std::cerr << "WARNING: Failed to open file 'locate_output'. See locate.cc\n";
  std::string line;
  while (std::getline(infile, line))
  {
    std::pair<locatepaths_type::iterator, bool> res = locatepaths.insert(LocatePath(line));
    std::string::size_type pos = line.find_last_of('/');
    if (pos != std::string::npos)
    {
      std::string dirname = line.substr(0, pos); 
      // Use insert, in case the parent directory wasn't seen first.
      // Since it's a set, it will only be inserted if it isn't already there.
      locatepaths_type::iterator locatepath_iter = locatepaths.insert(LocatePath(dirname)).first;
      locatepath_iter->set_certainly_directory();
      std::string filename = line.substr(pos + 1);
      filename_to_locatepath_map_type::iterator iter = filename_to_locatepath_map.find(filename);
      if (iter == filename_to_locatepath_map.end())
        filename_to_locatepath_map[filename] = filename_to_locatepath_map_type::mapped_type(1, locatepath_iter);
      else
        iter->second.push_back(locatepath_iter);
    }
  }
  infile.close();
  initialized = true;
}

#if 0
int const test_blocknr = 1418523;
#endif

std::string parent_directory(int
#if 0
    blocknr
#endif
    , std::set<std::string> const& filenames)
{
  if (!initialized)
    load_locate_data();
//#ifdef CARLO_WOODS_CASE	This should be automatic now.
//  if (blocknr == 1016319 || blocknr == 1640008 || blocknr == 1640009)
//    return "lost+found";	// Google Earth junk.
//#endif
  typedef std::map<std::string, std::pair<int, bool> > possible_directories_type;
  possible_directories_type possible_directories;
  for (std::set<std::string>::const_iterator filename_iter = filenames.begin(); filename_iter != filenames.end(); ++filename_iter)
  {
    filename_to_locatepath_map_type::iterator directories_iter = filename_to_locatepath_map.find(*filename_iter);
    if (directories_iter != filename_to_locatepath_map.end())
    {
      int count = 0;
      possible_directories_type::iterator possible_directory_iter;
      for (filename_to_locatepath_map_type::mapped_type::iterator directory_iter = directories_iter->second.begin();
          directory_iter != directories_iter->second.end(); ++directory_iter)
      {
        std::string const& path = (*directory_iter)->path();
        std::string fullpath = path + '/' + *filename_iter;
        locatepaths_type::iterator iter = locatepaths.find(LocatePath(fullpath));
        assert(iter != locatepaths.end());
        if (iter->is_certainly_directory())
          continue;
	++count;
        possible_directory_iter = possible_directories.find(path);
	if (possible_directory_iter == possible_directories.end())
	  possible_directory_iter = possible_directories.insert(possible_directories_type::value_type(path, std::pair<int, bool>(1, false))).first;
	else
	  ++(possible_directories[path].first);
      }
      if (count == 1)
        possible_directory_iter->second.second = true;
    }
  }
  int maxhits = 0;
  int total = filenames.size();
  std::string result;
  for (possible_directories_type::iterator possible_directory_iter = possible_directories.begin();
      possible_directory_iter != possible_directories.end(); ++possible_directory_iter)
  {
    int hits = possible_directory_iter->second.first + (possible_directory_iter->second.second ? 1 : 0);
    double percentage = 100.0 * hits / total;
    double threshold = possible_directory_iter->second.second ? 10 : 70;
#if 0
    if (blocknr == test_blocknr)
      std::cout << hits << " (" << percentage << "% of the files) match " << possible_directory_iter->first << '\n';
#endif
    if (hits >= maxhits && percentage >= threshold)
    {
      if (hits > maxhits || possible_directory_iter->first.size() < result.size())
      {
	maxhits = hits;
	result = possible_directory_iter->first;
      }
    }
  }
  if (maxhits == 0)
  {
    // EDIT THIS TO SUITE YOUR NEEDS!
    // The format is: "regular expression of files", "parent directory"
    // You can set test_blocknr and uncomment the #if 0'd code below to debug your regular expressions.
    static struct { char const* regexp; char const* path; } table[] = {
//#ifdef CARLO_WOODS_CASE	This should be automatic now.
//      { "^([0-9]{10}-[0-9]{3,5}-[0-9]+|11c0a8020[0-9]{28})\\.ms$", "carlo/k3b/temp" },
//      { "^1[12][0-9]{11}_(AutoSpeedSearchHistory|SpeedMan|seltrace|thread|alerts|debug)_[12]\\.log$", "carlo/.azureus/logs/save" },
//      { "^opr0[0-9][0-9A-Z]{3}\\.(js|ico|htm|gif|png|html|jpeg|xml|flv|css|swf|jpg)$", "lost+found" },
//      { "\\.(md5|eps|tex)$", "lost+found" }
//#endif
    };
    regex_t preg;
    int re_end = sizeof(table) / sizeof(table[0]);
    for (int re = 0; re < re_end; ++re)
    {
      int hits = 0;
      regcomp(&preg, table[re].regexp, REG_EXTENDED|REG_NOSUB);
      for (std::set<std::string>::const_iterator filename_iter = filenames.begin(); filename_iter != filenames.end(); ++filename_iter)
      {
#if 0
	if (blocknr == test_blocknr)
	  std::cout << "Matching \"" << filename_iter->c_str() << "\" against \"" << table[re].regexp << "\": ";
#endif
        if (regexec(&preg, filename_iter->c_str(), 0, NULL, 0) == 0)
	{
#if 0
	  if (blocknr == test_blocknr)
	    std::cout << "match!\n";
#endif
	  ++hits;
	}
#if 0
	else if (blocknr == test_blocknr)
	  std::cout << " no match.\n";
#endif
      }
      regfree(&preg);
#if 0
      if (blocknr == test_blocknr)
        std::cout << (100.0 * hits / total) << "% matched regular expression #" << re << ".\n";
#endif
      if (100.0 * hits / total > 90)
        return table[re].path;
    }
  }
  return result;
}

bool path_exists(std::string const& path)
{
  if (!initialized)
    load_locate_data();
  locatepaths_type::iterator iter = locatepaths.find(LocatePath(path));
  return iter != locatepaths.end();
}

