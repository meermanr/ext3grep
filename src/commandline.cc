// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file commandline.cc Implementation of commandline options.
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
#include <unistd.h>
#include <getopt.h>
#endif

#include "commandline.h"
#include "globals.h"
#include "restore.h"
#include "accept.h"

// Commandline options.
bool commandline_superblock = false;
int commandline_group = -1;
int commandline_inode_to_block = -1;
int commandline_inode = -1;
int commandline_block = -1;
int commandline_journal_block = -1;
int commandline_journal_transaction = -1;
bool commandline_print = false;
bool commandline_ls = false;
bool commandline_journal = false;
bool commandline_dump_names = false;
int commandline_depth = 0;
bool commandline_deleted = false;
bool commandline_directory = false;
time_t commandline_before = 0;
time_t commandline_after = 0;
bool commandline_allocated = false;
bool commandline_unallocated = false;
bool commandline_reallocated = false;
bool commandline_action = false;
bool commandline_search_zeroed_inodes = false;
bool commandline_zeroed_inodes = false;
bool commandline_show_path_inodes = false;
std::string commandline_search;
std::string commandline_search_start;
int commandline_search_inode = -1;
hist_type commandline_histogram = hist_none;
std::string commandline_inode_dirblock_table;
int commandline_show_journal_inodes = -1;
std::vector<std::string> commandline_restore_file;
std::string commandline_restore_inode;
bool commandline_restore_all = false;
bool commandline_show_hardlinks = false;
bool commandline_debug = false;
bool commandline_debug_malloc = false;
bool commandline_custom = false;
bool commandline_accept_all = false;

//-----------------------------------------------------------------------------
//
// Commandline
//

static void print_usage(std::ostream& os)
{
  os << "Usage: " << progname << " [options] [--] device-file\n";
//       012345678901234567890123456789012345678901234567890123456789012345678901234567890
  os << "Options:\n";
  os << "  --version, -[vV]       Print version and exit successfully.\n";
  os << "  --help,                Print this help and exit successfully.\n";
  os << "  --superblock           Print contents of superblock in addition to the rest.\n";
  os << "                         If no action is specified then this option is implied.\n";
  os << "  --print                Print content of block or inode, if any.\n";
  os << "  --ls                   Print directories with only one line per entry.\n";
  os << "                         This option is often needed to turn on filtering.\n";
  os << "  --accept filen         Accept 'filen' as a legal filename. Can be used multi-\n";
  os << "                         ple times. If you change any --accept you must remove\n";
  os << "                         BOTH stage* files!\n";
  os << "  --accept-all           Simply accept everything as filename.\n";
  os << "  --journal              Show content of journal.\n";
  os << "  --show-path-inodes     Show the inode of each directory component in paths.\n";
#ifdef CWDEBUG
  os << "  --debug                Turn on printing of debug output.\n";
  os << "  --debug-malloc         Turn on debugging of memory allocations.\n";
#endif
//       012345678901234567890123456789012345678901234567890123456789012345678901234567890
  os << "Filters:\n";
  os << "  --group grp            Only process group 'grp'.\n";
  os << "  --directory            Only process directory inodes.\n";
  os << "  --after dtime          Only entries deleted on or after 'dtime'.\n";
  os << "  --before dtime         Only entries deleted before 'dtime'.\n";
  os << "  --deleted              Only show/process deleted entries.\n";
  os << "  --allocated            Only show/process allocated inodes/blocks.\n";
  os << "  --unallocated          Only show/process unallocated inodes/blocks.\n";
  os << "  --reallocated          Do not suppress entries with reallocated inodes.\n";
  os << "                         Inodes are considered 'reallocated' if the entry\n";
  os << "                         is deleted but the inode is allocated, but also when\n";
  os << "                         the file type in the dir entry and the inode are\n";
  os << "                         different.\n";
  os << "  --zeroed-inodes        Do not suppress entries with zeroed inodes. Linked\n";
  os << "                         entries are always shown, regardless of this option.\n";
  os << "  --depth depth          Process directories recursively up till a depth\n";
  os << "                         of 'depth'.\n";
//       012345678901234567890123456789012345678901234567890123456789012345678901234567890
  os << "Actions:\n";
  os << "  --inode-to-block ino   Print the block that contains inode 'ino'.\n";
  os << "  --inode ino            Show info on inode 'ino'.\n";
  os << "                         If --ls is used and the inode is a directory, then\n";
  os << "                         the filters apply to the entries of the directory.\n";
  os << "                         If you do not use --ls then --print is implied.\n";
  os << "  --block blk            Show info on block 'blk'.\n";
  os << "                         If --ls is used and the block is the first block\n";
  os << "                         of a directory, then the filters apply to entries\n";
  os << "                         of the directory.\n";
  os << "                         If you do not use --ls then --print is implied.\n";
//       012345678901234567890123456789012345678901234567890123456789012345678901234567890
  os << "  --histogram=[atime|ctime|mtime|dtime|group]\n";
  os << "                         Generate a histogram based on the given specs.\n";
  os << "                         Using atime, ctime or mtime will change the\n";
  os << "                         meaning of --after and --before to those times.\n";
  os << "  --journal-block jblk   Show info on journal block 'jblk'.\n";
  os << "  --journal-transaction seq\n";
  os << "                         Show info on transaction with sequence number 'seq'.\n";
  os << "  --dump-names           Write the path of files to stdout.\n";
  os << "                         This implies --ls but suppresses it's output.\n";
  os << "  --search-start str     Find blocks that start with the fixed string 'str'.\n";
  os << "  --search str           Find blocks that contain the fixed string 'str'.\n";
  os << "  --search-inode blk     Find inodes that refer to block 'blk'.\n";
  os << "  --search-zeroed-inodes Return allocated inode table entries that are zeroed.\n";
//       012345678901234567890123456789012345678901234567890123456789012345678901234567890
  os << "  --inode-dirblock-table dir\n";
  os << "                         Print a table for directory path 'dir' of directory\n";
  os << "                         block numbers found and the inodes used for each file.\n";
  os << "  --show-journal-inodes ino\n";
  os << "                         Show copies of inode 'ino' still in the journal.\n";
  os << "  --restore-inode ino[,ino,...]\n";
  os << "                         Restore the file(s) with known inode number 'ino'.\n";
  os << "                         The restored files are created in ./" << outputdir << "\n";
  os << "                         with their inode number as extension (ie, inode.12345).\n";
  os << "  --restore-file 'path' [--restore-file 'path' ...]\n"; 
  os << "                         Will restore file 'path'. 'path' is relative to the\n";
  os << "                         root of the partition and does not start with a '/' (it\n";
  os << "                         must be one of the paths returned by --dump-names).\n";
  os << "                         The restored directory, file or symbolic link is\n";
  os << "                         created in the current directory as '"<< outputdir << "path'.\n";
  os << "  --restore-all          As --restore-file but attempts to restore everything.\n";
  os << "                         The use of --after is highly recommended because the\n";
  os << "                         attempt to restore very old files will only result in\n";
  os << "                         them being hard linked to a more recently deleted file\n";
  os << "                         and as such polute the output.\n";
  os << "  --show-hardlinks       Show all inodes that are shared by two or more files.\n";
}

static void print_version(void)
{
  std::cout << "ext3grep v" VERSION ", Copyright (C) 2008 Carlo Wood.\n";
  std::cout << "ext3grep comes with ABSOLUTELY NO WARRANTY;\n";
  std::cout << "This program is free software; your freedom to use, change\n";
  std::cout << "and distribute this program is protected by the GPL.\n";
}

extern char *optarg;
extern int optind, opterr, optopt;

enum opts {
  opt_version,
  opt_superblock,
  opt_group,
  opt_inode,
  opt_block,
  opt_print,
  opt_ls,
  opt_after,
  opt_before,
  opt_deleted,
  opt_allocated,
  opt_unallocated,
  opt_histogram,
  opt_directory,
  opt_accept,
  opt_accept_all,
  opt_dump_names,
  opt_reallocated,
  opt_depth,
  opt_journal,
  opt_journal_block,
  opt_journal_transaction,
  opt_search,
  opt_search_start,
  opt_search_inode,
  opt_search_zeroed_inodes,
  opt_inode_to_block,
  opt_zeroed_inodes,
  opt_show_path_inodes,
  opt_inode_dirblock_table,
  opt_show_journal_inodes,
  opt_restore_file,
  opt_restore_inode,
  opt_restore_all,
  opt_show_hardlinks,
  opt_help,
  opt_debug,
  opt_debug_malloc,
  opt_custom
};

void decode_commandline_options(int& argc, char**& argv)
{
  int short_option;
  static int long_option;
  struct option longopts[] = {
    {"help", 0, &long_option, opt_help},
    {"version", 0, &long_option, opt_version},
    {"superblock", 0, &long_option, opt_superblock},
    {"group", 1, &long_option, opt_group},
    {"inode", 1, &long_option, opt_inode},
    {"block", 1, &long_option, opt_block},
    {"print", 0, &long_option, opt_print},
    {"ls", 0, &long_option, opt_ls},
    {"after", 1, &long_option, opt_after},
    {"before", 1, &long_option, opt_before},
    {"deleted", 0, &long_option, opt_deleted},
    {"allocated", 0, &long_option, opt_allocated},
    {"unallocated", 0, &long_option, opt_unallocated},
    {"reallocated", 0, &long_option, opt_reallocated},
    {"histogram", 1, &long_option, opt_histogram},
    {"directory", 0, &long_option, opt_directory},
    {"accept", 1, &long_option, opt_accept},
    {"accept-all", 0, &long_option, opt_accept_all},
    {"dump-names", 0, &long_option, opt_dump_names},
    {"depth", 1, &long_option, opt_depth},
    {"journal", 0, &long_option, opt_journal},
    {"journal-block", 1, &long_option, opt_journal_block},
    {"journal-transaction", 1, &long_option, opt_journal_transaction},
    {"search", 1, &long_option, opt_search},
    {"search-start", 1, &long_option, opt_search_start},
    {"search-inode", 1, &long_option, opt_search_inode},
    {"search-zeroed-inodes", 0, &long_option, opt_search_zeroed_inodes},
    {"inode-to-block", 1, &long_option, opt_inode_to_block},
    {"zeroed-inodes", 0, &long_option, opt_zeroed_inodes},
    {"show-path-inodes", 0, &long_option, opt_show_path_inodes},
    {"inode-dirblock-table", 1, &long_option, opt_inode_dirblock_table},
    {"show-journal-inodes", 1, &long_option, opt_show_journal_inodes},
    {"restore-inode", 1, &long_option, opt_restore_inode},
    {"restore-file", 1, &long_option, opt_restore_file},
    {"restore-all", 0, &long_option, opt_restore_all},
    {"show-hardlinks", 0, &long_option, opt_show_hardlinks},
    {"debug", 0, &long_option, opt_debug},
    {"debug-malloc", 0, &long_option, opt_debug_malloc},
    {"custom", 0, &long_option, opt_custom},
    {NULL, 0, NULL, 0}
  };

  int exclusive1 = 0;
  int exclusive2 = 0;
  std::string hist_arg;
  progname = argv[0];
  while ((short_option = getopt_long(argc, argv, "vV", longopts, NULL)) != -1)
  {
    switch (short_option)
    {
      case 0:
        switch (long_option)
        {
          case opt_help:
            print_usage(std::cout);
            exit(EXIT_SUCCESS);
          case opt_version:
            print_version();
            exit(EXIT_SUCCESS);
	  case opt_debug:
	    commandline_debug = true;
	    break;
	  case opt_debug_malloc:
	    commandline_debug_malloc = true;
	    break;
	  case opt_custom:
	    commandline_custom = true;
	    break;
	  case opt_superblock:
	    commandline_superblock = true;
	    break;
	  case opt_print:
	    commandline_print = true;
	    break;
	  case opt_ls:
	    commandline_ls = true;
	    break;
	  case opt_dump_names:
	    commandline_dump_names = true;
	    ++exclusive1;
	    ++exclusive2;
	    break;
	  case opt_journal:
	    commandline_journal = true;
	    break;
	  case opt_show_path_inodes:
	    commandline_show_path_inodes = true;
	    break;
	  case opt_depth:
	    commandline_depth = atoi(optarg);
	    if (commandline_depth < 0)
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --depth: cannot use negative values." << std::endl;
	      exit(EXIT_FAILURE);
	    }
	    break;
	  case opt_deleted:
	    commandline_deleted = true;
	    break;
	  case opt_directory:
	    commandline_directory = true;
	    break;
	  case opt_allocated:
	    commandline_allocated = true;
	    break;
	  case opt_unallocated:
	    commandline_unallocated = true;
	    break;
	  case opt_reallocated:
	    commandline_reallocated = true;
	    break;
	  case opt_zeroed_inodes:
	    commandline_zeroed_inodes = true;
	    break;
	  case opt_after:
            commandline_after = atoi(optarg);
	    break;
	  case opt_before:
            commandline_before = atoi(optarg);
	    break;
	  case opt_search_zeroed_inodes:
	    commandline_search_zeroed_inodes = true;
	    ++exclusive2;
	    break;
	  case opt_search:
            commandline_search = optarg;
	    ++exclusive2;
	    break;
	  case opt_search_start:
            commandline_search_start = optarg;
	    ++exclusive2;
	    break;
	  case opt_inode_dirblock_table:
	    commandline_inode_dirblock_table = optarg;
	    break;
	  case opt_restore_inode:
	    commandline_restore_inode = optarg;
	    break;
	  case opt_restore_file:
	    commandline_restore_file.push_back(optarg);
	    break;
	  case opt_restore_all:
	    commandline_restore_all = true;
	    break;
	  case opt_show_hardlinks:
	    commandline_show_hardlinks = true;
	    break;
	  case opt_search_inode:
            commandline_search_inode = atoi(optarg);
	    if (commandline_search_inode <= 0)
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --search-inode: block " << commandline_search_inode << " is out of range." << std::endl;
	      exit(EXIT_FAILURE);
	    }
	    ++exclusive2;
	    break;
          case opt_group:
            commandline_group = atoi(optarg);
	    if (commandline_group < 0)
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --group: group " << commandline_group << " is out of range." << std::endl;
	      exit(EXIT_FAILURE);
	    }
	    ++exclusive1;
            break;
          case opt_inode_to_block:
            commandline_inode_to_block = atoi(optarg);
	    if (commandline_inode_to_block < 1)
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --inode-to-block: inode " << commandline_inode_to_block << " is out of range." << std::endl;
	      exit(EXIT_FAILURE);
	    }
            break;
          case opt_inode:
            commandline_inode = atoi(optarg);
	    if (commandline_inode < 1)
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --inode: inode " << commandline_inode << " is out of range." << std::endl;
	      exit(EXIT_FAILURE);
	    }
	    ++exclusive1;
	    ++exclusive2;
            break;
          case opt_block:
            commandline_block = atoi(optarg);
	    if (commandline_block < 0)
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --block: block " << commandline_block << " is out of range." << std::endl;
	      exit(EXIT_FAILURE);
	    }
	    ++exclusive1;
	    ++exclusive2;
            break;
	  case opt_show_journal_inodes:
	    commandline_show_journal_inodes = atoi(optarg);
	    if (commandline_show_journal_inodes < 1)
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --show-journal-inodes: inode " << commandline_show_journal_inodes << " is out of range." << std::endl;
	      exit(EXIT_FAILURE);
	    }
	    ++exclusive1;
	    ++exclusive2;
	    break;
          case opt_journal_block:
            commandline_journal_block = atoi(optarg);
	    if (commandline_journal_block < 0)
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --journal-block: block " << commandline_journal_block << " is out of range." << std::endl;
	      exit(EXIT_FAILURE);
	    }
	    ++exclusive1;
	    ++exclusive2;
            break;
	  case opt_journal_transaction:
            commandline_journal_transaction = atoi(optarg);
	    break;
	  case opt_histogram:
	  {
	    hist_arg = optarg;
	    if (hist_arg == "atime")
	      commandline_histogram = hist_atime;
	    else if (hist_arg == "ctime")
	      commandline_histogram = hist_ctime;
	    else if (hist_arg == "mtime")
	      commandline_histogram = hist_mtime;
	    else if (hist_arg == "dtime")
	      commandline_histogram = hist_dtime;
	    else if (hist_arg == "group")
	      commandline_histogram = hist_group;
	    else
	    {
	      std::cout << std::flush;
	      std::cerr << progname << ": --histogram: " << hist_arg << ": unknown histogram type." << std::endl;
	      exit(EXIT_FAILURE);
	    }
	    break;
	  }
	  case opt_accept:
	  {
	    accepted_filenames.insert(Accept(optarg, true));
	    break;
	  }
	  case opt_accept_all:
	  {
	    commandline_accept_all = true;
	  }
        }
        break;
      case 'v':
      case 'V':
        print_version();
        exit(EXIT_SUCCESS);
    }
  }

  if (exclusive1 > 1)
  {
    std::cout << std::flush;
    std::cerr << progname << ": Only one of --group, --inode, --block, --journal-block, --dump-names or --show-journal-inodes may be specified." << std::endl;
    exit(EXIT_FAILURE);
  }
  if (exclusive2 > 1)
  {
    std::cout << std::flush;
    std::cerr << progname << ": Only one of --inode, --block, --search*, --journal-block, --dump-names or --show-journal-inodes may be specified." << std::endl;
    exit(EXIT_FAILURE);
  }
  if (commandline_allocated && commandline_unallocated)
  {
    std::cout << std::flush;
    std::cerr << progname << ": Only one of --allocated or --unallocated may be specified." << std::endl;
    exit(EXIT_FAILURE);
  }
  if (commandline_dump_names)
    commandline_ls = true;
  bool outputwritten = false;
  if ((commandline_block != -1 || commandline_inode != -1) && !commandline_ls && !commandline_print)
  {
    std::cout << "No --ls used; implying --print.\n";
    commandline_print = true;
    outputwritten = true;
  }
  commandline_action =
      (commandline_inode != -1 ||
       commandline_block != -1 ||
       commandline_journal_block != -1 ||
       commandline_journal_transaction != -1 ||
       commandline_dump_names ||
       commandline_show_journal_inodes != -1 ||
       commandline_histogram ||
       !commandline_search.empty() ||
       !commandline_search_start.empty() ||
       commandline_search_inode != -1||
       commandline_search_zeroed_inodes ||
       commandline_inode_to_block != -1 ||
       !commandline_restore_inode.empty() ||
       !commandline_restore_file.empty() ||
       commandline_restore_all ||
       commandline_show_hardlinks);
  if (!commandline_action && !commandline_superblock)
  {
    std::cout << "No action specified; implying --superblock.\n";
    commandline_superblock = true;
    outputwritten = true;
  }
  if ((commandline_histogram == hist_atime ||
       commandline_histogram == hist_ctime ||
       commandline_histogram == hist_mtime ||
       commandline_histogram == hist_dtime) &&
      !(commandline_before && commandline_after))
  {
    if (!commandline_before)
    {
      commandline_before = std::numeric_limits<int32_t>::max();
      std::cout << progname << ": --histogram=" << hist_arg << ": no --before given, assuming --before=" << commandline_before << '\n';
    }
    if (!commandline_after)
    {
      commandline_after = 1;
      std::cout << progname << ": --histogram=" << hist_arg << ": no --after given, assuming --after=" << commandline_after << '\n';
    }
  }
  if (commandline_before || commandline_after)
  {
    std::cout << "Only show/process deleted entries if they are deleted ";
    outputwritten = true;
    std::string after(std::ctime(&commandline_after));
    std::string before(std::ctime(&commandline_before));
    if (commandline_after)
      std::cout << "on or after " << after.substr(0, after.length() - 1);
    if (commandline_before && commandline_after)
      std::cout << " and ";
    if (commandline_before)
      std::cout << "before " << before.substr(0, before.length() - 1);
    std::cout << '.' << std::endl;
    if (commandline_before && commandline_after)
      ASSERT(commandline_after < commandline_before);
  }
  if (!accepted_filenames.empty())
  {
    std::cout << "Accepted filenames:";
    for (std::set<Accept>::iterator iter = accepted_filenames.begin(); iter != accepted_filenames.end(); ++iter)
    {
      ASSERT(iter->accepted());
      std::cout << " '" << iter->filename() << "'";
    }
    outputwritten = true;
  }
  if (outputwritten)
    std::cout << '\n';

  argv += optind;
  argc -= optind;

  if (argc == 0)
  {
    print_usage(std::cerr);
    exit(EXIT_FAILURE);
  }
}
