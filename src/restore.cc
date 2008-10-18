// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file restore.cc Implementation of --restore-inode and --restore-file.
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
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <utime.h>
#include <sstream>
#include "ext3.h"
#endif

#include "inode.h"
#include "journal.h"
#include "commandline.h"
#include "get_block.h"
#include "forward_declarations.h"
#include "init_files.h"
#include "init_directories.h"
#include "restore.h"
#include "utils.h"
#include "FileMode.h"
#include "indirect_blocks.h"
#include "print_symlink.h"

#ifdef CPPGRAPH
void iterate_over_all_blocks_of__with__restore_file_action(void) { restore_file_action(0, 0, NULL); }
#endif

get_undeleted_inode_type get_undeleted_inode(int inodenr, Inode& inode, int* sequence)
{
  InodePointer real_inode(get_inode(inodenr));
  if (!real_inode->is_deleted())
  {
    inode = *real_inode;
    return ui_real_inode;
  }
  std::vector<std::pair<int, Inode> > inodes;
  get_inodes_from_journal(inodenr, inodes);
  for (std::vector<std::pair<int, Inode> >::iterator iter = inodes.begin(); iter != inodes.end(); ++iter)
  {
    Inode const& journal_inode(iter->second);
    if (!journal_inode.is_deleted())
    {
      inode = journal_inode;
      if (sequence)
	*sequence = iter->first;
      return ui_journal_inode;
    }
    else if (commandline_after && (time_t)journal_inode.dtime() < commandline_after)
      return ui_inode_too_old;
  }
  return ui_no_inode;
}

extern "C" int lutimes (char const*, struct timeval const [2]);

struct Data {
  int out;
  off_t remaining_size;
  int expected_file_block_nr;

  Data(int out_, off_t remaining_size_) : out(out_), remaining_size(remaining_size_), expected_file_block_nr(0) { }
};

void restore_file_action(int blocknr, int file_block_nr, void* ptr)
{
  Data& data(*reinterpret_cast<Data*>(ptr));
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  int len;

  if (data.expected_file_block_nr != file_block_nr)
  {
    ASSERT(data.expected_file_block_nr != -1);	// It's set to -1 below when we reached the end of the file.
    off64_t pos = ((off64_t) file_block_nr) * block_size_;
    if (lseek64(data.out, pos, SEEK_SET) == (off_t) -1)
    {
      int error = errno;
      std::cout << std::flush;
      std::cerr << progname << "restore_file_action: could not lseek64 to position " << pos << ": " << strerror(error) << std::endl;
      exit(EXIT_FAILURE);
    }
    data.expected_file_block_nr = file_block_nr;
  }

  get_block(blocknr, block_buf);
  if (data.remaining_size > block_size_)
  {
    len = block_size_;
    data.expected_file_block_nr += block_size_;
  }
  else
  {
    len = data.remaining_size;
    data.expected_file_block_nr = -1;	// This was the last block.
  }
  int res = ::write(data.out, (char const*)block_buf, len);
  ASSERT(res == len);
  data.remaining_size -= len;
}

void restore_file(std::string const& outfile)
{
  ASSERT(!outfile.empty());
  ASSERT(outfile[0] != '/');
  init_files();
  int inodenr;
  path_to_inode_map_type::iterator inode_iter = path_to_inode_map.find(outfile);
  if (inode_iter != path_to_inode_map.end())
    inodenr = inode_iter->second;
  else
  {
    all_directories_type::iterator directory_iter = all_directories.find(outfile);
    if (directory_iter == all_directories.end())
    {
      std::cout << "Cannot find an inode number for file \"" << outfile << "\".\n";
      return;
    }
    inodenr = directory_iter->second.inode_number();
  }
  InodePointer real_inode = get_inode(inodenr);
  std::string::size_type slash = outfile.find_last_of('/');
  if (slash != std::string::npos)
  {
    std::string dirname = outfile.substr(0, slash);
    struct stat statbuf;
    if (lstat((outputdir + dirname).c_str(), &statbuf) == -1)
    {
      int error = errno;
      if (error != ENOENT)
      {
	std::cout << std::flush;
	std::cerr << "WARNING: lstat: " << (outputdir + dirname) << ": " << strerror(error) << std::endl;
	std::cout << "Failed to recover " << outfile << '\n';
	return;
      }
      else
        restore_file(dirname);
    }
    else if (!S_ISDIR(statbuf.st_mode))
    {
      std::cout << std::flush;
      std::cerr << progname << ": failed to recover " << outfile << ": " << (outputdir + dirname) << " exists but is not a directory!" << std::endl;
      exit(EXIT_FAILURE);
    }
  }
  restore_inode(inodenr, real_inode, outfile);
}

void restore_inode(int inodenr, InodePointer real_inode, std::string const& outfile)
{
  std::string outputdir_outfile = outputdir + outfile;
  if (is_directory(*real_inode))
  {
    mode_t mode = inode_mode_to_mkdir_mode(real_inode->mode());
    if ((mode & (S_IWUSR|S_IXUSR)) != (S_IWUSR|S_IXUSR))
      std::cout << "Note: Restoring directory " << outputdir_outfile << " with mode " <<
          FileMode(real_inode->mode() | 0500) << " although it's original mode is " << FileMode(real_inode->mode()) << ".\n";
    if (mkdir(outputdir_outfile.c_str(), mode|S_IWUSR|S_IXUSR) == -1 && errno != EEXIST)
    {
      int error = errno;
      std::cout << std::flush;
      std::cerr << progname << ": could not create directory " << outputdir_outfile << ": " << strerror(error) << std::endl;
      exit(EXIT_FAILURE);
    }
    if (chmod(outputdir_outfile.c_str(), mode) == -1)
    {
      int error = errno;
      std::cout << "WARNING: failed to set mode on directory " << outputdir_outfile << std::endl;
      std::cerr << progname << ": chmod: " << strerror(error) << std::endl;
    }
    struct utimbuf ub;
    ub.actime = real_inode->atime();
    ub.modtime = real_inode->mtime();
    if (utime(outputdir_outfile.c_str(), &ub) == -1)
    {
      int error = errno;
      std::cout << "WARNING: Failed to set access and modification time on " << outputdir_outfile << ": " << strerror(error) << '\n';
    }
  }
  else
  {
    Inode inode;
    get_undeleted_inode_type res = get_undeleted_inode(inodenr, inode);
    if (res != ui_real_inode && res != ui_journal_inode)
    {
      if (res == ui_no_inode)
	std::cout << "Cannot find an undeleted inode for file \"" << outfile << "\".\n";
      else
        std::cout << "Not undeleting \"" << outfile << "\" because it was deleted before " << commandline_after << " (" << inode.ctime() << ")\n";
      return;
    }
    ASSERT(!inode.is_deleted());
    if (is_regular_file(inode))
    {
      int out;
      out = ::open(outputdir_outfile.c_str(), O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, 0777);
      if (out == -1)
      {
	std::cout << "Failed to open \"" << outputdir_outfile << "\".\n";
	return;
      }
      Data data(out, inode.size());
      std::cout << "Restoring " << outfile << '\n';
#ifdef CPPGRAPH
      // Tell cppgraph that we call restore_file_action from here.
      iterate_over_all_blocks_of__with__restore_file_action();
#endif
      bool reused_or_corrupted_indirect_block8 = iterate_over_all_blocks_of(inode, inodenr, restore_file_action, &data);
      ::close(out);
      if (reused_or_corrupted_indirect_block8)
      {
        std::cout << "WARNING: Failed to restore " << outfile << ": encountered a reused or corrupted (double/triple) indirect block!\n";
	std::cout << "Running iterate_over_all_blocks_of again with diagnostic messages ON:\n";
	iterate_over_all_blocks_of(inode, inodenr, restore_file_action, &data, direct_bit, true);
	// FIXME: file should be renamed.
      }
      if (chmod(outputdir_outfile.c_str(), inode_mode_to_mkdir_mode(inode.mode())) == -1)
      {
        int error = errno;
	std::cout << "WARNING: failed to set file mode on " << outputdir_outfile << std::endl;
	std::cerr << progname << ": chmod: " << strerror(error) << std::endl;
      }
      struct utimbuf ub;
      ub.actime = inode.atime();
      ub.modtime = inode.mtime();
      if (utime(outputdir_outfile.c_str(), &ub) == -1)
      {
	int error = errno;
	std::cout << "WARNING: Failed to set access and modification time on " << outputdir_outfile << ": " << strerror(error) << '\n';
	return;
      }
    }
    else if (is_symlink(inode))
    {
      std::ostringstream symlink_name;
      int len = print_symlink(symlink_name, inode);
      if (len == 0)
      {
        std::cout << "WARNING: Failed to recover " << outfile << ": symlink has zero length!\n";
	return;
      }
      else
      {
        if (symlink(symlink_name.str().c_str(), outputdir_outfile.c_str()) == -1)
	{
	  int error = errno;
	  std::cout << "WARNING: symlink: " << outputdir_outfile << ": " << strerror(error) << '\n';
	  return;
	}
	struct timeval tvp[2];
	tvp[0].tv_sec = inode.atime();
	tvp[0].tv_usec = 0;
	tvp[1].tv_sec = inode.mtime();
	tvp[1].tv_usec = 0;
        if (lutimes(outputdir_outfile.c_str(), tvp) == -1)
	{
	  int error = errno;
	  std::cout << "WARNING: Failed to set access and modification time on " << outputdir_outfile << ": " << strerror(error) << '\n';
	  return;
	}
      }
    }
    else
    {
      std::cout << "WARNING: Not recovering \"" << outfile << "\", which is a " << mode_str(inode.mode()) << '\n';
      return;
    }
  }
}

