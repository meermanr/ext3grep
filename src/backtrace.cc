// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file backtrace.cc Support for printing a backtrace.
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

#ifndef DEBUG
// This is a bug in src/Makefile.am.
#error : This source file shouldn't be included at all when DEBUG isn't set.
#endif

#ifdef __OPTIMIZE__
// It makes no sense to dump backtraces if optimization is being used.
#error : Please add --disable-optimize to your configure options.
#endif

#ifndef USE_PCH
#include "sys.h"
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <sstream>
#include <unistd.h>
#include "debug.h"
#endif

#include <execinfo.h>
#include "backtrace.h"

extern char const* progname;
extern char* reserved_memory;

static size_t const BACKTRACE_SIZE = 256;
static void* return_addresses[BACKTRACE_SIZE];

void dump_backtrace_on(std::ostream& os)
{
  // Free some memory to make this work.
  delete [] reserved_memory;
  reserved_memory = NULL;

  // Get the backtrace.
  int nptrs = backtrace(return_addresses, BACKTRACE_SIZE);

  // Print it.
#ifdef CWDEBUG
  for (int j = 0; j < nptrs; ++j)
  {
    libcwd::location_ct loc((char*)return_addresses[j] + libcwd::builtin_return_address_offset);
    os << '#' << std::left << std::setw(3) << j;
    os << std::left << std::setw(16) << return_addresses[j] << ' ' << loc << "\n                  in ";
    char const* mangled_function_name = loc.mangled_function_name();
    if (mangled_function_name != libcwd::unknown_function_c)
    {
      std::string demangled_function_name;
      libcwd::demangle_symbol(mangled_function_name, demangled_function_name);
      os << demangled_function_name << '\n';
    }
    else
      os << mangled_function_name << '\n';
  }
#else
  char** symbols = backtrace_symbols(return_addresses, BACKTRACE_SIZE);
  if (symbols == NULL)
  {
    perror("backtrace_symbols");
    // Attempt to write to stderr directly.
    backtrace_symbols_fd(return_addresses, nptrs, STDERR_FILENO);
    exit(EXIT_FAILURE);
  }
  for (int j = 0; j < nptrs; ++j)
  {
    std::cout << '#' << std::left << std::setw(3) << j;
    std::cout << symbols[j] << std::endl;
    std::ostringstream command;
    command << "addr2line -e " << progname << ' ' << return_addresses[j];
    std::cout << "    " << std::flush;
    system(command.str().c_str());
  }
  free(symbols);
#endif
}

