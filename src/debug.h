// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file debug.h
//! @brief This file contains the declaration of debug related macros, objects and functions.
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

#ifndef DEBUG_H
#define DEBUG_H

#ifndef CWDEBUG

#ifndef DOXYGEN         // No need to document this.  See http://libcwd.sourceforge.net/ for more info.

#include <iostream>
#include <cstdlib>      // std::exit, EXIT_FAILURE

#define AllocTag1(p)
#define AllocTag2(p, desc)
#define AllocTag_dynamic_description(p, x)
#define AllocTag(p, x)
#define Debug(x)
#define Dout(a, b)
#define DoutEntering(a, b)
#define DoutFatal(a, b) LibcwDoutFatal(::std, , a, b)
#define ForAllDebugChannels(STATEMENT)
#define ForAllDebugObjects(STATEMENT)
#define LibcwDebug(dc_namespace, x)
#define LibcwDout(a, b, c, d)
#define LibcwDoutFatal(a, b, c, d) do { ::std::cerr << d << ::std::endl; ::std::exit(EXIT_FAILURE); } while (1)
#define NEW(x) new x
#define CWDEBUG_ALLOC 0
#define CWDEBUG_MAGIC 0
#define CWDEBUG_LOCATION 0
#define CWDEBUG_LIBBFD 0
#define CWDEBUG_DEBUG 0
#define CWDEBUG_DEBUGOUTPUT 0
#define CWDEBUG_DEBUGM 0
#define CWDEBUG_DEBUGT 0
#define CWDEBUG_MARKER 0

#endif // !DOXYGEN

#else // CWDEBUG

#ifndef DEBUGCHANNELS
//! @brief The namespace in which the \c dc namespace is declared.
//
// <A HREF="http://libcwd.sourceforge.net/">Libcwd</A> demands that this macro is defined
// before <libcwd/debug.h> is included and must be the name of the namespace containing
// the \c dc (Debug Channels) namespace.
//
// @sa debug::channels::dc

#define DEBUGCHANNELS ::debug::channels
#endif
#include <libcwd/debug.h>

//! Debug specific code.
namespace debug {

void init(void);                // Initialize debugging code, called once from main.
void init_thread(void);         // Initialize debugging code, called once for each thread.

//! @brief Debug Channels (dc) namespace.
//
// @sa debug::channels::dc
namespace channels {	// namespace DEBUGCHANNELS

//! The namespace containing the actual debug channels.
namespace dc {
using namespace libcwd::channels::dc;
using libcwd::channel_ct;

#ifndef DOXYGEN         // Doxygen bug causes a warning here.
// Add the declaration of new debug channels here
// and add their definition in a custom debug.cc file.
//extern channel_ct custom;

#endif

} // namespace dc
} // namespace DEBUGCHANNELS

#if CWDEBUG_LOCATION
std::string call_location(void const* return_addr);
#endif

//! @brief Interface for marking scopes of invisible memory allocations.
//
// Creation of the object does nothing, you have to explicitly call
// InvisibleAllocations::on.  Destruction of the object automatically
// cancels any call to \c on of this object.  This makes it exception-
// (stack unwinding) and recursive-safe.
struct InvisibleAllocations {
  int M_on;             //!< The number of times that InvisibleAllocations::on() was called.
  //! Constructor.
  InvisibleAllocations() : M_on(0) { }
  //! Destructor.
  ~InvisibleAllocations() { while (M_on > 0) off(); }
  //! Set invisible allocations on. Can be called recursively.
  void on(void) { libcwd::set_invisible_on(); ++M_on; }
  //! Cancel one call to on().
  void off(void) { assert(M_on > 0); --M_on; libcwd::set_invisible_off(); }
};

//! @brief Interface for marking scopes with indented debug output.
//
// Creation of the object increments the debug indentation. Destruction
// of the object automatically decrements the indentation again.
struct Indent {
  int M_indent;                 //!< The extra number of spaces that were added to the indentation.
  //! Construct an Indent object.
  Indent(int indent) : M_indent(indent) { if (M_indent > 0) libcwd::libcw_do.inc_indent(M_indent); }
  //! Destructor.
  ~Indent() { if (M_indent > 0) libcwd::libcw_do.dec_indent(M_indent); }
};

} // namespace debug

//! Debugging macro.
//
// Print "Entering " << \a data to channel \a cntrl and increment
// debugging output indentation until the end of the current scope.
#define DoutEntering(cntrl, data) \
  int __ext3grep_debug_indentation = 2;                                                                      \
  {                                                                                                                     \
    LIBCWD_TSD_DECLARATION;                                                                                             \
    if (LIBCWD_DO_TSD_MEMBER_OFF(::libcwd::libcw_do) < 0)                                                               \
    {                                                                                                                   \
      ::libcwd::channel_set_bootstrap_st __libcwd_channel_set(LIBCWD_DO_TSD(::libcwd::libcw_do) LIBCWD_COMMA_TSD);      \
      bool on;                                                                                                          \
      {                                                                                                                 \
        using namespace LIBCWD_DEBUGCHANNELS;                                                                           \
        on = (__libcwd_channel_set|cntrl).on;                                                                           \
      }                                                                                                                 \
      if (on)                                                                                                           \
        Dout(cntrl, "Entering " << data);                                                                               \
      else                                                                                                              \
        __ext3grep_debug_indentation = 0;                                                                    \
    }                                                                                                                   \
  }                                                                                                                     \
  debug::Indent __ext3grep_debug_indent(__ext3grep_debug_indentation);

#endif // CWDEBUG

#undef ASSERT
#ifdef DEBUG
#include "backtrace.h"

extern void assert_fail(char const* expr, char const* file, int line, char const* function);

#define STRING(x) #x
#define ASSERT(expr) \
        (static_cast<void>((expr) ? 0 \
                                  : (assert_fail(STRING(expr), __FILE__, __LINE__, __PRETTY_FUNCTION__), 0)))
#else // !DEBUG
#include <cassert>
#define ASSERT(expr) assert(expr)
#endif // !DEBUG

#ifndef EXTERNAL_BLOCK
#define EXTERNAL_BLOCK 0
#endif

#if EXTERNAL_BLOCK
#define SOMEONES_BLOCK_SIZE 4096
#else
#define SOMEONES_BLOCK_SIZE 1
#endif

extern uint32_t someones_inode_count;
extern unsigned char someones_block[SOMEONES_BLOCK_SIZE];

#endif // DEBUG_H
