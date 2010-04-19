dnl Run autogen.sh to produce a configure script.

dnl CW_VERSION_MAJOR               : Increment when the whole application was rewritten; or some VERY MAJOR change was made.
dnl CW_VERSION_MINOR               : Increment when major changes have occured.
dnl CW_VERSION_REVISION            : Increment every public release; or set to 0 when CW_VERSION_MINOR was incremented.

define(CW_VERSION_MAJOR, 0)
define(CW_VERSION_MINOR, 10)
define(CW_VERSION_REVISION, 2)

define(CW_PACKAGE_NAME, [ext3grep])
define(CW_BUGREPORT, [carlo@alinoe.com])

dnl Package name and version
AC_INIT(CW_PACKAGE_NAME, CW_VERSION_MAJOR.CW_VERSION_MINOR.CW_VERSION_REVISION, CW_BUGREPORT)

dnl Put resulting configuration defines in this header file.
AC_CONFIG_HEADERS([config.h])

dnl Put revision of configure.ac in configure script.
AC_REVISION($Revision: 7 $)dnl

dnl Ensure that the directory specified with --srcdir was correct
dnl by demanding that it contains `ext3grep.pc.in'.
AC_CONFIG_SRCDIR([src/ext3grep.cc])

dnl Automake options.
AM_INIT_AUTOMAKE

dnl Include maintainer mode targets
AM_MAINTAINER_MODE

dnl Because we use cwautomacros.
CW_AUTOMACROS([20080318])

dnl Demand at least version 2.57 of autoconf.
AC_PREREQ(2.57)

dnl Check for compiler and preprocessor
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CXXCPP

dnl Demand little endian system
AC_C_BIGENDIAN([AC_MSG_ERROR([ext3grep doesn't work on Big Endian systems])])

dnl Make these two the default until ext3grep is stable.
dnl Add --enable-debug (DEBUG, DOXYGEN_DEBUG), --enable-libcwd (CWDEBUG, DOXYGEN_CWDEBUG),
dnl --enable-optimise and --enable-profile options. Update USE_LIBCWD, CWD_LIBS and CXXFLAGS accordingly.
CW_OPG_FLAGS([-W -Wall -Woverloaded-virtual -Wundef -Wpointer-arith -Wwrite-strings -Winline])

dnl Add --enable-pch (USE_PCH (macro)) option.
dnl Update USE_PCH (automake conditional) and PCHFLAGS accordingly.
CW_PCHFLAGS

dnl Add --enable-mmap option.
dnl Sets USE_MMAP appropriately.
AC_ARG_ENABLE(mmap, [  --enable-mmap           Use mmap for inode tables instead of operator new @<:@yes@:>@])
if test x"$enable_mmap" = x"no"; then	# --disable-mmap given.
  CXXFLAGS="$CXXFLAGS -DUSE_MMAP=0"
else
  CXXFLAGS="$CXXFLAGS -DUSE_MMAP=1"
fi

dnl Each Makefile.am should use DEFS = @DEFS@. Set DEFS here.
DEFS="-DHAVE_CONFIG_H"
AC_SUBST(DEFS)

dnl Test if we are checked out by svn.
if test -d "$srcdir/.svn"; then
  if test x"$enable_maintainer_mode" != x"yes"; then
    AC_MSG_ERROR([Always use --enable-maintainer-mode if you are using SVN.])
  fi
  AC_DEFINE_UNQUOTED([USE_SVN], 1, [Define when this project is checked out using svn.])
fi
AM_CONDITIONAL([USE_SVN], [test -d "$srcdir/.svn"])

dnl Set this conditional when --enable-debug was given.
AM_CONDITIONAL([USE_DEBUG], [test x"$cw_config_debug" = x"yes"])

dnl Set this conditional if we're linking with libcwd.
AM_CONDITIONAL([USE_CWDEBUG], [test x"$cw_used_libcwd" = x"yes"])

dnl Checks for other programs.
AC_PROG_INSTALL

dnl Include support for 64-bit file offsets if supported.
AC_SYS_LARGEFILE

dnl Include flags needed for the e2progs header files.
CXXFLAGS="$CXXFLAGS `pkg-config --cflags ext2fs`"

dnl Warn user if those headers couldn't be found.
AC_CHECK_HEADERS(ext2fs/ext2_fs.h ext2fs/ext2fs.h)
if test x"$ac_cv_header_ext2fs_ext2_fs_h" != x"yes" -o x"$ac_cv_header_ext2fs_ext2fs_h" != x"yes"; then
  AC_MSG_ERROR([Missing headers. Please install the package e2fslibs-dev from e2fsprogs, or http://e2fsprogs.sourceforge.net for the upstream tar-ball.])
fi

dnl Used in sys.h to force recompilation when the compiler version changes.
CW_PROG_CXX_FINGER_PRINTS
CC_FINGER_PRINT="$cw_prog_cc_finger_print"
AC_SUBST([CC_FINGER_PRINT])
CXX_FINGER_PRINT="$cw_prog_cxx_finger_print"
AC_SUBST([CXX_FINGER_PRINT])
CXXCPP_FINGER_PRINT="$cw_prog_cxxcpp_finger_print"
AC_SUBST([CXXCPP_FINGER_PRINT])

dnl Use in sys.h to force recompilation when CXXFLAGS change.
CXXFLAGS_FINGER_PRINT=[$(echo $CXXFLAGS | sed -e 's/-W[a-z-]* *//g')]
AC_SUBST([CXXFLAGS_FINGER_PRINT])

dnl Generate src/sys.h from src/sys.h.in
CW_CONFIG_FILE([src], [sys.h])

dnl Output the other configuration files.
AC_CONFIG_FILES(
        [Makefile]
        [src/Makefile])

AC_OUTPUT
