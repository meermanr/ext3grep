## Process this file with automake to generate Makefile.in

AUTOMAKE_OPTIONS = foreign
EXTRA_DIST = pch-source.h

bin_PROGRAMS = ext3grep
BUILT_SOURCES =
DEFS = @DEFS@
CXXFLAGS =

ext3grep_SOURCES = \
	custom.cc \
	accept.cc \
	blocknr_vector_type.cc \
	commandline.cc \
	directories.cc \
	dir_inode_to_block.cc \
	dump_hex_to.cc \
	dump_names.cc \
	init_journal_consts.cc \
	get_block.cc \
	globals.cc \
	histogram.cc \
	indirect_blocks.cc \
	init_consts.cc \
	init_directories.cc \
	init_files.cc \
	inode.cc \
	inode_refers_to.cc \
	is_blockdetection.cc \
	journal.cc \
	last_undeleted_directory_inode_refering_to_block.cc \
	load_meta_data.cc \
	ostream_operators.cc \
	Parent.cc \
	print_directory.cc \
	print_directory_inode.cc \
	print_dir_entry_long_action.cc \
	printing.cc \
	print_inode_to.cc \
	print_symlink.cc \
	restore.h \
	restore.cc \
	show_hardlinks.cc \
	show_journal_inodes.cc \
	utils.cc \
	ext3grep.cc \
	locate.cc \
	locate.h \
	ext3.h \
	Parent.h \
	forward_declarations.h \
	histogram.h \
	indirect_blocks.h \
	init_directories.h \
	utils.h \
	dir_inode_to_block.h \
	is_filename_char.h \
	superblock.h \
	directories.h \
	is_blockdetection.h \
	conversion.h \
	commandline.h \
	inode.h \
	ostream_operators.h \
	print_inode_to.h \
	bitmap.h \
	load_meta_data.h \
	FileMode.h \
	accept.h \
	endian_conversion.h \
	inode_refers_to.h \
	journal.h \
	init_files.h \
	init_journal_consts.h \
	print_dir_entry_long_action.h \
	get_block.h \
	init_consts.h \
	print_symlink.h \
	blocknr_vector_type.h \
	restore.h \
	globals.h \
	kernel-jbd.h \
	jfs_compat.h

ext3grep_CXXFLAGS = @CXXFLAGS@ @CWD_FLAGS@
ext3grep_LDADD = @LIBS@ @CWD_LIBS@
ext3grep_LDFLAGS =

if USE_DEBUG
ext3grep_SOURCES += backtrace.cc backtrace.h debug.cc debug.h
ext3grep_LDFLAGS += -rdynamic
ext3grep_SOURCES += 
else
if USE_CWDEBUG
ext3grep_SOURCES += debug.cc debug.h
endif
endif

if USE_PCH
@Makefilein@PREVCXXDEPMODE := $(CXXDEPMODE)
@Makefilein@CXXDEPMODE = $(PREVCXXDEPMODE) havepch=yes
@Makefilein@ifeq (./$(DEPDIR)/pch.po, $(wildcard ./$(DEPDIR)/pch.po))
@Makefilein@@am__include@ ./$(DEPDIR)/pch.po
@Makefilein@endif
ext3grep_CXXFLAGS += @PCHFLAGS@

APPLICATIONSUM := $(shell echo "$(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(ext3grep_CXXFLAGS)" | md5sum | sed -e 's/ .*//')

BUILT_SOURCES += pch.h.gch/$(APPLICATIONSUM)

pch.h.gch/$(APPLICATIONSUM): $(srcdir)/pch-source.h
	@rm -rf pch.h.gch
	@mkdir pch.h.gch
	@test -d $(DEPDIR) || mkdir $(DEPDIR)
	@mkdir -p empty.pch.h
	@touch empty.pch.h/pch.h
	@if $(CXX) -Iempty.pch.h $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(ext3grep_CXXFLAGS) \
	  -UUSE_PCH -M -MT pch.h.gch -MF $(DEPDIR)/pch.TTpo $(srcdir)/pch-source.h; then \
	  cat $(DEPDIR)/pch.TTpo | sed -e 's%^pch\.h\.gch:%pch.h.gch/$(APPLICATIONSUM):%' -e 's% empty\.pch\.h/pch\.h%%' > $(DEPDIR)/pch.Tpo; \
	  cmp -s $(DEPDIR)/pch.Tpo $(DEPDIR)/pch.po || mv $(DEPDIR)/pch.Tpo $(DEPDIR)/pch.po; \
	fi
	$(CXX) -Iempty.pch.h $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(ext3grep_CXXFLAGS) \
	  -c -o $@ $(srcdir)/pch-source.h
	test ! -e sys.h || touch sys.h
	@rm empty.pch.h/pch.h
	@rmdir empty.pch.h

endif

if USE_SVN
ext3grep_SOURCES += revision.cc

revision.cc: FORCE
	@(cd $(srcdir) && svn info) | grep '^Revision' | sed -e 's/R/char const* svn_revision = "R/;s/$$/";/' > revision.cc.tmp
	@cmp -s revision.cc revision.cc.tmp || mv revision.cc.tmp revision.cc && echo "Generating revision.cc"
	@rm -f revision.cc.tmp

FORCE:

.PHONY: FORCE
endif

# --------------- Maintainer's Section

#dist-hook:

all-local:
	@if test -e $(top_srcdir)/../.libcwdrc-src -a ! -e .libcwdrc; then \
	  echo "ln -s $(top_srcdir)/../.libcwdrc-src .libcwdrc"; \
	  ln -s $(top_srcdir)/../.libcwdrc-src .libcwdrc; \
	fi
	@if test -e $(top_srcdir)/../.gdbinit-src -a ! -e .gdbinit; then \
	  echo "ln -s $(top_srcdir)/../.gdbinit-src .gdbinit"; \
	  ln -s $(top_srcdir)/../.gdbinit-src .gdbinit; \
	fi

distclean-local:
	rm -rf $(srcdir)/autom4te.cache pch.h.gch sys.h
	test -L .libcwdrc && rm .libcwdrc || true
	test -L .gdbinit && rm .gdbinit || true
	@MAINTAINER_MODE_TRUE@rm -f .all_sources *.s *.ii

clean-local:
if USE_PCH
	rm -f pch.h.gch/* $(DEPDIR)/pch.*po
endif
if USE_SVN
	rm -f revision.cc
endif

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in tags troep* *.cgd

if MAINTAINER_MODE

if !USE_DEBUG
EXTRA_DIST += backtrace.cc backtrace.h
endif

if !USE_CWDEBUG
EXTRA_DIST += debug.cc debug.h
endif

# Usage: You have to set the CTAGS_ROOT_SRCDIRS environment variable yourself,
# for example: export CTAGS_ROOT_SRCDIRS="/usr/src/gtk/glib-current /usr/src/gtk/gtk+-current"
# Then run 'vim -u /some/path/.vimrc' where the .vimrc is the normal .vimrc, but with the
# additional lines: set tags=/full/path/to/top_builddir/tags
#                   nmap <C-N> :tnext<CR>
ctags:
	rm -f .all_sources
	touch .all_sources
	for d in $(CTAGS_ROOT_SRCDIRS) $(top_srcdir); do \
	  find $$d -follow -type f -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.C' -o -name '*.inl' >> .all_sources; \
	done
	ctags `cat .all_sources`
endif
