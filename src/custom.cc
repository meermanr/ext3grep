// ext3grep -- An ext3 file system investigation and undelete tool
//
//! @file custom.cc Functions that can be called by passing the commandline option --custom.
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
#include "ext3.h"
#include "debug.h"
#endif

#include "commandline.h"
#include "globals.h"
#include "ostream_operators.h"
#include "inode.h"
#include "conversion.h"
#include "init_journal_consts.h"
#include "load_meta_data.h"
#include "forward_declarations.h"
#include "is_blockdetection.h"
#include "indirect_blocks.h"
#include "restore.h"
#include "get_block.h"
#include "init_consts.h"
#include "print_inode_to.h"

uint32_t wbblocks[] = {
  131961, 131980, 132587, 132598, 132599, 132600, 132601, 132602, 132603,
  132610, 132617, 132621, 132623, 132625, 132626, 133492, 133520, 133522,
  133523, 133524, 133536, 133537, 133552, 133554, 133556, 133564, 133565,
  133568, 133569, 133570, 133571, 133576, 133577, 133578, 133579, 133843,
  133864, 133865, 133866, 133867, 135213, 135217, 135218, 135219, 135220,
  135222, 135223, 135224, 135225, 135227, 135228, 135245, 135246, 135254,
  135255, 135256, 135261, 135263, 135264, 135265, 135267, 135269, 135270,
  135271, 135272, 135273, 135276, 135278, 135279, 135280, 135287, 135289,
  135290, 135291, 135292, 135293, 135294, 135295, 135298, 135300, 135301,
  135302, 135303, 135304, 137578, 137588, 137606, 137607, 137608, 137609,
  137610, 137611, 137612, 137621, 137622, 137623, 137625, 137626, 137629,
  137631, 137637, 137638, 139352, 139353, 139354, 139357, 139360, 139361,
  139362, 139363, 139364, 139365, 139366, 139367, 139368, 139369, 139370,
  139372, 139373, 139374, 139375, 139376, 139377, 139379, 139381, 139383,
  139384, 139385, 139387, 139388, 143609, 143627, 143628, 143630, 143631,
  143641, 143642, 143644, 143645, 143646, 143650, 143665, 143669, 143670,
  143671, 143675, 143717, 143747, 143748, 143749, 143750, 143751, 143752,
  143753, 143754, 143755, 143762, 143769, 143774, 143777, 143780, 143781,
  143783, 143785, 143787, 143800, 145435, 145437, 145446, 145447, 145448,
  145449, 145453, 145454, 145461, 145469, 145470, 145471, 145472, 145473,
  145474, 145476, 145477, 145480, 145482, 145484, 145485, 145486, 145489,
  145490, 145491, 145492, 145493, 145494, 145495, 145880, 147756, 147757,
  147758, 147759, 147760, 147761, 147762, 148099, 148100, 148531, 148533,
  148535, 149548, 149550, 149551, 149552, 149553, 149554, 149555, 149556,
  149568, 149569, 149570, 149572, 149573, 149575, 149576, 149577, 149578,
  149579, 149580, 149582, 149592, 149593, 149594, 149596, 149597, 151594,
  151618, 151633, 151643, 151646, 151647, 151648, 151650, 151652, 151661,
  151673, 151676, 151677, 151679, 153637, 154270, 154843, 154854, 155336,
  156087, 156908, 159508, 160258, 160260, 160262, 160263, 161968, 161969,
  161971, 161972, 161973, 161984, 161986, 161988, 161990, 161995, 161997,
  162002, 162003, 162004, 162008, 162010, 162014, 162016, 162018, 162020,
  162022, 162024, 162028, 162031, 162033, 162035, 162037, 162039, 162041,
  162043, 162045, 162047, 162050, 162051, 162052, 162053, 162054, 162055,
  162057, 162059, 162075, 162077, 162079, 504510, 504599, 519014, 519211,
  519423, 519858, 519919, 520076, 520126, 520909, 521778, 524033, 524100,
  524236, 527110, 4784662, 4784670, 4784746, 4784758, 4784760, 4784763,
  4784771, 4784789, 4784832, 4784835, 4785360, 4786178, 4786179, 4786198,
  4786201, 4786205, 4786206, 4786209, 4786242, 4786244, 4786245, 4786246,
  4786247, 4786252, 4786253, 4786256, 4786257, 4786258, 4786259, 4786260,
  4786261, 4786262, 4786267, 4786268, 4786269, 4786270, 4786275, 4786287,
  4788235, 4788238, 4788240, 4788242, 4788243, 4788624, 4788627, 4788628,
  4788849, 4788850, 4788852, 4788858, 4788860, 4788861, 4788862, 4788863,
  4788865, 4788867, 4788868, 4788871, 4788873, 4788874, 4788875, 4788887,
  4788890, 4788891, 4788892, 4788893, 4788895, 4788896, 4788897, 4788898,
  4788900, 4788901, 4788902, 4788903, 4788905, 4788906, 4790298, 4790320,
  4790323, 4790338, 4790352, 4790358, 4790421, 4790422, 4790426, 4790432,
  4790469, 4790470, 4790471, 4790481, 4790658, 4791131, 4791136, 4791138,
  4791139, 4791140, 4791263, 4791270, 4791272, 4791285, 4791286, 4791305,
  4791306, 4791307, 4791308, 4791344, 4791345, 4791352, 4791354, 4791367,
  4791368, 4791369, 4791375, 4791376, 4791377, 4791378, 4791397, 4791398,
  4791399, 4791400, 4791401, 4791407, 4791421, 4791437, 4792326, 4792327,
  4792347, 4792384, 4792389, 4792390, 4792392, 4792403, 4792441, 4792493,
  4792494, 4792495, 4792496, 4792497, 4792498, 4792504, 4792505, 4792580,
  4792583, 4792585, 4792593, 4792623, 4792626, 4792897, 4793537, 4793539,
  4794368, 4794370, 4794376, 4794392, 4794403, 4794753, 4794754, 4794787,
  4794788, 4794789, 4794794, 4794796, 4794798, 4794859, 4794861, 4794862,
  4794864, 4794865, 4794866, 4794867, 4794868, 4794869, 4794871, 4794874,
  4794875, 4794876, 4794877, 4794878, 4794879, 4794880, 4794906, 4794908,
  4794914, 4794919, 4796522, 4796550, 4796551, 4796556, 4796560, 4796570,
  4796592, 4796875, 4796955, 4796958, 4797450, 4798479, 4798481, 4798482,
  4798491, 4798515, 4798518, 4799123, 4799600, 4799603, 4799621, 4799625,
  4799626, 4799628, 4799629, 4799635, 4799638, 4799639, 4799640, 4799642,
  4799647, 4799648, 4799649, 4799656, 4799667, 4799668, 4799669, 4799670,
  4799681, 4799684, 4799685, 4799686, 4800725, 4800728, 4800729, 4800751,
  4800755, 4800756, 4800758, 4800760, 4800761, 4800762, 4800763, 4800764,
  4800765, 4800766, 4800767, 4800768, 4800769, 4800770, 4800771, 4800772,
  4800773, 4800774, 4800775, 4800776, 4800777, 4800778, 4800779, 4800782,
  4800783, 4800794, 4801101, 4801106, 4801108, 4801118, 4801132, 4802560,
  4802696, 4802699, 4802789, 4802790, 4802791, 4802794, 4802798, 4802818,
  4802820, 4802821, 4802991, 4804618, 4804621, 4804623, 4804642, 4804651,
  4804652, 4804783, 4804784, 4804794, 4804807, 4804930, 4805511, 4805945,
  4805946, 4805947, 4806662, 4806680, 4806723, 4806724, 4806739, 4806784,
  4806786, 4806792, 4806796, 4806797, 4806798, 4806799, 4806800, 4806802,
  4806803, 4806804, 4806805, 4806807, 4807173, 4808747, 4808748, 4808752,
  4808753, 4808757, 4808762, 4808763, 4808764, 4808767, 4808771, 4808773,
  4808774, 4808775, 4808776, 4808777, 4808779, 4808780, 4808781, 4808782,
  4808784, 4808787, 4808788, 4808789, 4808790, 4808791, 4808792, 4808793,
  4808794, 4808796, 4808797, 4808801, 4808802, 4808919, 4808922, 4809278,
  4809282, 4810873, 4810889, 4810891, 4810896, 4810929, 4810930, 4810946,
  4810951, 4810958, 4810970, 4810973, 4811005, 4811006, 4811011, 4811012,
  4811016, 4811018, 4811019, 4811020, 4811038, 4811056, 4811057, 4811058,
  4811060, 4811061, 4811077, 4811078, 4811081, 4811082, 4811083, 4811084,
  4811534, 4811573, 4811600, 4811633, 4811639, 4811805, 4811811, 4811815,
  4811827, 4812355, 4812364, 4812808, 4812811, 4812910, 4812911, 4812934,
  4812936, 4812944, 4812945, 4813122, 4813455, 4813524, 4814047, 4814049,
  4814051, 4814052, 4814054, 4814058, 4814059, 4814060, 4814061, 4814062,
  4814063, 4814064, 4814067, 4814068, 4814070, 4814071, 4814072, 4814073,
  4814079, 4814085, 4814479, 4814856, 4814893, 4814900, 4814901, 4814902,
  4814903, 4814907, 4814941, 4815767, 4815777, 4815778, 4815779, 4815780,
  4815781, 4995757, 4998221, 5001702, 5001707, 5007956, 5011543, 5013485,
  5247648, 5251712, 5259945, 5261346, 5268196, 5274299, 6141983, 7444886,
  7502539
};

#if 0
void custom(void)
{
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
#if 0
#if 0
  static unsigned char mail_size[4096];
  int len = 0;

  for (unsigned int i = 0; i < sizeof(wbblocks) / sizeof(uint32_t); ++i)
  {
    unsigned char* block_ptr = get_block(wbblocks[i], block_buf);
    bool saw_zero = false;
    for (int j = 0; j < block_size_; ++j)
    {
      if (block_ptr[j] != 0)
      {
        ASSERT(!saw_zero);
      }
      else
      {
        if (!saw_zero)
	{
	 len = j;
	}
        saw_zero = true;
      }
    }
    if (saw_zero)
    {
      std::cout << "BLOCK: " << wbblocks[i] << "; size = " << len << '\n';
      ++mail_size[len];
    }
    else
    {
      std::cout << "BLOCK: " << wbblocks[i] << "; size > 4096\n";
    }
  }
#endif
  static int groups_count[257];
  print_restrictions();
  if (commandline_deleted || commandline_histogram == hist_dtime)
    std::cout << "Only showing deleted entries.\n";
  if (commandline_histogram == hist_atime ||
      commandline_histogram == hist_ctime ||
      commandline_histogram == hist_mtime ||
      commandline_histogram == hist_dtime)
    hist_init(commandline_after, commandline_before);
  else if (commandline_histogram == hist_group)
    hist_init(0, groups_);
  // Run over all (requested) groups.
  std::vector<unsigned int> inodes_group_any;
  for (int group = 0, ibase = 0; group < groups_; ++group, ibase += inodes_per_group_)
  {
    if (commandline_group != -1 && group != commandline_group)
      continue;
    // Run over all inodes.
    for (int bit = 0,  inode_number = (group == 0) ? first_inode(super_block) : ibase + 1; bit < inodes_per_group_; ++bit, ++inode_number)
    {
      InodePointer inode(get_inode(inode_number));
      if (commandline_deleted && !inode->is_deleted())
	continue;
      if ((commandline_histogram == hist_dtime || commandline_histogram == hist_group) && !inode->has_valid_dtime())
	continue;
      if (commandline_directory && !is_directory(inode))
	continue;
      if (commandline_allocated || commandline_unallocated)
      {
	bitmap_ptr bmp = get_bitmap_mask(bit);
	bool allocated = (inode_bitmap[group][bmp.index] & bmp.mask);
	if (commandline_allocated && !allocated)
	  continue;
	if (commandline_unallocated && allocated)
	  continue;
      }
      time_t xtime = 0;
      if (commandline_histogram == hist_dtime)
	xtime = inode->dtime();
      else if (commandline_histogram == hist_atime)
      {
	xtime = inode->atime();
	if (xtime == 0)
	  continue;
      }
      else if (commandline_histogram == hist_ctime)
      {
	xtime = inode->ctime();
	if (xtime == 0)
	  continue;
      }
      else if (commandline_histogram == hist_mtime)
      {
	xtime = inode->mtime();
	if (xtime == 0)
	  continue;
      }
      if (xtime && commandline_after <= xtime && xtime < commandline_before)
      {
	hist_add(xtime);
	++groups_count[group];
	inodes_group_any.push_back(inode_number);
      }
      if (commandline_histogram == hist_group)
      {
	if (commandline_after && commandline_after > (time_t)inode->dtime())
	  continue;
	if (commandline_before && (time_t)inode->dtime() >= commandline_before)
	  continue;
	hist_add(group);
      }
    }
  }
  hist_print();
#if 0
  for (int i = 0; i < groups_; ++i)
  {
    std::cout << i << ' ' << groups_count[i] << '\n';
  }
  unsigned int max146 = 0;
  unsigned int min146 = 0xffffffff;
  for (std::vector<unsigned int>::iterator iter = inodes_group146.begin(); iter != inodes_group146.end(); ++iter)
  {
    max146 = std::max(max146, *iter);
    min146 = std::min(min146, *iter);
  }
  std::cout << "min146 = " << min146 << "; max146 = " << max146 << '\n';
  std::cout << "diff146 = " << (max146 - min146) << '\n';
  ++max146;
  unsigned char ino146[max146 - min146];
  std::memset(ino146, 0, max146 - min146);
  for (std::vector<unsigned int>::iterator iter = inodes_group146.begin(); iter != inodes_group146.end(); ++iter)
    ino146[*iter - min146] = 1;
  unsigned int max4 = 0;
  unsigned int min4 = 0xffffffff;
  for (std::vector<unsigned int>::iterator iter = inodes_group4.begin(); iter != inodes_group4.end(); ++iter)
  {
    max4 = std::max(max4, *iter);
    min4 = std::min(min4, *iter);
  }
  std::cout << "min4 = " << min4 << "; max4 = " << max4 << '\n';
  std::cout << "diff4 = " << (max4 - min4) << '\n';
  ++max4;
  unsigned char ino4[max4 - min4];
  std::memset(ino4, 0, max4 - min4);
  for (std::vector<unsigned int>::iterator iter = inodes_group4.begin(); iter != inodes_group4.end(); ++iter)
    ino4[*iter - min4] = 1;
#else
  for (std::vector<unsigned int>::iterator iter = inodes_group_any.begin(); iter != inodes_group_any.end(); ++iter)
  {
    std::cout << "INODE: " << *iter << '\n';
  }
  unsigned int max = 0;
  unsigned int min = 0xffffffff;
  for (std::vector<unsigned int>::iterator iter = inodes_group_any.begin(); iter != inodes_group_any.end(); ++iter)
  {
    max = std::max(max, *iter);
    min = std::min(min, *iter);
  }
  std::cout << "min = " << min << "; max = " << max << '\n';
  std::cout << "diff = " << (max - min) << '\n';
  ++max;
  unsigned char ino[max - min];
  std::memset(ino, 0, max - min);
  for (std::vector<unsigned int>::iterator iter = inodes_group_any.begin(); iter != inodes_group_any.end(); ++iter)
    ino[*iter - min] = 1;
#endif
#endif
#if 1
  for (int group = 0; group < groups_; ++group)
  {
    if (group != 4 && group != 15 && group != 16 && group != 146 && group != 152 && group != 160 && group != 187 && group != 227 && group != 228)
      continue;
    //std::cout << "\nSearching group " << group << ": " << std::flush;
    int first_block = first_data_block(super_block) + group * blocks_per_group(super_block);
    int last_block = std::min(first_block + blocks_per_group(super_block), block_count(super_block));
    for (int block = first_block; block < last_block; ++block)
    {
      if (is_journal(block))
	continue;
      unsigned char* block_ptr = get_block(block, block_buf);
#if 0
      DirectoryBlockStats stats;
      is_directory_type result = is_directory(block_ptr, block, stats, false);
      if (result != isdir_no)
      {
	int offset = 0;
	while (offset < block_size_)
	{
	  ext3_dir_entry_2* dir_entry = reinterpret_cast<ext3_dir_entry_2*>(block_ptr + offset);
	  if (dir_entry->inode >= min && dir_entry->inode < max && ino[dir_entry->inode - min])
	  {
	    std::cout << "Block " << block << " has an entry with inode " << dir_entry->inode << " (";
	    print_buf_to(std::cout, dir_entry->name, dir_entry->name_len);
	    std::cout << ")\n";
	  }
	  offset += dir_entry->rec_len;
	}
      }
#else
      if (strncmp((char const*)block_ptr, "Return-Path:", 12) == 0 && block_ptr[4095] != 0)
      {
        for (char const* p = (char const*)block_ptr; p < (char const*)block_ptr + 4095; ++p)
	{
	  if (*p == 'i' && p[1] == 'n' && p[2] == 'v' && p[3] == 'o' && p[4] == 'k' && p[5] == 'e' && p[6] == 'd' && p[7] == ' ')
	  {
	    if (strncmp(p, "invoked by uid ", 15) == 0)
	    {
	      p += 15;
	      while(std::isdigit(*p)) ++p;
	    }
	    else if (strncmp(p, "invoked from network", 20) == 0)
	    {
	      p += 20;
	    }
	    else if (strncmp(p, "invoked for bounce", 18) == 0)
	    {
	      p += 18;
	    }
	    else if (strncmp(p, "invoked by alias", 16) == 0)
	    {
	      p += 16;
	    }
	    else
	    {
	      std::cout << "XXX p = \"" << p << "\"." << std::endl;
	      ASSERT(false);
	    }
	    if (*p == '[')
	    {
	      while(*p && *p != ']')
	        ++p;
	      ++p;
	    }
	    if (!(p[0] == ')' && p[1] == ';' && p[2] == ' '))
	      std::cout << "ZZZ p = \"" << p << "\"." << std::endl;
	    ASSERT(p[0] == ')' && p[1] == ';' && p[2] == ' ');
	    p += 3;
#if 0
	    if (std::isdigit(*p))
	    {
	      char const* q = p;
	      while(std::isdigit(*q))
	        ++q;
	      ASSERT(*q == ' ');
	    }
	    else
	    {
	      char day[4];
	      strncpy(day, p, 3);
	      if (!(!strcmp(day, "Mon") || !strcmp(day, "Tue") || !strcmp(day, "Wed") || !strcmp(day, "Thu") || !strcmp(day, "Fri") || !strcmp(day, "Sat") || !strcmp(day, "Sun")))
	        std::cout << "YYY p = \"" << p << "\"." << std::endl;
	      ASSERT(!strcmp(day, "Mon") || !strcmp(day, "Tue") || !strcmp(day, "Wed") || !strcmp(day, "Thu") || !strcmp(day, "Fri") || !strcmp(day, "Sat") || !strcmp(day, "Sun"));
	    }
#endif
	    char const* q = p;
	    while (*q == ' ' || std::isalnum(*q) || *q == ':' || *q == '-' || *q == '+')
	      ++q;
	    struct tm tm;
	    strptime(p, "%d %b %Y %H:%M:%S %z", &tm);
	    time_t t = mktime(&tm) + 7200;
	    std::cout << "GROUP: " << group << "; BLOCK: " << block << /*"; SIZE: " << strlen((char const*)block_ptr) <<*/ "; TIME: " << t << std::endl;
	    break;
	  }
	}
      }
#endif
    }
  }
  std::cout << '\n';
#endif
}
#endif

#if 0
void custom(void)
{
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  for (int group = 0; group < groups_; ++group)
  {
    if (group != 4 && group != 15 && group != 16 && group != 146 && group != 152 && group != 160 && group != 187 && group != 227 && group != 228)
      continue;
    //std::cout << "\nSearching group " << group << ": " << std::flush;
    int first_block = first_data_block(super_block) + group * blocks_per_group(super_block);
    int last_block = std::min(first_block + blocks_per_group(super_block), block_count(super_block));
    for (int block = first_block; block < last_block; ++block)
    {
      if (is_journal(block))
	continue;
      unsigned char* block_ptr = get_block(block, block_buf);
    }
  }
}
#endif

#if 1
struct Data {
 int count;
 int failures;
};

void indirect_block_action(int block_number, void* data)
{
  Data& number_of_indirect_blocks(*reinterpret_cast<Data*>(data));
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  get_block(block_number, block_buf);
  if (!is_indirect_block(block_buf))
  {
    std::cout << "BLOCK " << block_number << " is an indirect block, but is_indirect_block() returns false!\n";
    ++number_of_indirect_blocks.failures;
  }
  ++number_of_indirect_blocks.count;
}

void direct_block_action(int block_number, void* data)
{
  Data& number_of_direct_blocks(*reinterpret_cast<Data*>(data));
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  get_block(block_number, block_buf);
  if (is_indirect_block(block_buf))
  {
    std::cout << "BLOCK " << block_number << " is a direct block, but is_indirect_block() returns true!\n";
    ++number_of_direct_blocks.failures;
  }
  ++number_of_direct_blocks.count;
}

void custom(void)
{
  int allocated_inode_count = 0;
  Data number_of_indirect_blocks = { 0, 0 };
  Data number_of_direct_blocks = { 0, 0 };
  // Run over all groups.
  for (int group = 0, ibase = 0; group < groups_; ++group, ibase += inodes_per_group_)
  {
    // Run over all inodes.
    for (int bit = 0, inode_number = (group == 0) ? first_inode(super_block) : ibase + 1; bit < inodes_per_group_; ++bit, ++inode_number)
    {
      // Only run over allocated inodes.
      if (!is_allocated(inode_number))
        continue;
      InodePointer inode(get_inode(inode_number));
      // Skip inodes with size 0 (whatever).
      if (inode->size() == 0)
        continue;
      // Skip symlinks.
      if (is_symlink(inode))
        continue;
      ASSERT(inode->block()[0]);
      ++allocated_inode_count;
      bool corrupt_indirect_block = iterate_over_all_blocks_of(inode, inode_number, indirect_block_action, &number_of_indirect_blocks, indirect_bit, false);
      ASSERT(!corrupt_indirect_block);
      iterate_over_all_blocks_of(inode, inode_number, direct_block_action, &number_of_direct_blocks, direct_bit, false);
    }
  }
  std::cout << "allocated_inode_count = " << allocated_inode_count << std::endl;
  std::cout << "number_of_indirect_blocks = " << number_of_indirect_blocks.count << std::endl;
  std::cout << "number_of_indirect_blocks_failures = " << number_of_indirect_blocks.failures << std::endl;
  std::cout << "Percentage correct: " <<
      100.0 * ((number_of_indirect_blocks.count - number_of_indirect_blocks.failures) / number_of_indirect_blocks.count) << "%." << std::endl;
  std::cout << "number_of_direct_blocks = " << number_of_direct_blocks.count << std::endl;
  std::cout << "number_of_direct_blocks_failures = " << number_of_direct_blocks.failures << std::endl;
  std::cout << "Percentage correct: " <<
      100.0 * ((number_of_direct_blocks.count - number_of_direct_blocks.failures) / number_of_direct_blocks.count) << "%." << std::endl;
}
#endif

