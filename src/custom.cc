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

// The first part of this file was written and used for custom job:
// recovering emails on a 40 GB partition that had no information
// left in the journal and had been mounted for a week since the deletion.
// In the end, 85% of the emails were recovered.
//
// The second part of this file was written and used for another
// custom job: recovering a vmware flat file of 322 GB.
// In the end, 100% was recovered.

bool is_double_indirect_block(unsigned char* block_ptr)
{
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  std::cout << "Calling is_indirect_block(*)..." << std::endl;
  if (!is_indirect_block(block_ptr), true)
    return false;
  uint32_t* p = reinterpret_cast<uint32_t*>(block_ptr);
  do
  {
    unsigned char* indirect_block_ptr = get_block(*p, block_buf);
    std::cout << "Calling is_indirect_block(" << *p << ")..." << std::endl;
    std::cout << "Group: " << block_to_group(super_block, *p) << "; block: " << *p << std::endl;
    if (!is_indirect_block(indirect_block_ptr), true)
      return false;
  }
  while (*++p);
  return true;
}

bool is_tripple_indirect_block(unsigned char* block_ptr)
{
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  std::cout << "Calling is_indirect_block(*)..." << std::endl;
  if (!is_indirect_block(block_ptr), true)
    return false;
  uint32_t* p = reinterpret_cast<uint32_t*>(block_ptr);
  bool res = true;
  do
  {
    unsigned char* indirect_block_ptr = get_block(*p, block_buf);
    std::cout << "Calling is_double_indirect_block(" << *p << ")..." << std::endl;
    std::cout << "Group: " << block_to_group(super_block, *p) << "; block: " << *p << std::endl;
    if (!is_double_indirect_block(indirect_block_ptr))
    {
      res = false;
      std::cout << "FAILED! But continue anyway..." << std::endl;
      //return false;
    }
  }
  while (*++p);
  return res;
}

#if 0

// This must be set to the full email address (I obfuscated it before
// committing this to SVN for obvious reasons).
#define EMAILADDRESS "g@f"

uint32_t wbblocks[] = {
  // Delivered-To:
  131961, 132587, 132598, 132599, 132600, 132601, 132602, 132603,
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
  137631, 137638, 139352, 139353, 139354, 139357, 139360, 139361,
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
  162057, 162059, 162075, 162077, 162079, 504599, 519014, 519211,
  519423, 519858, 519919, 520076, 520126, 520909, 521778, 524033, 524100,
  524236, 527110, 4784662, 4784670, 4784746, 4784758, 4784760, 4784763,
  4784771, 4784789, 4784832, 4784835, 4785360, 4786179, 4786198,
  4786201, 4786205, 4786206, 4786209, 4786244, 4786245, 4786246,
  4786247, 4786252, 4786253, 4786256, 4786257, 4786258, 4786259, 4786260,
  4786261, 4786262, 4786267, 4786268, 4786269, 4786270, 4786275, 4786287,
  4788235, 4788238, 4788240, 4788243, 4788627, 4788628,
  4788852, 4788858, 4788860, 4788861, 4788862, 4788863,
  4788865, 4788867, 4788868, 4788871, 4788873, 4788874, 4788875, 4788887,
  4788890, 4788891, 4788892, 4788893, 4788895, 4788896, 4788897, 4788898,
  4788900, 4788901, 4788902, 4788903, 4788905, 4788906, 4790298, 4790320,
  4790323, 4790338, 4790352, 4790421, 4790422, 4790426, 4790432,
  4790469, 4790470, 4790471, 4790481, 4790658, 4791131, 4791136, 4791138,
  4791139, 4791140, 4791263, 4791270, 4791272, 4791285, 4791286, 4791305,
  4791306, 4791307, 4791308, 4791344, 4791345, 4791352, 4791354, 4791367,
  4791368, 4791369, 4791375, 4791376, 4791377, 4791378, 4791397, 4791398,
  4791399, 4791400, 4791401, 4791407, 4791421, 4791437, 4792326,
  4792347, 4792384, 4792390, 4792392, 4792403, 4792441, 4792493,
  4792494, 4792495, 4792496, 4792497, 4792498, 4792504, 4792505, 4792580,
  4792583, 4792585, 4792593, 4792623, 4792626, 4792897, 4793539,
  4794368, 4794370, 4794376, 4794392, 4794403, 4794753, 4794754, 4794787,
  4794788, 4794789, 4794794, 4794796, 4794798, 4794859, 4794861, 4794862,
  4794864, 4794865, 4794866, 4794867, 4794868, 4794869, 4794871, 4794874,
  4794875, 4794876, 4794877, 4794878, 4794879, 4794880, 4794906, 4794908,
  4794914, 4796522, 4796550, 4796551, 4796556, 4796560, 4796570,
  4796592, 4796875, 4796955, 4796958, 4797450, 4798479, 4798481,
  4798491, 4798515, 4798518, 4799123, 4799600, 4799603, 4799621, 4799625,
  4799626, 4799628, 4799629, 4799635, 4799638, 4799639, 4799640, 4799642,
  4799647, 4799648, 4799649, 4799656, 4799667, 4799668, 4799669, 4799670,
  4799681, 4799684, 4799685, 4799686, 4800725, 4800728, 4800729, 4800751,
  4800755, 4800756, 4800758, 4800760, 4800761, 4800762, 4800763, 4800764,
  4800765, 4800766, 4800767, 4800768, 4800769, 4800770, 4800772,
  4800773, 4800774, 4800775, 4800776, 4800777, 4800778, 4800779, 4800782,
  4800783, 4800794, 4801101, 4801106, 4801108, 4801118, 4801132, 4802560,
  4802696, 4802699, 4802789, 4802790, 4802791, 4802794, 4802798, 4802818,
  4802820, 4802821, 4802991, 4804618, 4804623, 4804642,
  4804652, 4804783, 4804784, 4804794, 4804807, 4804930, 4805511, 4805945,
  4805946, 4805947, 4806662, 4806680, 4806723, 4806724, 4806739, 4806784,
  4806786, 4806792, 4806796, 4806797, 4806798, 4806799, 4806800, 4806802,
  4806803, 4806804, 4806805, 4806807, 4808748, 4808752,
  4808753, 4808757, 4808762, 4808763, 4808764, 4808767, 4808771, 4808773,
  4808774, 4808775, 4808776, 4808777, 4808779, 4808780, 4808781, 4808782,
  4808784, 4808787, 4808788, 4808789, 4808790, 4808791, 4808792, 4808793,
  4808794, 4808796, 4808797, 4808801, 4808802, 4808919, 4808922, 4809278,
  4809282, 4810873, 4810889, 4810891, 4810896, 4810929, 4810930, 4810946,
  4810951, 4810958, 4810970, 4810973, 4811005, 4811006, 4811011, 4811012,
  4811016, 4811018, 4811019, 4811020, 4811038, 4811056, 4811057, 4811058,
  4811060, 4811061, 4811077, 4811078, 4811081, 4811082, 4811083, 4811084,
  4811534, 4811573, 4811633, 4811639, 4811805, 4811811, 4811815,
  4811827, 4812355, 4812364, 4812808, 4812811, 4812910, 4812911, 4812934,
  4812936, 4812945, 4813122, 4813455, 4813524, 4814047, 4814049,
  4814051, 4814052, 4814054, 4814058, 4814059, 4814060, 4814061, 4814062,
  4814063, 4814064, 4814067, 4814068, 4814070, 4814071, 4814072, 4814073,
  4814079, 4814085, 4814479, 4814893, 4814900, 4814901, 4814902,
  4814903, 4814907, 4814941, 4815767, 4815777, 4815778, 4815779, 4815780,
  4815781, 4995757, 4998221, 5001702, 5001707, 5007956, 5011543,
  5247648, 5251712, 5259945, 5261346, 5268196, 5274299, 6141983, 7444886,
  7502539,
  // SquirrelMail authenticated:
  131690, 131757, 131811, 131813, 131816, 131820, 131821, 131822, 131962,
  131980, 132568, 132572, 132573, 132575, 132578, 132583, 132585, 132586,
  132750, 133125, 133132, 133136, 133145, 133147, 133405, 133445, 133450,
  133463, 133483, 133484, 133486, 133488, 133525, 133545, 134368, 134402,
  134405, 134406, 134419, 134420, 134423, 134439, 134954, 135212, 135214,
  135216, 135237, 135281, 135819, 137547, 137550, 137558, 137559, 137604,
  137637, 138479, 138515, 138564, 138600, 138604, 138714, 138731, 139269,
  139270, 139271, 139276, 139278, 139620, 139621, 139635, 139638, 139648,
  140297, 143437, 143438, 143439, 143440, 143442, 143444, 143445, 143446,
  143448, 143579, 143601, 143603, 143604, 143605, 143606, 143607, 143608,
  143611, 143614, 143619, 143629, 143632, 143652, 143653, 143708, 143723,
  143724, 144282, 144452, 144584, 144589, 145434, 145487, 145496, 145497,
  145500, 145548, 146873, 148998, 149044, 149515, 149517, 149523, 149524,
  149525, 149529, 149530, 149532, 149538, 149541, 149542, 149546, 149547,
  149557, 149560, 150054, 150236, 150304, 150525, 150559, 151595, 151596,
  151597, 151598, 151663, 153414, 153609, 153610, 153611, 153612, 153613,
  153614, 153615, 153616, 153617, 153618, 153619, 153620, 153623, 153645,
  153651, 153656, 154340, 154345, 154346, 154407, 154558, 154806, 154810,
  155362, 156078, 156079, 156084, 156086, 156907, 156909, 156947, 157004,
  157036, 157038, 157043, 157044, 157067, 158795, 158796, 158798, 159012,
  159053, 159260, 159261, 159619, 159622, 161862, 161865, 161866, 161869,
  161934, 161948, 161970, 161975, 162125, 162960, 163079, 163113, 163114,
  163118, 163124, 163158, 163162, 163163, 163166, 163172, 163192, 163195,
  163197, 168280, 168342, 168363, 185502, 504510, 4786178, 4786242, 4788242,
  4788624, 4788849, 4788850, 4790358, 4792327, 4792389, 4793537, 4794919,
  4798482, 4800771, 4804621, 4804651, 4807173, 4808747, 4811600, 4812944,
  4814856, 5013485
};

struct block_size_pairs_st {
  uint32_t block_number;
  size_t size;
};

// This data was extracted from remaining directory blocks containing
// dir entries with inodes that were deleted in the interval where
// the missing files were deleted (the interval being determined
// statistically by looking at group/size matches for small files).
// The file names in those directory blocks contained both, the
// time at which they were created as well as the size of the file.
// The size of the file was then determined by matching the given
// creation time with the 'Received:' header line in the emails.
// See work.log2 for a full description.
int const block_size_pairs_size = 94;
block_size_pairs_st block_size_pairs[block_size_pairs_size] = {
  { 133520, 5746 },
  { 135220, 5782 },
  { 135225, 4706 },
  { 137631, 10012 },
  { 137638, 32718 },
  { 143762, 27720 },
  { 143769, 12721 },
  { 143781, 4478 },
  { 143783, 4440 },
  { 149573, 5745 },
  { 153637, 4302397 },
  { 154270, 140427 },
  { 154843, 18110 },
  { 154854, 4316909 },
  { 4784760, 838866 },
  { 4784771, 13350 },
  { 4784789, 9698 },
  { 4784835, 151939 },
  { 4786179, 13067 },
  { 4786206, 46274 },
  { 4786209, 92893 },
  { 4786242, 4629 },
  { 4786275, 6337 },
  { 4788238, 6531 },
  { 4788240, 4307 },
  { 4788243, 1516073 },
  { 4788627, 5751 },
  { 4788628, 882212 },
  { 4788850, 6958 },
  { 4788852, 9725 },
  { 4790323, 53155 },
  { 4790338, 9737514 },
  { 4790358, 37408 },
  { 4790358, 37662 },
  { 4790432, 27720 },
  { 4791140, 112024 },
  { 4792347, 34161 },
  { 4792384, 19492 },
  { 4792390, 7509 },
  { 4792403, 4127 },
  { 4792441, 14684 },
  { 4792623, 8979 },
  { 4792626, 98247 },
  { 4794376, 5745 },
  { 4794914, 18909 },
  { 4794919, 4197 },
  { 4796875, 219680 },
  { 4796958, 1515670 },
  { 4798491, 1488414 },
  { 4799600, 6602 },
  { 4799603, 49768 },
  { 4799621, 6409 },
  { 4800751, 7756 },
  { 4800773, 259336 },
  { 4802798, 76966 },
  { 4802818, 32372 },
  { 4802991, 6257548 },
  { 4804623, 4101 },
  { 4804642, 74611 },
  { 4804807, 398680 },
  { 4804930, 5112 },
  { 4805511, 14272 },
  { 4806739, 6508 },
  { 4806784, 4486 },
  { 4806786, 6727 },
  { 4806792, 12438 },
  { 4806805, 7652 },
  { 4806807, 6825 },
  { 4807173, 22041 },
  { 4808753, 11521 },
  { 4808801, 64046 },
  { 4808802, 14917 },
  { 4808922, 1413362 },
  { 4810930, 27575 },
  { 4810946, 39669 },
  { 4811573, 8959 },
  { 4811600, 34322 },
  { 4811600, 34577 },
  { 4811633, 39784 },
  { 4811639, 35141 },
  { 4811805, 8400 },
  { 4811811, 7753 },
  { 4812945, 2814448 },
  { 4814047, 4274 },
  { 4814479, 5252 },
  { 4814901, 3433765 },
  { 4814903, 5798 },
  { 4814907, 19876 },
  { 4814941, 57078 },
  { 4995757, 4671 },
  { 5011543, 2492287 },
  { 5251712, 283591 },
  { 5261346, 267621 },
  { 6141983, 2494271 }
};

struct Data {
  bool one_block;		// Set if the block ends on zeroes.
  bool sent;			// Set if the headers have a line containing "SquirrelMail authenticated user EMAILADDRESS".
  bool received;		// Set if the block has a line ""
  bool headers;			// Set if the block contains all the headers.
  std::string boundary;		// Set to the boundary string if any exists in the headers in the first block.
  bool multipart_match;		// Set if a boundary string was found and it matched the last non-empty line in the last block.
  std::vector<size_t> size;	// Possible sizes as per block_size_pairs.
  size_t recovered_size;	// Number of bytes that were recovered.

  Data(void) : one_block(false), sent(false), received(false), headers(false), multipart_match(false), recovered_size(0) { }
};

unsigned int const number_of_start_blocks = sizeof(wbblocks)/sizeof(uint32_t);
Data data[number_of_start_blocks];

void create_directory(std::string const& dirname)
{
  struct stat buf;
  int res = stat(dirname.c_str(), &buf);
  if (res == -1 && errno != ENOENT)
  {
    perror("stat");
    exit(EXIT_FAILURE);
  }
  if (res == -1 && errno == ENOENT)
  {
    if (mkdir(dirname.c_str(), 0750) == -1)
    {
      perror("mkdir");
      exit(EXIT_FAILURE);
    }
  }
  else if (!S_ISDIR(buf.st_mode))
  {
    std::cerr << dirname << " exists and is not a directory.\n";
    exit(EXIT_FAILURE);
  }
}

struct BlockInfo {
  uint32_t next_block;		// Set to non-zero if known to be the next block of the email.
  bool known_not_contiguous;	// Set if it is known that the next block on disk is not the next block of the email.
  int search_depth;		// Set to the number of block directly following the last block that were checked.

  BlockInfo(uint32_t next_block_, bool known_not_contiguous_, int search_depth_) :
      next_block(next_block_), known_not_contiguous(known_not_contiguous_), search_depth(search_depth_) { }
};

typedef std::map<uint32_t, BlockInfo> block_info_map_type;
block_info_map_type block_info_map;

void load_block_info_map(void)
{
  std::ifstream file;
  file.open("block_info_map");
  uint32_t blocknr;
  uint32_t next_block;
  bool known_not_contiguous;
  int search_depth;
  while (file >> blocknr >> next_block >> known_not_contiguous >> search_depth)
  {
    block_info_map.insert(block_info_map_type::value_type(blocknr, BlockInfo(next_block, known_not_contiguous, search_depth)));
  }
}

void save_block_info_map(void)
{
  std::ofstream file;
  file.open("block_info_map_out");
  for (block_info_map_type::iterator iter = block_info_map.begin(); iter != block_info_map.end(); ++iter)
    file << iter->first << ' ' << iter->second.next_block << ' ' << iter->second.known_not_contiguous << ' ' << iter->second.search_depth << '\n';
}

int get_block_size(unsigned char* block_ptr)
{
  int size = block_size_;
  for (unsigned int j = block_size_ - 1; j > 0; --j)
  {
    if (block_ptr[j] != 0)
    {
      size = j + 1;
      break;
    }
  }
  return size;
}

enum answer_t {
  contiguous,
  not_contiguous,
  unclear
};

class FileBlock {
  private:
    int M_current_block_number;
    int M_current_block_count;
    int M_indirect_index;
    int M_double_index;
    int M_tripple_index;
    uint32_t M_indirect_block_buf[EXT3_MAX_BLOCK_SIZE / sizeof(uint32_t)];
    uint32_t M_double_indirect_block_buf[EXT3_MAX_BLOCK_SIZE / sizeof(uint32_t)];
    uint32_t M_tripple_indirect_block_buf[EXT3_MAX_BLOCK_SIZE / sizeof(uint32_t)];
    bool M_known_not_contiguous;

  public:
    FileBlock(int current_block_number) :
	M_current_block_number(current_block_number), M_current_block_count(1),
	M_indirect_index(-1), M_double_index(-1), M_tripple_index(-1), M_known_not_contiguous(false) { }

    bool next(void);
    int current_block_number(void) const { return M_current_block_number; }
    bool known_not_contiguous(void) const { return M_known_not_contiguous; }

  private:
    answer_t human_verification(int next_block, bool first_indirect_block);
};

answer_t FileBlock::human_verification(int next_block, bool first_indirect_block)
{
  int const max_search_depth = 10;
  block_info_map_type::iterator iter = block_info_map.find(M_current_block_number);
  if (iter != block_info_map.end())	// Block already known from previous session?
  {
    if (iter->second.next_block)
    {
      M_current_block_number = iter->second.next_block;
      return contiguous;
    }
    if (iter->second.known_not_contiguous &&
        (first_indirect_block || iter->second.search_depth >= max_search_depth))
    {
      M_known_not_contiguous = true;
      return not_contiguous;
    }
  }
  unsigned char block_buf1[EXT3_MAX_BLOCK_SIZE];
  get_block(M_current_block_number, block_buf1);
  int prev_block = M_current_block_number;
  int search_depth = (first_indirect_block || iter == block_info_map.end()) ? 0 : iter->second.search_depth;
  std::string answer = "n";
  do
  {
    if (search_depth >= max_search_depth)
      break;
    M_current_block_number = next_block + search_depth;
    ++search_depth;
    unsigned char block_buf2[EXT3_MAX_BLOCK_SIZE];
    get_block(M_current_block_number, block_buf2);
    unsigned char* p1 = block_buf1 + block_size_;
    int newline_count = 0;
    for (--p1; newline_count < 10 && p1 >= block_buf1; --p1)
      if (*p1 == '\n')
	++newline_count;
    ++p1;
    unsigned char* p2 = block_buf2;
    for (newline_count = 0; newline_count < 10 && p2 < block_buf2 + block_size_; p2++)
      if (*p2 == '\n')
	++newline_count;
    --p2;
    std::cout << "============================================================================================================================================\n";
    std::cout << "\e[31m";
    std::cout.write((char const*)p1, block_buf1 + block_size_ - p1);
    std::cout << "\e[0m";
    for (char const* p = (char const*)block_buf2; p < (char const*)p2; ++p)
      if (std::isprint(*p) || *p == '\n')
        std::cout << *p;
      else
        std::cout << '~';
    std::cout << std::endl;
    for(;;)
    {
      std::cout << "Does this look ok? (y/n) " << std::flush;
      std::cin >> answer;
      if (answer == "y" || answer == "n" || answer == "?")
	break;
    }
    if (answer != "n")
      break;
  }
  while (!first_indirect_block);
  if (answer == "?")
  {
    if (--search_depth > 0)
      answer = "n";
  }
  if (answer == "y")
  {
    if (iter != block_info_map.end())
      block_info_map.erase(iter);
    block_info_map.insert(block_info_map_type::value_type(prev_block, BlockInfo(M_current_block_number, false, search_depth)));
    save_block_info_map();
    return contiguous;
  }
  else if (answer == "n")
  {
    if (iter != block_info_map.end())
      block_info_map.erase(iter);
    block_info_map.insert(block_info_map_type::value_type(prev_block, BlockInfo(0, true, search_depth)));
    M_known_not_contiguous = true;
    save_block_info_map();
    return not_contiguous;
  }
  return unclear;
}

bool FileBlock::next(void)
{
  bool find_next_indirect_block = false;
  ++M_current_block_count;
  if (M_current_block_count < 13)
  {
    answer_t answer = human_verification(M_current_block_number + 1, false);	// Assume first 12 blocks are contiguous.
    if (answer == not_contiguous)
    {
      M_known_not_contiguous = true;
      return false;
    }
  }
  else if (M_current_block_count == 13)
    find_next_indirect_block = true;
  else
  {
    for (;;)	// So we can use break.
    {
      ++M_indirect_index;
      if (M_indirect_index < 1024)
	M_current_block_number = M_indirect_block_buf[M_indirect_index];
      if (M_indirect_index == 1024 || !M_current_block_number)
      {
	if (M_double_index == -1)
	{
	  find_next_indirect_block = true;
	  break;
	}
	++M_double_index;
	if (M_double_index < 1024)
	  M_current_block_number = M_double_indirect_block_buf[M_double_index];
	if (M_double_index == 1024 || !M_current_block_number)
	{
	  if (M_tripple_index == -1)
	  {
	    find_next_indirect_block = true;
	    break;
	  }
	  ++M_tripple_index;
	  if (M_tripple_index < 1024)
	    M_current_block_number = M_tripple_indirect_block_buf[M_tripple_index];
	  if (M_tripple_index == 1024 || !M_current_block_number)
	    return false;
	  get_block(M_current_block_number, (unsigned char*)M_double_indirect_block_buf);
	  M_double_index = 0;
	  M_current_block_number = M_double_indirect_block_buf[M_double_index];
	  if (!M_current_block_number)
	    return false;
	}
	get_block(M_current_block_number, (unsigned char*)M_indirect_block_buf);
	M_indirect_index = 0;
	M_current_block_number = M_indirect_block_buf[M_indirect_index];
	if (!M_current_block_number)
	  return false;
      }
    }
  }
  if (find_next_indirect_block)
  {
    int old_current_block_number = M_current_block_number;
    ++M_current_block_number;			// Assume indirect block follows directly.
    get_block(M_current_block_number, (unsigned char*)M_indirect_block_buf);
    if (!is_indirect_block((unsigned char*)M_indirect_block_buf))
    {
      M_known_not_contiguous = true;
      return false;				// Failure.
    }
    if (is_tripple_indirect_block((unsigned char*)M_indirect_block_buf))
    {
      std::memcpy(M_tripple_indirect_block_buf, M_indirect_block_buf, block_size_);
      M_tripple_index = 0;
      M_current_block_number = M_tripple_indirect_block_buf[M_tripple_index];
      get_block(M_current_block_number, (unsigned char*)M_double_indirect_block_buf);
      M_double_index = 0;
      M_current_block_number = M_double_indirect_block_buf[M_double_index];
      get_block(M_current_block_number, (unsigned char*)M_indirect_block_buf);
      M_indirect_index = 0;
      M_current_block_number = M_indirect_block_buf[M_indirect_index];
    }
    else if (is_double_indirect_block((unsigned char*)M_indirect_block_buf))
    {
      std::memcpy(M_double_indirect_block_buf, M_indirect_block_buf, block_size_);
      M_double_index = 0;
      M_current_block_number = M_double_indirect_block_buf[M_double_index];
      get_block(M_current_block_number, (unsigned char*)M_indirect_block_buf);
      M_indirect_index = 0;
      M_current_block_number = M_indirect_block_buf[M_indirect_index];
    }
    else
    {
      M_indirect_index = 0;
      M_current_block_number = M_indirect_block_buf[M_indirect_index];
    }
    int next_block = M_current_block_number;
    M_current_block_number = old_current_block_number;
    answer_t answer = human_verification(next_block, true);
    if (answer == not_contiguous)
    {
      M_known_not_contiguous = true;
      return false;
    }
  }
  return true;
}

bool check_boundary(unsigned char* block_ptr, std::string const& boundary)
{
  // This one crosses a block boundary; I manually verified it.
  if (boundary == "----_=_NextPart_001_01C8C028.8F6267F8")
    return true;
  unsigned char* p = block_ptr + block_size_;
  while ((*--p == 0 || *p == '\n' || std::isspace(*p)) && p > block_ptr) ;
  if (p == block_ptr)
    return false;
  ++p;
  if (*p != '\n')
    return false;
  unsigned char* end = p;
  while (*--p != '\n' && p > block_ptr) ;
  if (p == block_ptr)
    return false;
  ++p;
  return ("--" + boundary + "--") == std::string((char const*)p, end - p);
}

void custom(void)
{
  load_block_info_map();
  int one_block_count = 0;
  static unsigned char block_buf[EXT3_MAX_BLOCK_SIZE];
  // Run over all start blocks.
  for (unsigned int i = 0; i < number_of_start_blocks; ++i)
  {
    //std::cout << "BLOCK: " << wbblocks[i] << std::endl;

    // Read the start block.
    unsigned char* block_ptr = get_block(wbblocks[i], block_buf);

    // Initialize one_block.
    data[i].one_block = (block_ptr[block_size_ - 1] == 0);
    if (data[i].one_block)
    {
      ++one_block_count;
      data[i].size.push_back(get_block_size(block_ptr));
    }

    // Search the headers.
    unsigned char* p = block_ptr;
    for (int line_count = 0;; ++line_count)
    {
      std::string::size_type boundary_pos;
      unsigned char c;
      std::string str;
      do
      {
        c = *p++;
	ASSERT(c != 0);
	str += c;
      }
      while (c != '\n' && p < &block_ptr[block_size_]);
      if (c != '\n')
        break;			// Not all headers fit in the first block.
      if (str.size() == 1)
      {
        data[i].headers = true;
        break;
      }
      else if (str.find("SquirrelMail authenticated user " EMAILADDRESS) != std::string::npos)
      {
        data[i].sent = true;
	data[i].received = false;
      }
      else if (str.substr(0, 13) == "Delivered-To:")
      {
        ASSERT(!data[i].sent);
        data[i].received = true;
      }
      else if ((boundary_pos = str.find("boundary=")) != std::string::npos && str[boundary_pos - 1] != '_')
      {
        std::string::size_type first = boundary_pos + 9 + ((str[boundary_pos + 9] == '"') ? 1 : 0);
	std::string::size_type len = str.find_first_of("\"\n", first) - first;
	data[i].boundary = str.substr(first, len);
      }
    }
    if (data[i].sent)
      data[i].received = false;
  }
  std::cout << "There are " << one_block_count << " emails existing of one block.\n";
  std::cout << "There are " << (number_of_start_blocks - one_block_count) << " emails existing of more than one block.\n";

  // Stats.
  int not_contiguous_count = 0;
  int found_boundary = 0;
  int found_boundary_in_known_not_contiguous = 0;

  for (unsigned int i = 0; i < number_of_start_blocks; ++i)
  {
    // Sanity checks.
    ASSERT(data[i].sent || data[i].received);
    ASSERT(!(data[i].sent && data[i].received));
    if (!data[i].headers)
      std::cout << "Block " << wbblocks[i] << " does not contain all headers.\n";
    ASSERT(!(data[i].one_block && !data[i].headers));
    ASSERT((data[i].size.empty() && !data[i].one_block) || (data[i].size.size() == 1 && data[i].size[0] < (size_t)block_size_ && data[i].one_block));

    // Fill data[i].size with possible sizes of multi-block emails.
    for (int j = 0; j < block_size_pairs_size; ++j)
      if (block_size_pairs[j].block_number == wbblocks[i])
        data[i].size.push_back(block_size_pairs[j].size);

    // Create block list.
    std::list<uint32_t> blocks;
    FileBlock file_block(wbblocks[i]);
    do
    {
      int block_number = file_block.current_block_number();
      blocks.push_back(block_number);
      unsigned char* block_ptr = get_block(block_number, block_buf);
      int size = get_block_size(block_ptr);
      data[i].recovered_size += size;
      if (size < block_size_)
      {
        if (!data[i].boundary.empty())
	  data[i].multipart_match = check_boundary(block_ptr, data[i].boundary);
        break;
      }
    }
    while(file_block.next());

    if (!data[i].boundary.empty())
    {
      ++found_boundary;
      if (file_block.known_not_contiguous())
        ++found_boundary_in_known_not_contiguous;
    }

    // Create file name.
    std::string filename("RECOVERED/");
    create_directory(filename);
    if (data[i].one_block)
      filename += "one_block/";
    else
    {
      filename += "multiple_blocks/";
      create_directory(filename);
      if (!data[i].boundary.empty())
      {
        if (data[i].multipart_match)
	  filename += "matched_multipart/";
	else
	  filename += "unverified_multipart/";
      }
      create_directory(filename);
      if (!data[i].size.empty())
      {
        bool size_matches = false;
        for (std::vector<size_t>::iterator iter = data[i].size.begin(); iter != data[i].size.end(); ++iter)
	{
	  if (*iter == data[i].recovered_size)
	  {
	    size_matches = true;
	    break;
	  }
	}
	if (size_matches)
	  filename += "matched_size/";
        else if (!file_block.known_not_contiguous())
	  filename += "SIZE_MISMATCH/";
      }
    }
    create_directory(filename);
    if (data[i].sent)
      filename += "sent/";
    else
      filename += "received/";
    create_directory(filename);
    if (!data[i].headers)
      filename += "not_all_headers_in_first_block/";
    create_directory(filename);
    if (file_block.known_not_contiguous())
    {
      filename += "known_not_contiguous/";
      ++not_contiguous_count;
    }
    create_directory(filename);
    std::ostringstream blocknr;
    blocknr << std::setfill('0') << std::setw(7) << wbblocks[i];
    filename += blocknr.str();

    // Write block list to file.
    std::ofstream file;
    file.open(filename.c_str());
    for (std::list<uint32_t>::iterator iter = blocks.begin(); iter != blocks.end(); ++iter)
    {
      unsigned char* block_ptr = get_block(*iter, block_buf);
      file.write((char const*)block_ptr, get_block_size(block_ptr));
    }
    file.close();
  }
  save_block_info_map();

  std::cout << "Total number of emails with a multipart boundary: " << found_boundary << '\n';
  std::cout << "Number of non-contiguous emails: " << not_contiguous_count << '\n';
  std::cout << "Number of non-contiguous emails with a multipart boundary: " << found_boundary_in_known_not_contiguous << '\n';

  std::cout << "Total number of emails recovered: " << number_of_start_blocks << '\n';
  std::cout << "Number of complete emails: " << (number_of_start_blocks - not_contiguous_count) << '\n';
  std::cout << "Percentage fully recovered: " << (100.0 * (number_of_start_blocks - not_contiguous_count) / number_of_start_blocks) << "%\n";
}
#endif

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

#if 0
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
      if (inode->size() == 0)	// Files with size 0 exist, of course.
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

//-----------------------------------------------------------------------------
//
// The code of the second custom job starts here.
//
// This code was written and used to successfully recover a 322 GB vmware file,
// containing an ext3 filesystem with all emails and websites of all clients
// of a small webhosting company. Work hours: 80. Recovery: 100%.

// This table contained blocks changed by running fsck.
int fsckd_blocks[] = {
  0 // Deleted to save space in this demonstration code.
};

union block_t {
  struct data_st {
    int file_block_offset;
    int sequence_number;
  } data;
  unsigned char raw[4096];
};
static block_t buf;

void custom_action(int block_nr, int file_block_nr, void*)
{
  static int last_file_block_nr = -1;
  if (file_block_nr != -1)
  {
    if (file_block_nr != ++last_file_block_nr)
    {
      std::cout << "SKIPPED " << (file_block_nr - last_file_block_nr) << " BLOCKS, file blocks " << last_file_block_nr << " up till and including " << (file_block_nr - 1) << "!" << std::endl;
      last_file_block_nr = file_block_nr;
    }
    get_block(block_nr, buf.raw);
    std::cout << "buf.data.file_block_offset = " << buf.data.file_block_offset << "; file_block_nr = " << file_block_nr << std::endl;
    assert(buf.data.file_block_offset == file_block_nr);
  }
  assert(block_nr);
  if (block_nr == 167575554 || (block_nr >= 167606272 && block_nr <= 167606300))
  {
    std::cout << "USING BLOCK " << block_nr << "OVERWRITTEN BY FOREMOST!" << std::endl;
    //assert(false);
  }
  for (unsigned int i = 0; i < sizeof(fsckd_blocks) / sizeof(fsckd_blocks[0]); ++i)
  {
    if (fsckd_blocks[i] == block_nr)
    {
      std::cout << "USING FSCK-ED BLOCK "<< block_nr << "!" << std::endl;
      //assert(false);
    }
  }
  std::cout << "File block nr: " << file_block_nr << "; block: " << block_nr << std::endl;
}

struct block_color {
  int blocknr;
  block_color(int bn) : blocknr(bn) { }
  friend std::ostream& operator<<(std::ostream& os, block_color const& bc)
  {
    int group = block_to_group(super_block, bc.blocknr);
    int first_block = group_to_block(super_block, group);
    int last_block = first_block + 32767;
    if ((group & 1) == 1)
      os << "\e[31m";
    else
      os << "\e[34m";
    os << bc.blocknr << "\e[0m";
    if (bc.blocknr == first_block)
      os << '^';
    else if (bc.blocknr == last_block)
      os << '$';
    return os;
  }
};

class Range {
  private:
    bool first;
    int last_blocknr;
    int current_begin;
    std::vector<std::pair<int, int> > v;

  public:
    Range(void) : first(true) { }

    Range& operator+=(int blocknr)
    {
      if (first)
      {
	first = false;
	current_begin = blocknr;
      }
      else
      {
	assert(blocknr > last_blocknr);
        if (blocknr != last_blocknr + 1)
	{
	  v.push_back(std::pair<int, int>(current_begin, last_blocknr));
	  current_begin = blocknr;
	}
      }
      last_blocknr = blocknr;
      return *this;
    }

    friend std::ostream& operator<<(std::ostream& os, Range const& range)
    {
      for (std::vector<std::pair<int, int> >::const_iterator iter = range.v.begin(); iter != range.v.end(); ++iter)
	if (iter->first != iter->second)
	  os << '[' << block_color(iter->first) << " - " << block_color(iter->second) <<
	      " (" << (iter->second - iter->first + 1) << ")]";
        else
	  os << '[' << block_color(iter->first) << ']';
      if (!range.first)
      {
	if (range.current_begin != range.last_blocknr)
	  os << '[' << block_color(range.current_begin) << " - " << block_color(range.last_blocknr) <<
	      " (" << (range.last_blocknr - range.current_begin + 1) << ")]";
        else
	  os << '[' << block_color(range.current_begin) << ']';
      }
      return os;
    }
};

bool has_at_least_n_increasing_block_numbers(int n, unsigned char* block_buf)
{
  __le32* p = reinterpret_cast<__le32*>(block_buf);
  __le32 last_block = 0;
  int total = 0;
  for (int i = 0; i < 1024; ++i)
  {
    if (p[i])
    {
      if (p[i] < last_block)
	return false;
      if (p[i] == last_block + 1)
	++total;
      last_block = p[i];
    }
  }
  return total >= n;
}

// This function guesses what is the first valid Indirect Block in group 'group'.
// Later I found a smarter way to do this by looking at the block bitmap updates
// in the journal-- but this worked too.
int first_indirect_block(int group, size_t& size)
{
  std::cout << "Entering first_indirect_block(" << group << ")\n";
  static unsigned char block_buf[4096];
  int first_block = group_to_block(super_block, group);
  std::cout << "first_block = " << first_block << '\n';
  int group_end = first_block + blocks_per_group(super_block);
  std::cout << "group_end = " << group_end << '\n';
  int freq[1025];
  std::memset(freq, 0, sizeof(freq));
  for (int b = first_block; b < group_end; ++b)
  {
    get_block(b, block_buf);
    if (is_indirect_block(block_buf) && has_at_least_n_increasing_block_numbers(32, block_buf))
    {
      //std::cout << "Found indirect block at " << b << '\n';
      freq[(b - first_block - 514) % 1025] += 1;	// 514 = bitmaps + inode table. 1025 = indirect block + its 1024 data blocks.
    }
  }
  int best = 0;
  int fbest = 0;
  int total = 0;
  std::vector<std::pair<int, int> > candidates;
  for (int i = 0; i < 1025; ++i)
  {
    if (freq[i])
    {
      if (freq[i] > 1)
      {
	std::cout << i << " (" << freq[i] << "), ";
	candidates.push_back(std::pair<int, int>(i, freq[i]));
      }
      total += freq[i];
      if (freq[i] > fbest)
      {
	fbest = freq[i];
	best = i;
      }
    }
  }
  std::cout << '\n';
  std::cout << '\t' << "total: " << total << std::endl;
  assert(!candidates.empty());
  size = candidates.size();
  if (size > 2)
  {
    std::cout << "FAILURE FOR GROUP " << group << ": indirect blocks are scattered! Returning -1.\n";
    return -1;
  }
  if (size == 2)
  {
    int jump = 1;
    if (group == 5146)
      jump = 2;	// Special case, because this group contains the double indirect block.
    int diff = candidates[1].first - candidates[0].first;
    int sum = fbest;
    if (diff == jump)
    {
      std::cout << "Choosing smallest of two\n";
      best = candidates[0].first;
      sum = candidates[0].second + candidates[1].second;
    }
    if (sum < 30)
    {
      std::cout << "WARNING: LOW INDIRECT BLOCK COUNT! There is a not insignificant chance that the heuristics fail in this case!\n";
    }
  }
  else if (best > 0 && freq[best - 1] == 1)
  {
    size_t prev_size;
    int prev_first_indirect_block = first_indirect_block(group - 1, prev_size);
    // Turn it into the real block number.
    prev_first_indirect_block += group_to_block(super_block, group - 1) + 514;
    // Do the same for 'best - 1'.
    int next_first_indirect_block = group_to_block(super_block, group) + 514 + best - 1;
    // Use this heuristic magical formula to test if it's likely that in fact
    // we have a pair with sizes (1, 30).
    if ((prev_first_indirect_block + 520) % 1025 == next_first_indirect_block % 1025 && prev_size == 1)
    {
      std::cout << "Decrementing best!\n";
      --best;
    }
  }
  std::cout << "Leaving first_indirect_block() (returning " << best << ")\n";
  return best;
}

int first_indirect_block(int group)
{
  size_t dummy;
  return first_indirect_block(group, dummy);
}

int fib_table1[] = {
  190, 742, 269, 821, 348, 900, 427, 979, 506, 33, 585, 112, 664, 191, 743, 270,
  // ... lots of numbers deleted to save space in the demonstration code.
  456, 1008, 535, 62
};

// WARNING: This table was HAND EDITTED (after generation).
int fib_table2[] = {
  570, 91, 644, 170, 722, 248, 800, 321, 873, 400, 952, 479, 6, 558, 85, 637,
  // ... lots of numbers deleted to save space in the demonstration code.
  198, 750, 277, 829, 356, 908, 435, 987, 514, 41, 593, 120, 672
};

// Manually recovered Tripple Indirect Block.
int tib_table[] = {
  168649904, 169716665, 170782906, 171849661, 172915902, 173982663, 175049424, 176115659,
  177182420, 178248661, 179315416, 180381657, 181448418, 182514659, 117359, 1189230,
  2256495, 3324280, 4392059, 5458300, 6525061, 7591302, 8659087, 9725322,
  30015342, 31082103, 32151318, 33217553, 34284314, 35350549, 36417310, 37483551,
  38550306, 39617067, 40683308, 41750069, 42816304, 43883065, 44949306, 46016067,
  47082302, 48149063, 49215304, 50282065, 51348820, 52415061, 53481822, 54548057,
  55614818, 56681059, 57747820, 58814061, 59880816, 60947057, 62013818, 63080573,
  64146814, 65213575, 66279816, 67346571, 68412812, 69479573, 70545808, 71612569,
  72680349, 73746590, 74813351, 75879586, 76946347, 78012588, 79080373, 80146614,
  81213375, 82279616
};

__le32 const dib_169716665[/*1024*/] = {
  /* 1024 block numbers deleted to save space */
};

__le32 const dib_39617067[/*1024*/] = {
  /* 1024 block numbers deleted to save space */
};

__le32 const dib_49215304[/*1024*/] = {
  /* 1024 block numbers deleted to save space */
};

__le32 const dib_56681059[/*1024*/] = {
  /* 1024 block numbers deleted to save space */
};

__le32 const dib_66279816[/*1024*/] = {
  /* 1024 block numbers deleted to save space */
};

// The function 'first_indirect_block' is rather slow.
// Therefore it was once used to generate fib_table1 and fib_table2,
// and this function uses the table.
int first_indirect_block_table(int group)
{
  if (5147 <= group && group <= 5598)
    return fib_table1[group - 5147];
  else if (2 <= group && group <= 2510)
  {
    int res = fib_table2[group - 2];
    if (res == -1)
    {
      std::cout << "FAILURE for group " << group << "\n\t";
      first_indirect_block(group);
      std::cout << std::endl;
    }
    assert(res != -1);
    return res;
  }

  int res = first_indirect_block(group);
  std::cout << "MISSING: first_indirect_block_table(" << group << ") = " << res << std::endl;
  assert(res != -1);
  return res;
}

// Given the block number of an (single) 'Indirect Block', return the next Indirect block
// using the following heuristics: The next indirect block immediately follows the
// last data block, which all immediately followed the last Indirect block; hence:
// the next Indirect block is the current one plus 1025, UNLESS we reach the end
// of a group. Then the next indirect block is retrieved from a table, which was
// generated by determining what was the statistically most likely offset of such
// equally spaced indirect blocks in the next group.
__le32 next_indirect_block(__le32 current_indirect_block, bool need_restoring)
{
  // Special cases that the heuristics fail for:
  if (current_indirect_block == 183467615)
    return 183469160;
  if (current_indirect_block == 183499910)
    return 36375;
  if (current_indirect_block == 10517828)
    return 10519373;
  if (current_indirect_block == 10523473)
    return 10537013;
  if (current_indirect_block == 10537013)
    return 29726800;
  if (current_indirect_block == 29754995)
    return 29778002;
  if (current_indirect_block == 32048904)
    return 32052383;
  int current_group = block_to_group(super_block, current_indirect_block);
  int next_group = block_to_group(super_block, current_indirect_block + 1025);
  if (current_group != next_group)
  {
    int group_start = group_to_block(super_block, current_group);
    int group_end = group_start + blocks_per_group(super_block);
    int left = group_end - current_indirect_block - 1;
    std::cout << "left = " << left << std::endl;

    int next_group_start = group_to_block(super_block, next_group);
    std::cout << "next_group_start = " << next_group_start << std::endl;
    int fib = need_restoring ? first_indirect_block(next_group) : first_indirect_block_table(next_group);
    std::cout << "Returning " << next_group_start + fib + 514 << std::endl;
    return next_group_start + fib + 514;
  }
  return current_indirect_block + 1025;
}

// Return true if this block is wiped (contains only zeroes).
bool all_zeroes(__le32* indirect_block_buf)
{
  for(int i = 0; i < 1024; ++i)
  {
    if (indirect_block_buf[i])
      return false;
  }
  return true;
}

// Retriece a Double Indirect Block.
void get_dib(int block_number, __le32* buf)
{
  // These blocks were wiped during deletion.
  if (block_number == 169716665)
    memcpy(buf, dib_169716665, sizeof(dib_169716665));
  else if (block_number == 39617067)
    memcpy(buf, dib_39617067, sizeof(dib_39617067));
  else if (block_number == 49215304)
    memcpy(buf, dib_49215304, sizeof(dib_49215304));
  else if (block_number == 56681059)
    memcpy(buf, dib_56681059, sizeof(dib_56681059));
  else if (block_number == 66279816)
    memcpy(buf, dib_66279816, sizeof(dib_66279816));
  else
  // The rest is still intact.
    get_block(block_number, (unsigned char*)buf);
}

void generate_sib(int sib_number, __le32* buf, __le32 next_indirect_block)
{
  int sib_group = block_to_group(super_block, sib_number);
  int next_group_start = group_to_block(super_block, sib_group + 1);
  if (sib_group == 5599)		// Last group?
    next_group_start = 183500446;	// Byte-past-the-end in this group (fake a new group start).
  int block_number = sib_number;
  for (int k = 0; k < 1024; ++k)
  {
    ++block_number;
    if (block_number == next_group_start)
    {
      int next_block_number = next_indirect_block - (1024 - k);
#if 0	// Not a gamble anymore. See skip6check.
      if (sib_number == 183499910)	// The only special case (manualy checked to be ok too)
      {
      std::cout << "Gambling that data block " << next_block_number << " follows " << (block_number - 1) << std::endl;
      int group = block_to_group(super_block, next_block_number);
      int next_group_start = group_to_block(super_block, group);
      std::cout << "  number of skipped blocks at the start of group " << group << ": " << (next_block_number - next_group_start - 514) << std::endl;
      }
#endif
      block_number = next_block_number;
    }
    buf[k] = block_number;
  }
}

// This function retrieves a Single (normal) Indirect Block 'block_number').
void get_sib(int block_number, __le32* buf, __le32 next_indirect_block)
{
  // These blocks were wiped during deletion.
  if (block_number == 169868396 || block_number == 181632444 || block_number == 183499910 || block_number == 1900225 ||
      block_number == 3801011 || block_number == 5668471 || block_number == 34111044 || block_number == 36011825 ||
      block_number == 37879292 || block_number == 39780073 || block_number == 41680859 || block_number == 43548320 ||
      block_number == 45449107 || block_number == 47316568 || block_number == 49249650 || block_number == 51117110 ||
      block_number == 53017897 || block_number == 54918678 || block_number == 56819465 || block_number == 58720251 ||
      block_number == 60620007 || block_number == 62520788 || block_number == 64421575 || block_number == 66386952 ||
      block_number == 80608995 || block_number == 82509782)
    generate_sib(block_number, buf, next_indirect_block);
  else
  // The rest is still intact.
    get_block(block_number, (unsigned char*)buf);
}

#define DO_ACTUAL_RECOVERY 0

#if DO_ACTUAL_RECOVERY
int outfd;
#endif
int count = 0;

struct timeval& operator-=(struct timeval& t1, struct timeval const& t2)
{
  t1.tv_sec -= t2.tv_sec;
  if ((t1.tv_usec -= t2.tv_usec) < 0)
  {
    t1.tv_usec += 1000000;
    --t1.tv_sec;
  }
  return t1;
}

static char const zeroes[4096] = { 0, };
struct timeval start_time;
struct timeval current_time;
int const total_blocks = 78643200;
int remaining_blocks = total_blocks;

// This function is called for every data block.
void process_data_block(int block_number)
{
#if DO_ACTUAL_RECOVERY
  assert(block_number);
  // If the block is a block that was corrupted by running 'foremost' after deletion,
  // and before umounting, then gamble it originally only contained zeroes because
  // many blocks before and after this region turn out to contain zeroes.
  if (block_number == 167575554 || (block_number >= 167606272 && block_number <= 167606300))
  {
    int len = ::write(outfd, zeroes, 4096);
    assert(len == 4096);
  }
  else
  {
    static unsigned char block_buf[4096];
    get_block(block_number, block_buf);
    int len = ::write(outfd, (char*)block_buf, 4096);
    assert(len == 4096);
  }
#else
  if (block_number == 167575554 || (block_number >= 167606272 && block_number <= 167606300))
  {
    std::cout << "Using foremost block " << block_number << " at file block " << count << '\n';
  }
#endif
  ++count;
  --remaining_blocks;
  if (remaining_blocks % 10000 == 0)
  {
    gettimeofday(&current_time, NULL);
    current_time -= start_time;
    double seconds = current_time.tv_sec + current_time.tv_usec * 1e-6;
    double blocks_per_second = (total_blocks - remaining_blocks) / seconds;
    std::cout << "Speed: " << (blocks_per_second * 4.096e-3) << " MB/s. ";
    double remaining_minutes = remaining_blocks / blocks_per_second / 60;
    std::cout << "ETA: " << std::fixed << remaining_minutes << " minutes." << std::endl;
  }
}

void custom(void)
{
#if 0
  // This code was used to do many/various quick queries.
  std::cout << block_to_group(super_block, 182514659) << '\n';
  //std::cout << group_to_block(super_block, block_to_group(super_block, 2589192)) << '\n';
  //first_indirect_block(5184);
  return;
#endif
  //init_journal();
#if 1
  // This code was used to do the final recovery.
#if DO_ACTUAL_RECOVERY
  outfd = ::open("/home/carlo/RECOVERED.MOSES-DRIVE-322GB.VDMK-flat.vmdk", O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, 0644);
#endif
  gettimeofday(&start_time, NULL);
  int blocknrs[] = { 163021314, 163021315, 163021316, 163021317, 163021318, 163021319, 163054082, 163054083, 163054084, 163054085, 163054086, 163054087 };
  for (int i = 0; i < (int)(sizeof(blocknrs) / sizeof(int)); ++i)
  {
    process_data_block(blocknrs[i]);
  }
  static __le32 sib_buf[1024];
  get_block(167582637, (unsigned char*)sib_buf);
  for (int k = 0; k < 1024; ++k)
  {
    process_data_block(sib_buf[k]);
  }
  static __le32 dib_buf[1024];
  get_block(167583662, (unsigned char*)dib_buf);
  for (int i = 0; i < 1024; ++i)
  {
    assert(dib_buf[i]);
    get_block(dib_buf[i], (unsigned char*)sib_buf);
    for (int k = 0; k < 1024; ++k)
    {
      process_data_block(sib_buf[k]);
    }
  }
  for (unsigned int j = 0; j < sizeof(tib_table) / sizeof(*tib_table); ++j)
  {
    bool saw_zeroes = false;
    int block_number = tib_table[j];
    get_dib(block_number, dib_buf);
    assert(is_indirect_block((unsigned char*)dib_buf));
    for (int i = 0; i < 1024; ++i)
    {
      if (!dib_buf[i])
	continue;
      __le32 next_indirect_block;
      if (i < 1023)
	next_indirect_block = dib_buf[i + 1];
      else
	next_indirect_block = tib_table[j + 1];
      get_sib(dib_buf[i], sib_buf, next_indirect_block);
      if (all_zeroes(sib_buf))
      {
#if 0
	std::cout << block_number << " --> " << dib_buf[i] << " == ZEROES!\n";
	saw_zeroes = true;
#else
	assert(false);
#endif
      }
      else
      {
	assert(is_indirect_block((unsigned char*)sib_buf, true));
	if (sib_buf[0] != dib_buf[i] + 1)
	{
	  assert(dib_buf[i] + 1 == (__le32)group_to_block(super_block, block_to_group(super_block, sib_buf[0])));
	}
	process_data_block(sib_buf[0]);
	for (int k = 1; k < 1024; ++k)
	{
	  if (dib_buf[i] == 83344321 && sib_buf[k] == 0)
	    continue;
	  if (sib_buf[k] != sib_buf[k - 1] + 1)
	  {
	    if (sib_buf[k - 1] != (__le32)group_to_block(super_block, block_to_group(super_block, sib_buf[k])) - 1)
	    {
	      std::cout << block_number << " --> " << dib_buf[i] << " --> " << sib_buf[k] <<
		  " fails hypothesis. It is the previous entry plus " << (sib_buf[k] - sib_buf[k - 1]) << " instead of plus 1.\n";
	    }
	  }
	  process_data_block(sib_buf[k]);
	}
	if (dib_buf[i] == 83344321)
	  continue;
	if (sib_buf[1023] + 1 != next_indirect_block)
	{
	  int current_group = block_to_group(super_block, sib_buf[1023]);
	  int next_group = block_to_group(super_block, sib_buf[1023] + 1);
	  assert(current_group == next_group - 1);
	}
      }
    }
    if (!saw_zeroes)
      std::cout << block_number << " OK" << std::endl;
  }
  std::cout << "Total number of blocks: " << count << std::endl;
#if DO_ACTUAL_RECOVERY
  ::close(outfd);
#endif
#endif
#if 0
  // This code was used to see if the file that had to be recovered used sparse data
  // (zero block numbers, meaning a block with only zeroes) and whether or not
  // blocks where used that were corrupted AFTER the deletion of this file (the
  // so called 'foremost' blocks).
  Inode inode;
  int inode_nr = 34818; // 81362958
  get_undeleted_inode_type res = get_undeleted_inode(inode_nr, inode);
  //assert(res == ui_journal_inode);
  iterate_over_all_blocks_of(inode, inode_nr, custom_action, NULL, direct_bit|indirect_bit, false);
#endif
#if 0
  // This was used to create fib_table2 (and fib_table1 with different loop parameters).
  // However, fib_table2 was hand editted at a few places after that.
  std::vector<int> v;
  for (int group = 2; group <= 2510; ++group)
  {
    int res = first_indirect_block(group);
    v.push_back(res);
  }
  int count = 0;
  for (std::vector<int>::iterator iter = v.begin(); iter != v.end(); ++iter)
  {
    if (count % 16 == 0)
      std::cout << ",\n  ";
    else
      std::cout << ", ";
    std::cout << *iter;
    ++count;
  }
  std::cout << std::endl;
  return;
#endif
#if 0
  // This code either tests the heuristic code to generate double indirect blocks,
  // by comparing what it would do with the actual data of existing blocks,
  // or it generates such a block; used to generate tables dib_169716665, dib_39617067 etc.
  for (unsigned int j = 0; j < sizeof(tib_table) / sizeof(*tib_table); ++j)
  {
    int block_number = tib_table[j];
    bool need_restoring =
        (block_number == 169716665 || block_number == 39617067 || block_number == 49215304 ||
         block_number == 56681059 || block_number == 66279816);
    // Toggle this to test the heuristic code, or to generate the missing double indirect blocks.
    if (!need_restoring)
      continue;
    __le32 predicted_indirect_block = block_number + 1;
    std::cout << block_color(block_number) << ": Double indirect block.\n";
    __le32 double_block_buf[1024];
    __le32 indirect_block_buf[1024];
    get_block(block_number, (unsigned char*)double_block_buf);
    for (int i = 0; i < 1024; ++i)
    {
      if (!need_restoring || double_block_buf[i])
      {
	std::cout << '\t' << block_color(double_block_buf[i]) << ": Indirect block.\n";
	get_block(double_block_buf[i], (unsigned char*)indirect_block_buf);
	if (all_zeroes(indirect_block_buf))
	{
	  std::cout << "\t\tZEROES\n";
	  assert(double_block_buf[i] == predicted_indirect_block);
	}
	else
	{
	  assert(is_indirect_block((unsigned char*)indirect_block_buf));
	  if (double_block_buf[i] != predicted_indirect_block)
	  {
	    unsigned char buf[4096];
	    get_block(predicted_indirect_block, buf);
	    assert(!is_indirect_block(buf));
	    predicted_indirect_block += 1025;
	  }
	  assert(double_block_buf[i] == predicted_indirect_block);
	  Range range;
	  for (int j = 0; j < 1024; ++j)
	    range += indirect_block_buf[j];
	  std::cout << "\t\t" << range << '\n';
	}
      }
      else
      {
	std::cout << "\tPredicted indirect block: " << predicted_indirect_block << '\n';
	get_block(predicted_indirect_block, (unsigned char*)indirect_block_buf);
	if (all_zeroes(indirect_block_buf))
	{
	  std::cout << "\t\tZEROES\n";
	}
	else
	{
	  assert(is_indirect_block((unsigned char*)indirect_block_buf));
	}
      }
      predicted_indirect_block = next_indirect_block(predicted_indirect_block, need_restoring);
    }
  }
#endif
}

