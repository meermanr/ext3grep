#ifndef LOCATE_H
#define LOCATE_H

#include <string>
#include <set>

std::string parent_directory(int blocknr, std::set<std::string> const& filenames);
bool path_exists(std::string const& path);

#endif // LOCATE_H
