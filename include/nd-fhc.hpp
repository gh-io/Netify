// Netify Agent
// Copyright (C) 2015-2023 eGloo Incorporated
// <http://www.egloo.ca>
//
// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public
// License along with this program.  If not, see
// <http://www.gnu.org/licenses/>.

#pragma once

#include <list>
#include <mutex>
#include <string>
#include <unordered_map>

using namespace std;

#include "nd-util.hpp"
#include "netifyd.hpp"

// Hash cache filename
#define ND_FLOW_HC_FILE_NAME "/flow-hash-cache.dat"

typedef list<pair<string, string>> nd_fhc_list;
typedef unordered_map<string, nd_fhc_list::iterator> nd_fhc_map;

class ndFlowHashCache
{
public:
    ndFlowHashCache(size_t cache_size = ND_MAX_FHC_ENTRIES)
      : cache_size(cache_size) { }

    void Push(const string &lower_hash, const string &upper_hash);
    bool Pop(const string &lower_hash, string &upper_hash);

    void Load(void);
    void Save(void);

protected:
    mutex lock;

    size_t cache_size;
    nd_fhc_list index;
    nd_fhc_map lookup;
};
