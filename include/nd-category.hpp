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

#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <unordered_set>

#include "nd-addr.hpp"

using json = nlohmann::json;
using namespace std;

#define ND_CAT_UNKNOWN 0

typedef unsigned nd_cat_id_t;

class ndCategory;

class ndCategories
{
public:
    enum Type {
        TYPE_NONE,

        TYPE_APP,
        TYPE_PROTO,

        TYPE_MAX
    };

    ndCategories();
    virtual ~ndCategories();

    bool Load(const string &filename);
    bool Load(Type type, json &jdata);
    bool Save(const string &filename);
    void Dump(Type type = TYPE_MAX);

    bool LoadDotDirectory(const string &path);

    bool IsMember(Type type, nd_cat_id_t cat_id, unsigned id);
    bool IsMember(Type type, const string &cat_tag, unsigned id);

    nd_cat_id_t Lookup(Type type, unsigned id) const;
    nd_cat_id_t LookupTag(Type type, const string &tag) const;
    nd_cat_id_t ResolveTag(Type type, unsigned id, string &tag) const;

    nd_cat_id_t LookupDotDirectory(const string &domain);
    nd_cat_id_t LookupDotDirectory(const ndAddr &addr);

protected:
    mutable mutex lock;

    typedef map<Type, ndCategory> cat_map;
    cat_map categories;

    typedef unordered_map<nd_cat_id_t, unordered_set<string>> cat_domain_map;
    cat_domain_map domains;

    bool LoadLegacy(const json &jdata);

    void ResetCategories(void);
    inline void ResetDomains(void);
    void ResetNetworks(bool free_only = true);

private:
    void *networks4, *networks6;
};

class ndCategory
{
public:
    typedef map<string, nd_cat_id_t> index_tag;
    typedef set<unsigned> set_id;
    typedef map<nd_cat_id_t, set_id> index_cat;
    typedef pair<nd_cat_id_t, set_id> index_cat_insert;

protected:
    friend class ndCategories;

    index_tag tag;
    index_cat index;

    ndCategories::Type type;
};
