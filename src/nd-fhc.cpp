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

// Enable flow hash cache debug logging
// #define _ND_DEBUG_FHC 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "nd-config.hpp"
#include "nd-fhc.hpp"

void ndFlowHashCache::Push(const string &lower_hash,
  const string &upper_hash) {
    lock_guard<mutex> lg(lock);

    nd_fhc_map::const_iterator i = lookup.find(lower_hash);

    if (i != lookup.end()) {
        nd_dprintf(
          "WARNING: Found existing hash in flow hash cache "
          "on push.\n");
    }
    else {
        if (lookup.size() == cache_size) {
#if _ND_DEBUG_FHC
            nd_dprintf(
              "Purging flow hash cache entries, size: "
              "%lu\n",
              lookup.size());
#endif
            for (size_t n = 0; n < cache_size / ndGC.fhc_purge_divisor;
                 n++)
            {
                pair<string, string> j = index.back();

                nd_fhc_map::iterator k = lookup.find(j.first);
                if (k == lookup.end()) {
                    nd_dprintf(
                      "WARNING: flow hash cache index not "
                      "found in "
                      "map\n");
                }
                else lookup.erase(k);

                index.pop_back();
            }
        }

        index.push_front(make_pair(lower_hash, upper_hash));
        lookup[lower_hash] = index.begin();
#if _ND_DEBUG_FHC
        nd_dprintf("Flow hash cache entries: %lu\n", lookup.size());
#endif
    }
}

bool ndFlowHashCache::Pop(const string &lower_hash,
  string &upper_hash) {
    bool found = false;

    lock_guard<mutex> lg(lock);

    nd_fhc_map::iterator i = lookup.find(lower_hash);

    if ((found = (i != lookup.end()))) {
        upper_hash = i->second->second;

        index.erase(i->second);

        index.push_front(make_pair(lower_hash, upper_hash));

        i->second = index.begin();
    }

    return found;
}

void ndFlowHashCache::Load(void) {
    string filename;

    switch (ndGC.fhc_save) {
    case ndFHC_PERSISTENT:
        filename = ndGC.path_state_persistent + ND_FLOW_HC_FILE_NAME;
        break;
    case ndFHC_VOLATILE:
        filename = ndGC.path_state_volatile + ND_FLOW_HC_FILE_NAME;
        break;
    default: return;
    }

    FILE *hf = fopen(filename.c_str(), "rb");
    if (hf != NULL) {
        do {
            string digest_lower, digest_mdata;
            uint8_t digest[SHA1_DIGEST_LENGTH * 2];

            if (fread(digest, SHA1_DIGEST_LENGTH * 2, 1, hf) != 1)
                break;

            digest_lower.assign((const char *)digest,
              SHA1_DIGEST_LENGTH);
            digest_mdata.assign(
              (const char *)&digest[SHA1_DIGEST_LENGTH],
              SHA1_DIGEST_LENGTH);

            Push(digest_lower, digest_mdata);
        }
        while (! feof(hf));

        fclose(hf);
    }

    if (index.size())
        nd_dprintf("Loaded %lu flow hash cache entries.\n",
          index.size());
}

void ndFlowHashCache::Save(void) {
    string filename;

    switch (ndGC.fhc_save) {
    case ndFHC_PERSISTENT:
        filename = ndGC.path_state_persistent + ND_FLOW_HC_FILE_NAME;
        break;
    case ndFHC_VOLATILE:
        filename = ndGC.path_state_volatile + ND_FLOW_HC_FILE_NAME;
        break;
    default: return;
    }

    FILE *hf = fopen(filename.c_str(), "wb");
    if (hf == NULL) {
        nd_printf(
          "WARNING: Error saving flow hash cache: %s: %s\n",
          filename.c_str(), strerror(errno));
        return;
    }

    nd_fhc_list::iterator i;
    for (i = index.begin(); i != index.end(); i++) {
        fwrite((*i).first.c_str(), 1, SHA1_DIGEST_LENGTH, hf);
        fwrite((*i).second.c_str(), 1, SHA1_DIGEST_LENGTH, hf);
    }
    fclose(hf);

    nd_dprintf("Saved %lu flow hash cache entries.\n",
      index.size());
}
