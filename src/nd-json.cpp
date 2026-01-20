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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <regex>

#include "nd-config.hpp"
#include "nd-json.hpp"
#include "netifyd.hpp"

void nd_json_to_string(const json &j, string &output, bool pretty) {
    output = j.dump(pretty ? ND_JSON_INDENT : -1, ' ', true,
      json::error_handler_t::replace);

    vector<pair<regex *, string> >::const_iterator i;
    for (i = ndGC.privacy_regex.begin();
         i != ndGC.privacy_regex.end();
         i++)
    {
        string result = regex_replace(output, *((*i).first),
          (*i).second);
        if (result.size()) output = result;
    }
}
