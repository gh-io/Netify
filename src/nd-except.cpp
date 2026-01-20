// Netify Agent
// Copyright (C) 2023 eGloo Incorporated
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

#include <cstring>
#include <sstream>

#include "nd-except.hpp"

ndException::ndException(const string &where_arg,
  const string &what_arg) throw()
  : runtime_error(what_arg), where_arg(where_arg),
    what_arg(what_arg), message(NULL) {
    ostringstream os;
    os << where_arg << ": " << what_arg;
    message = strdup(os.str().c_str());
}

ndException::~ndException() throw() {
    if (message != NULL) free((void *)message);
}

const char *ndException::what() const throw() {
    return message;
}

ndSystemException::ndSystemException(const string &where_arg,
  const string &what_arg, int why_arg) throw()
  : runtime_error(what_arg), where_arg(where_arg),
    what_arg(what_arg), why_arg(why_arg), message(NULL) {
    ostringstream os;
    os << where_arg << ": " << what_arg << ": " << strerror(why_arg);
    message = strdup(os.str().c_str());
}

ndSystemException::~ndSystemException() throw() {
    if (message != NULL) free((void *)message);
}

const char *ndSystemException::what() const throw() {
    return message;
}
