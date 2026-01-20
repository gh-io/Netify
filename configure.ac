# ==================================================
# Agent Gateway – GNU Autoconf Configuration
# ==================================================

AC_PREREQ([2.69])

AC_INIT(
  [Agent Gateway],
  [0.1.0],
  [https://github.com/yourname/agent-gateway/issues],
  [agent-gateway],
  [https://github.com/yourname/agent-gateway]
)

AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

# --------------------------------------------------
# Toolchain
# --------------------------------------------------
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
LT_INIT

AX_CXX_COMPILE_STDCXX_11
AS_VAR_APPEND([CXXFLAGS], [" -std=gnu++11"])

# --------------------------------------------------
# Host info (for code)
# --------------------------------------------------
AC_DEFINE_UNQUOTED([AG_HOST_CPU], ["$host_cpu"], [Target CPU])
AC_DEFINE_UNQUOTED([AG_HOST_OS],  ["$host_os"],  [Target OS])

# --------------------------------------------------
# Required libraries
# --------------------------------------------------
AC_CHECK_LIB([pthread], [pthread_create],
  [],
  [AC_MSG_ERROR([pthread is required])]
)

AC_CHECK_LIB([dl], [dlopen],
  [],
  [AC_MSG_ERROR([libdl is required])]
)

# --------------------------------------------------
# Optional Features
# --------------------------------------------------

# ---- Debug mode
AC_ARG_ENABLE([debug],
  AS_HELP_STRING([--enable-debug], [Enable debug logging]),
  [],
  [enable_debug=no]
)

AS_IF([test "x$enable_debug" = "xyes"], [
  AC_DEFINE([AG_ENABLE_DEBUG], [1], [Enable debug logging])
])

# ---- Lean mode
AC_ARG_ENABLE([lean],
  AS_HELP_STRING([--enable-lean], [Build minimal gateway]),
  [],
  [enable_lean=no]
)

AS_IF([test "x$enable_lean" = "xyes"], [
  AC_DEFINE([AG_LEAN_BUILD], [1], [Lean build])
])

# --------------------------------------------------
# Networking
# --------------------------------------------------

# ---- Unix socket
AC_ARG_ENABLE([unix-socket],
  AS_HELP_STRING([--enable-unix-socket], [Enable Unix socket IPC]),
  [],
  [enable_unix_socket=yes]
)

AS_IF([test "x$enable_unix_socket" = "xyes"], [
  AC_DEFINE([AG_ENABLE_UNIX_SOCKET], [1], [Unix socket enabled])
])

# ---- TCP/IP
AC_ARG_ENABLE([tcp],
  AS_HELP_STRING([--enable-tcp], [Enable TCP gateway]),
  [],
  [enable_tcp=yes]
)

AS_IF([test "x$enable_tcp" = "xyes"], [
  AC_DEFINE([AG_ENABLE_TCP], [1], [TCP enabled])
])

# --------------------------------------------------
# TLS (OpenSSL)
# --------------------------------------------------
AC_ARG_ENABLE([tls],
  AS_HELP_STRING([--enable-tls], [Enable TLS (OpenSSL)]),
  [],
  [enable_tls=yes]
)

AS_IF([test "x$enable_tls" = "xyes"], [
  PKG_CHECK_MODULES([OPENSSL], [openssl], [
    AC_DEFINE([AG_ENABLE_TLS], [1], [TLS enabled])
  ], [
    AC_MSG_ERROR([OpenSSL requested but not found])
  ])
])

# --------------------------------------------------
# systemd (optional)
# --------------------------------------------------
PKG_CHECK_MODULES([SYSTEMD], [systemd],
  [have_systemd=yes],
  [have_systemd=no]
)

AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$have_systemd" = "xyes"])

AS_IF([test "x$have_systemd" = "xyes"], [
  AC_DEFINE([AG_HAVE_SYSTEMD], [1], [systemd available])
])

# --------------------------------------------------
# Directories
# --------------------------------------------------

AC_ARG_WITH([rundir],
  AS_HELP_STRING([--with-rundir=DIR], [PID / runtime dir]),
  [],
  [with_rundir=$localstatedir/run/$PACKAGE_TARNAME]
)
AC_SUBST([rundir])

AC_ARG_WITH([sysconfdir-agent],
  AS_HELP_STRING([--with-sysconfdir-agent=DIR], [Config dir]),
  [],
  [with_sysconfdir_agent=$sysconfdir/$PACKAGE_TARNAME]
)
AC_SUBST([sysconfdir_agent])

# --------------------------------------------------
# Headers
# --------------------------------------------------
AC_CHECK_HEADERS([
  stdlib.h
  stdint.h
  string.h
  unistd.h
  sys/socket.h
  sys/un.h
  sys/types.h
  netinet/in.h
  arpa/inet.h
], [], AC_MSG_ERROR([Required headers missing]))

# --------------------------------------------------
# Functions
# --------------------------------------------------
AC_CHECK_FUNCS([
  socket
  bind
  listen
  accept
  select
  poll
  memset
  strdup
])

# --------------------------------------------------
# Output
# --------------------------------------------------
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  include/Makefile
  systemd/agent-gateway.service
])

AC_OUTPUT

AS_BOX([Agent Gateway v$PACKAGE_VERSION])

AC_MSG_NOTICE([Debug mode: ${enable_debug}])
AC_MSG_NOTICE([Lean build: ${enable_lean}])
AC_MSG_NOTICE([Unix socket: ${enable_unix_socket}])
AC_MSG_NOTICE([TCP support: ${enable_tcp}])
AC_MSG_NOTICE([TLS support: ${enable_tls}])
AC_MSG_NOTICE([systemd: ${have_systemd}])
AC_MSG_NOTICE([Config dir: ${sysconfdir_agent}])
AC_MSG_NOTICE([Runtime dir: ${rundir}])
