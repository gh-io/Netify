# Netify Agent Include Automake File
# Copyright (C) 2016-2022 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = nlohmann pcap-compat radix

netifyincludedir = $(includedir)/netifyd
netifyinclude_HEADERS = nd-apps.hpp nd-addr.hpp nd-base64.hpp nd-category.hpp \
	nd-config.hpp nd-conntrack.hpp nd-capture.hpp nd-capture-pcap.hpp \
	nd-capture-nfq.hpp nd-capture-tpv3.hpp nd-detection.hpp nd-dhc.hpp \
	nd-except.hpp nd-fhc.hpp nd-flow.hpp nd-flow-map.hpp nd-flow-parser.hpp \
	nd-instance.hpp nd-json.hpp nd-napi.hpp nd-ndpi.hpp nd-netlink.hpp \
	nd-plugin.hpp nd-packet.hpp nd-protos.hpp nd-risks.hpp nd-serializer.hpp \
	nd-sha1.h nd-signal.hpp nd-tls-alpn.hpp nd-thread.hpp nd-util.hpp netifyd.hpp

nlohmannincludedir = $(includedir)/netifyd/nlohmann
nlohmanninclude_HEADERS = nlohmann/json.hpp

pcapcompatincludedir = $(includedir)/netifyd/pcap-compat
pcapcompatinclude_HEADERS = pcap-compat/sll.h pcap-compat/vlan.h

radixincludedir = $(includedir)/netifyd/radix
radixinclude_HEADERS = radix/radix_tree.hpp radix/radix_tree_it.hpp \
	radix/radix_tree_node.hpp
