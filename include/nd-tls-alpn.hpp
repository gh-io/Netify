// Auto-generated, update with ./util/generate-alpn-include.sh

#pragma once

#include "nd-protos.hpp"

typedef unordered_map<const char *, nd_proto_id_t> nd_alpn_proto_map;

const nd_alpn_proto_map nd_alpn_protos = {
    { "http/0.9" /* HTTP/0.9 */, ND_PROTO_HTTPS },
    { "http/1.0" /* HTTP/1.0 */, ND_PROTO_HTTPS },
    { "http/1.1" /* HTTP/1.1 */, ND_PROTO_HTTPS },
    { "spdy/1" /* SPDY/1 */, ND_PROTO_QUIC },
    { "spdy/2" /* SPDY/2 */, ND_PROTO_QUIC },
    { "spdy/3" /* SPDY/3 */, ND_PROTO_QUIC },
    { "stun.turn" /* Traversal Using Relays around NAT (TURN) */,
      ND_PROTO_STUN },
    { "stun.nat-discovery" /* NAT discovery using Session Traversal Utilities for NAT (STUN) */,
      ND_PROTO_STUN },
    { "h2" /* HTTP/2 over TLS */, ND_PROTO_HTTPS },
    { "h2c" /* HTTP/2 over TCP */, ND_PROTO_HTTPS },
    { "webrtc" /* WebRTC Media and Data */, ND_PROTO_TLS },
    { "c-webrtc" /* Confidential WebRTC Media and Data */, ND_PROTO_TLS },
    { "ftp" /* FTP */, ND_PROTO_FTPS },
    { "imap" /* IMAP */, ND_PROTO_MAIL_IMAPS },
    { "pop3" /* POP3 */, ND_PROTO_MAIL_POPS },
    { "managesieve" /* ManageSieve */, ND_PROTO_TLS },
    { "coap" /* CoAP */, ND_PROTO_COAP },
    { "xmpp-client" /* XMPP jabber:client namespace */, ND_PROTO_XMPPS },
    { "xmpp-server" /* XMPP jabber:server namespace */, ND_PROTO_XMPPS },
    { "acme-tls/1" /* acme-tls/1 */, ND_PROTO_TLS },
    { "mqtt" /* OASIS Message Queuing Telemetry Transport (MQTT) */,
      ND_PROTO_MQTTS },
    { "dot" /* DNS-over-TLS */, ND_PROTO_DOT },
    { "ntske/1" /* Network Time Security Key Establishment, version 1 */,
      ND_PROTO_TLS },
    { "sunrpc" /* SunRPC */, ND_PROTO_TLS },
    { "h3" /* HTTP/3 */, ND_PROTO_HTTPS },
    { "smb" /* SMB2 */, ND_PROTO_SMBV23 },
    { "irc" /* IRC */, ND_PROTO_IRCS },
    { "nntp" /* NNTP (reading) */, ND_PROTO_NNTPS },
    { "nnsp" /* NNTP (transit) */, ND_PROTO_NNTPS },
    { "doq" /* DoQ */, ND_PROTO_DOQ },
    { "sip/2" /* SIP */, ND_PROTO_SIPS },
    { "tds/8.0" /* TDS/8.0 */, ND_PROTO_MSSQL_TDS },
    { "dicom" /* DICOM */, ND_PROTO_TLS },
};

// vi: ei=all
