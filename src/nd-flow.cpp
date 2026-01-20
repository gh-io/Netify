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

#include <iomanip>
#include <locale>

#include "nd-flow.hpp"

// Enable lower map debug output
// #define _ND_DEBUG_LOWER_MAP	1

void ndFlowStats::UpdateRate(bool lower, uint64_t timestamp,
  uint64_t bytes) {
    const unsigned interval = ndGC.update_interval;

    unsigned index = (unsigned)fmod(
      floor((double)timestamp / (double)1000), (double)interval);

    atomic<float> &rate = (lower) ? lower_rate : upper_rate;
    vector<float> &samples = (lower) ? lower_rate_samples : upper_rate_samples;

    samples[index] += bytes;

    uint64_t total = 0;
    unsigned divisor = 0;
    for (unsigned i = 0; i < interval; i++) {
        if (samples[i] == 0) continue;
        total += samples[i];
        divisor++;
    }

    rate = (divisor > 0) ? ((float)total / (float)divisor) : 0.0f;
}

ndFlow::ndFlow(nd_iface_ptr &iface)
  : iface(iface), dpi_thread_id(-1), ip_version(0),
    ip_protocol(0), vlan_id(0), tcp_last_seq(0),
    ts_first_seen(0), ts_last_seen(0), lower_map(LOWER_UNKNOWN),
    other_type(OTHER_UNKNOWN), tunnel_type(TUNNEL_NONE),
    detected_protocol(ND_PROTO_UNKNOWN),
    detected_application(ND_APP_UNKNOWN),
    detected_protocol_name("Unknown"),
    category{ ND_CAT_UNKNOWN, ND_CAT_UNKNOWN, ND_CAT_UNKNOWN },
    ndpi_flow(NULL), http{ { 0 } }, privacy_mask(0),
    origin(0), direction(0),
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
    ct_id(0), ct_mark(0),
#endif
    lower_type(ndAddr::atNONE), upper_type(ndAddr::atNONE),
    flags{}, gtp{ 0 }, ndpi_risk_score(0),
    ndpi_risk_score_client(0), ndpi_risk_score_server(0) {
    gtp.version = 0xFF;

    digest_lower.reserve(SHA1_DIGEST_LENGTH);
    digest_lower.resize(SHA1_DIGEST_LENGTH);
    digest_mdata.reserve(SHA1_DIGEST_LENGTH);
    digest_mdata.resize(SHA1_DIGEST_LENGTH);
}

ndFlow::ndFlow(const ndFlow &flow)
  : iface(flow.iface), dpi_thread_id(-1),
    ip_version(flow.ip_version), ip_protocol(flow.ip_protocol),
    vlan_id(flow.vlan_id), tcp_last_seq(flow.tcp_last_seq),
    ts_first_seen(flow.ts_first_seen),
    ts_last_seen(flow.ts_last_seen.load()),
    lower_map(LOWER_UNKNOWN), other_type(OTHER_UNKNOWN),
    lower_mac(flow.lower_mac), upper_mac(flow.upper_mac),
    lower_addr(flow.lower_addr), upper_addr(flow.upper_addr),
    tunnel_type(flow.tunnel_type),
    detected_protocol(ND_PROTO_UNKNOWN),
    detected_application(ND_APP_UNKNOWN),
    detected_protocol_name("Unknown"),
    category{ ND_CAT_UNKNOWN, ND_CAT_UNKNOWN, ND_CAT_UNKNOWN },
    ndpi_flow(NULL), http{ { 0 } }, privacy_mask(0),
    origin(0), direction(0),
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
    ct_id(0), ct_mark(0),
#endif
    lower_type(ndAddr::atNONE), upper_type(ndAddr::atNONE),
    flags{}, gtp(flow.gtp), ndpi_risk_score(0),
    ndpi_risk_score_client(0), ndpi_risk_score_server(0) {
    digest_lower.assign(flow.digest_lower.begin(),
      flow.digest_lower.end());
    digest_mdata.reserve(SHA1_DIGEST_LENGTH);
    digest_mdata.resize(SHA1_DIGEST_LENGTH);
}

ndFlow::~ndFlow() {
    Release();

    if (HasTLSIssuerDN()) {
        free(ssl.issuer_dn);
        ssl.issuer_dn = NULL;
    }

    if (HasTLSSubjectDN()) {
        free(ssl.subject_dn);
        ssl.subject_dn = NULL;
    }
}

void ndFlow::Hash(const string &device, bool hash_mdata,
  const uint8_t *key, size_t key_length) {
    sha1 ctx;

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)device.c_str(), device.size());

    sha1_write(&ctx, (const char *)&ip_version, sizeof(ip_version));
    sha1_write(&ctx, (const char *)&ip_protocol,
      sizeof(ip_protocol));
    sha1_write(&ctx, (const char *)&vlan_id, sizeof(vlan_id));

    switch (ip_version) {
    case 4:
        sha1_write(&ctx,
          (const char *)&lower_addr.addr.in.sin_addr,
          sizeof(struct in_addr));
        sha1_write(&ctx,
          (const char *)&upper_addr.addr.in.sin_addr,
          sizeof(struct in_addr));

        if (lower_addr.addr.in.sin_addr.s_addr == 0 &&
          upper_addr.addr.in.sin_addr.s_addr == 0xffffffff)
        {
            // XXX: Hash in lower MAC for ethernet broadcasts
            // (DHCPv4).
#if defined(__linux__)
            sha1_write(&ctx,
              (const char *)lower_mac.addr.ll.sll_addr,
              ETH_ALEN);
#elif defined(__FreeBSD__)
            sha1_write(&ctx,
              (const char *)LLADDR(&lower_mac.addr.dl),
              ETH_ALEN);
#endif
        }

        break;
    case 6:
        sha1_write(&ctx,
          (const char *)&lower_addr.addr.in6.sin6_addr,
          sizeof(struct in6_addr));
        sha1_write(&ctx,
          (const char *)&upper_addr.addr.in6.sin6_addr,
          sizeof(struct in6_addr));
        break;
    default: break;
    }

    uint16_t port = lower_addr.GetPort(false);
    sha1_write(&ctx, (const char *)&port, sizeof(port));
    port = upper_addr.GetPort(false);
    sha1_write(&ctx, (const char *)&port, sizeof(port));

    if (hash_mdata) {
        sha1_write(&ctx, (const char *)&detected_protocol,
          sizeof(ndpi_protocol));

        if (! host_server_name.empty()) {
            sha1_write(&ctx, host_server_name.c_str(),
              host_server_name.size());
        }
        if (HasBTInfoHash()) {
            sha1_write(&ctx, bt.info_hash, ND_FLOW_BTIHASH_LEN);
        }
    }

    if (key != NULL && key_length > 0)
        sha1_write(&ctx, (const char *)key, key_length);

    if (! hash_mdata) sha1_result(&ctx, &digest_lower[0]);
    else sha1_result(&ctx, &digest_mdata[0]);
}

void ndFlow::Reset(bool full_reset) {
    stats.Reset(full_reset);

    if (full_reset) {
        flags.detection_complete = false;
        flags.detection_guessed = false;
        flags.detection_init = false;
        flags.detection_updated = false;
        flags.dhc_hit = false;
        flags.expired = false;
        flags.expiring = false;
        flags.risks_checked = false;
        flags.soft_dissector = false;

        risks.clear();
    }
}

void ndFlow::Release(void) {
    if (ndpi_flow != NULL) {
        ndpi_free_flow(ndpi_flow);
        ndpi_flow = NULL;
    }
}

nd_proto_id_t ndFlow::GetMasterProtocol(void) const {
    switch (detected_protocol) {
    case ND_PROTO_HTTPS:
    case ND_PROTO_TLS:
    case ND_PROTO_FTPS:
    case ND_PROTO_FTPS_DATA:
    case ND_PROTO_MAIL_IMAPS:
    case ND_PROTO_MAIL_POPS:
    case ND_PROTO_MAIL_SMTPS:
    case ND_PROTO_MQTTS:
    case ND_PROTO_NNTPS:
    case ND_PROTO_SIPS: return ND_PROTO_TLS;
    case ND_PROTO_HTTP:
    case ND_PROTO_HTTP_CONNECT:
    case ND_PROTO_HTTP_PROXY:
    case ND_PROTO_OOKLA:
    case ND_PROTO_PPSTREAM:
    case ND_PROTO_QQ:
    case ND_PROTO_RTSP:
    case ND_PROTO_STEAM:
    case ND_PROTO_TEAMVIEWER:
    case ND_PROTO_XBOX: return ND_PROTO_HTTP;
    case ND_PROTO_DNS:
    case ND_PROTO_MDNS:
    case ND_PROTO_LLMNR: return ND_PROTO_DNS;
    default: break;
    }

    return detected_protocol;
}

bool ndFlow::HasDhcpFingerprint(void) const {
    return (detected_protocol == ND_PROTO_DHCP &&
      dhcp.fingerprint[0] != '\0');
}

bool ndFlow::HasDhcpClassIdent(void) const {
    return (detected_protocol == ND_PROTO_DHCP &&
      dhcp.class_ident[0] != '\0');
}

bool ndFlow::HasHttpUserAgent(void) const {
    return (GetMasterProtocol() == ND_PROTO_HTTP &&
      http.user_agent[0] != '\0');
}

bool ndFlow::HasHttpURL(void) const {
    return (GetMasterProtocol() == ND_PROTO_HTTP &&
      http.url[0] != '\0');
}

bool ndFlow::HasSSHClientAgent(void) const {
    return (detected_protocol == ND_PROTO_SSH &&
      ssh.client_agent[0] != '\0');
}

bool ndFlow::HasSSHServerAgent(void) const {
    return (detected_protocol == ND_PROTO_SSH &&
      ssh.server_agent[0] != '\0');
}

bool ndFlow::HasTLSClientSNI(void) const {
    return ((GetMasterProtocol() == ND_PROTO_TLS ||
              detected_protocol == ND_PROTO_QUIC) &&
      host_server_name.empty() == false);
}

bool ndFlow::HasTLSServerCN(void) const {
    return ((GetMasterProtocol() == ND_PROTO_TLS ||
              detected_protocol == ND_PROTO_QUIC) &&
      ssl.server_cn[0] != '\0');
}

bool ndFlow::HasTLSIssuerDN(void) const {
    return ((GetMasterProtocol() == ND_PROTO_TLS ||
              detected_protocol == ND_PROTO_QUIC) &&
      ssl.issuer_dn != NULL);
}

bool ndFlow::HasTLSSubjectDN(void) const {
    return ((GetMasterProtocol() == ND_PROTO_TLS ||
              detected_protocol == ND_PROTO_QUIC) &&
      ssl.subject_dn != NULL);
}

bool ndFlow::HasTLSClientJA3(void) const {
    return (GetMasterProtocol() == ND_PROTO_TLS &&
      ssl.client_ja3[0] != '\0');
}

bool ndFlow::HasTLSServerJA3(void) const {
    return (GetMasterProtocol() == ND_PROTO_TLS &&
      ssl.server_ja3[0] != '\0');
}

bool ndFlow::HasBTInfoHash(void) const {
    return (detected_protocol == ND_PROTO_BITTORRENT &&
      bt.info_hash_valid);
}

bool ndFlow::HasSSDPUserAgent(void) const {
    return (GetMasterProtocol() == ND_PROTO_SSDP &&
      http.user_agent[0] != '\0');
}

#if 0
bool ndFlow::HasMiningVariant(void) const
{
    return (
        detected_protocol == ND_PROTO_MINING &&
        mining.variant[0] != '\0'
    );
}
#endif
bool ndFlow::HasMDNSDomainName(void) const {
    return (detected_protocol == ND_PROTO_MDNS &&
      mdns.domain_name[0] != '\0');
}

void ndFlow::Print(uint8_t pflags) const {
    bool multiline = false;
    ndDebugLogStream dls(ndDebugLogStream::DLT_FLOW);

    nd_output_lock();

    try {
        dls << iface->ifname.c_str() << ": ";

        if ((pflags & PRINTF_HASHES)) {
            for (unsigned i = 0; i < 5; i++) {
                dls << setw(2) << setfill('0') << hex
                    << (int)digest_lower[i];
            }
            dls << ":";
            for (unsigned i = 0; i < 5; i++) {
                dls << setw(2) << setfill('0') << hex
                    << (int)digest_mdata[i];
            }
            dls << " ";
        }

        dls
          << setfill(' ') << dec
          << ((iface->role == ndIR_LAN) ? 'i' : 'e')
          << ((ip_version == 4)    ? '4' :
                 (ip_version == 6) ? '6' :
                                     '-')
          << (flags.detection_init.load() ? 'p' : '-')
          << (flags.detection_complete.load() ? 'c' : '-')
          << (flags.detection_updated.load() ? 'u' : '-')
          << (flags.detection_guessed.load() ? 'g' : '-')
          << (flags.expiring.load() ? 'x' : '-')
          << (flags.expired.load() ? 'X' : '-')
          << (flags.dhc_hit.load() ? 'd' : '-')
          << (flags.fhc_hit.load() ? 'f' : '-')
          << (flags.ip_nat.load() ? 'n' : '-')
          << (flags.risks_checked.load() && ! risks.empty() ? 'r' : '-')
          << (flags.soft_dissector.load() ? 's' : '-')
          << (flags.tcp_fin_ack.load() ? 'F' : '-')
          << ((privacy_mask & PRIVATE_LOWER) ?
                 'v' :
                 (privacy_mask & PRIVATE_UPPER) ?
                 'V' :
                 (privacy_mask & (PRIVATE_LOWER | PRIVATE_UPPER)) ?
                 '?' :
                 '-')
          << " ";

        string proto;
        nd_get_ip_protocol_name(ip_protocol, proto);
        dls << proto << " ";

        switch (lower_map) {
        case LOWER_UNKNOWN: dls << "[U"; break;
        case LOWER_LOCAL: dls << "[L"; break;
        case LOWER_OTHER: dls << "[O"; break;
        }

        char ot = '?';
        switch (other_type) {
        case OTHER_UNKNOWN: ot = 'U'; break;
        case OTHER_UNSUPPORTED: ot = 'X'; break;
        case OTHER_LOCAL: ot = 'L'; break;
        case OTHER_MULTICAST: ot = 'M'; break;
        case OTHER_BROADCAST: ot = 'B'; break;
        case OTHER_REMOTE: ot = 'R'; break;
        case OTHER_ERROR: ot = 'E'; break;
        }

        if (lower_map == LOWER_OTHER) dls << ot;

        dls << "] ";

        if ((pflags & PRINTF_MACS))
            dls << lower_mac.GetString() << " ";

        dls
          << lower_addr.GetString() << ":"
          << lower_addr.GetPort() << " "
          << ((origin == ORIGIN_LOWER || origin == ORIGIN_UNKNOWN) ? '-' : '<')
          << ((origin == ORIGIN_UNKNOWN) ? '?' : '-')
          << ((origin == ORIGIN_UPPER || origin == ORIGIN_UNKNOWN) ? '-' : '>')
          << " ";

        switch (lower_map) {
        case LOWER_UNKNOWN: dls << "[U"; break;
        case LOWER_LOCAL: dls << "[O"; break;
        case LOWER_OTHER: dls << "[L"; break;
        }

        if (lower_map == LOWER_LOCAL) dls << ot;

        dls << "] ";

        if ((pflags & PRINTF_MACS))
            dls << upper_mac.GetString() << " ";

        dls << upper_addr.GetString() << ":"
            << upper_addr.GetPort();

        if ((pflags & PRINTF_METADATA) &&
          flags.detection_init.load())
        {
            multiline = true;

            dls
              << endl
              << setw(iface->ifname.size()) << " "
              << ": " << detected_protocol_name
              << ((! detected_application_name.empty()) ? "." : "")
              << ((! detected_application_name.empty()) ?
                     detected_application_name :
                     "");

            if (! dns_host_name.empty() ||
              ! host_server_name.empty())
            {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ":";
                if (! dns_host_name.empty())
                    dls << " D: " << dns_host_name;
                if (! host_server_name.empty() &&
                  dns_host_name.compare(host_server_name))
                    dls << " H: " << host_server_name;
            }

            if (HasMDNSDomainName()) {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ":";
                dls << " MDNS/DN: " << mdns.domain_name;
            }

            if (HasDhcpFingerprint() || HasDhcpClassIdent()) {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ":";
                if (HasDhcpFingerprint())
                    dls << " DHCP/FP: " << dhcp.fingerprint;
                if (HasDhcpClassIdent())
                    dls << " DHCP/CI: " << dhcp.class_ident;
            }

            if (HasHttpUserAgent() || HasSSDPUserAgent()) {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ":";
                dls << " HTTP/UA: " << http.user_agent;
            }

            if (HasHttpURL()) {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ":";
                dls << " URL: " << http.url;
            }

            if (HasSSHClientAgent() || HasSSHServerAgent()) {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ":";
                if (HasSSHClientAgent())
                    dls << " SSH/CA: " << ssh.client_agent;
                if (HasSSHServerAgent())
                    dls << " SSH/SA: " << ssh.server_agent;
            }

            if ((GetMasterProtocol() == ND_PROTO_TLS ||
                  detected_protocol == ND_PROTO_QUIC) &&
              (ssl.version || ssl.cipher_suite))
            {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ": ";
                dls << "V: 0x" << setfill('0') << setw(4) << hex
                    << ssl.version << setfill(' ') << dec;

                if (ssl.cipher_suite) {
                    dls << " "
                        << "CS: 0x" << setfill('0')
                        << setw(4) << hex << ssl.cipher_suite
                        << setfill(' ') << dec;
                }
            }

            if (HasTLSClientSNI() || HasTLSServerCN()) {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ":";
                if (HasTLSClientSNI())
                    dls << " TLS/SNI: " << host_server_name;
                if (HasTLSServerCN())
                    dls << " TLS/CN: " << ssl.server_cn;
            }

            if (HasTLSIssuerDN() || HasTLSSubjectDN()) {
                dls << endl
                    << setw(iface->ifname.size()) << " "
                    << ":";
                if (HasTLSIssuerDN())
                    dls << " TLS/IDN: " << ssl.issuer_dn;
                if (HasTLSSubjectDN())
                    dls << " TLS/SDN: " << ssl.subject_dn;
            }
        }

        if ((pflags & PRINTF_RISKS)) {
            if (flags.risks_checked.load() && ! risks.empty())
            {
                auto r = risks.begin();
                if (r != risks.end()) {
                    dls
                      << endl
                      << setw(iface->ifname.size()) << " "
                      << setw(0) << ": RID" << setw(3)
                      << (*r) << ": " << setw(0)
                      << nd_risk_get_name(*r);
                }
                if (risks.size() > 1) {
                    for (r = next(risks.begin());
                         r != risks.end(); r++)
                    {
                        dls
                          << endl
                          << setw(iface->ifname.size())
                          << " " << setw(0) << ": RID"
                          << setw(3) << (*r) << ": "
                          << setw(0) << nd_risk_get_name(*r);
                    }
                }
            }
        }

        if ((pflags & PRINTF_STATS)) {
            multiline = true;

            dls.imbue(locale(""));

            dls << endl
                << setw(iface->ifname.size()) << " "
                << ": "
                << "DP: "
                << ndLogFormat(ndLogFormat::FORMAT_BYTES,
                     stats.detection_packets.load());

            if ((pflags & PRINTF_STATS_FULL)) {
                dls
                  << " "
                  << "TP: "
                  << ndLogFormat(ndLogFormat::FORMAT_PACKETS,
                       stats.total_packets.load())
                  << " "
                  << "TB: "
                  << ndLogFormat(ndLogFormat::FORMAT_BYTES,
                       stats.total_bytes.load());
            }

            dls.imbue(locale("C"));
        }

        if (multiline) dls << endl;
        dls << endl;
    }
    catch (exception &e) {
        nd_output_unlock();

        nd_dprintf("exception caught printing flow: %s\n",
          e.what());
        return;
    }

    nd_output_unlock();
}

void ndFlow::UpdateLowerMaps(void) {
    if (lower_map == LOWER_UNKNOWN)
        GetLowerMap(lower_type, upper_type, lower_map, other_type);

    switch (tunnel_type) {
    case TUNNEL_GTP:
        if (gtp.lower_map == LOWER_UNKNOWN) {
            GetLowerMap(gtp.lower_type, gtp.upper_type,
              gtp.lower_map, gtp.other_type);
        }
        break;
    }
}

void ndFlow::GetLowerMap(ndAddr::Type lt, ndAddr::Type ut,
  uint8_t &lm, uint8_t &ot) {
    if (lt == ndAddr::atERROR || ut == ndAddr::atERROR) {
        ot = OTHER_ERROR;
    }
    else if (lt == ndAddr::atLOCAL && ut == ndAddr::atLOCAL) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atLOCAL && ut == ndAddr::atLOCAL) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atLOCAL && ut == ndAddr::atLOCALNET)
    {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atLOCALNET && ut == ndAddr::atLOCAL)
    {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atMULTICAST) {
        lm = LOWER_OTHER;
        ot = OTHER_MULTICAST;
    }
    else if (ut == ndAddr::atMULTICAST) {
        lm = LOWER_LOCAL;
        ot = OTHER_MULTICAST;
    }
    else if (lt == ndAddr::atBROADCAST) {
        lm = LOWER_OTHER;
        ot = OTHER_BROADCAST;
    }
    else if (ut == ndAddr::atBROADCAST) {
        lm = LOWER_LOCAL;
        ot = OTHER_BROADCAST;
    }
    else if (lt == ndAddr::atRESERVED && ut == ndAddr::atLOCALNET)
    {
        lm = LOWER_OTHER;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atLOCALNET && ut == ndAddr::atRESERVED)
    {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    // TODO: Further investigation required!
    // This appears to catch corrupted IPv6 headers.
    // Spend some time to figure out if there are any
    // possible over-matches for different methods of
    // deployment (gateway/port mirror modes).
    else if (ip_version != 6 && lt == ndAddr::atRESERVED &&
      ut == ndAddr::atRESERVED)
    {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atRESERVED && ut == ndAddr::atLOCAL)
    {
        lm = LOWER_OTHER;
        ot = OTHER_REMOTE;
    }
    else if (lt == ndAddr::atLOCAL && ut == ndAddr::atRESERVED)
    {
        lm = LOWER_LOCAL;
        ot = OTHER_REMOTE;
    }
    else if (lt == ndAddr::atLOCALNET && ut == ndAddr::atLOCALNET)
    {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atOTHER) {
        lm = LOWER_OTHER;
        ot = OTHER_REMOTE;
    }
    else if (ut == ndAddr::atOTHER) {
        lm = LOWER_LOCAL;
        ot = OTHER_REMOTE;
    }
#if _ND_DEBUG_LOWER_MAP
    const static vector<string> lower_maps = {
        "LOWER_UNKNOWN", "LOWER_LOCAL", "LOWER_OTHER"
    };
    const static vector<string> other_types = {
        "OTHER_UNKNOWN", "OTHER_UNSUPPORTED", "OTHER_LOCAL",
        "OTHER_MULTICAST", "OTHER_BROADCAST",
        "OTHER_REMOTE", "OTHER_ERROR"
    };
    const static vector<string> at = { "atNONE", "atLOCAL",
        "atLOCALNET", "atRESERVED", "atMULTICAST",
        "atBROADCAST", "atOTHER" };

    if (lm == LOWER_UNKNOWN) {
        nd_dprintf("lower map: %s, other type: %s\n",
          lower_maps[lm].c_str(),
          other_types[ot].c_str());
        nd_dprintf(
          "lower type: %s: %s, upper_type: %s: %s\n",
          lower_addr.GetString().c_str(),
          (lt == ndAddr::atERROR) ? "atERROR" : at[lt].c_str(),
          upper_addr.GetString().c_str(),
          (ut == ndAddr::atERROR) ? "atERROR" : at[ut].c_str());
    }
#endif
}
