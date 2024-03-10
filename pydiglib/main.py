"""
main function.

"""

import sys
import socket
import time

from .common import options, excepthook, dprint, Stats, ErrorMessage, UsageError, ITIMEOUT, RETRIES
from .options import parse_args
from .util import random_init, get_socketparams, vprint
from .dnsparam import qc, qt
from .dnsmsg import DNSquery, DNSresponse
from .query import send_request_udp, send_request_tcp, send_request_tls, do_axfr
from .https import send_request_https
from .walk import zonewalk


def main(args, VERBOSE=0) -> DNSresponse:

    """ 
        Get the DNS response from the server.

        Args:
            `args`: Arguments to be parsed. e.g. `["@8.8.8.8", "+nsid", "+dnssec"]` \n
            `VERBOSE`: Verbosity level 0(default), 1, 2. \n

        Returns: `DNSresponse` object \n
            `family`: Address family of the server  \n
            `query`: DNSquery object  \n
            `message`: DNS message  \n
            `msglen`: Length of the message  \n
            `use_tcp`: Use TCP for the query  \n
            \n
            (Preamble) \n
            `qname_0x20`: 0x20-hack qname \n
            `rcode`: Response code \n
            `rcode_name`: Response code name \n
            `txid`: Transaction ID \n
            `qr`: Query/Response flag \n
            `opcode`: Opcode \n
            `aa`: Authoritative Answer flag \n
            `tc`: Truncation flag \n
            `rd`: Recursion Desired flag \n
            `ra`: Recursion Available flag \n
            `z`: Reserved for future use \n
            `ad`: Authentic Data flag \n
            `cd`: Checking Disabled flag \n
            `qdcount`: Number of questions \n
            `ancount`: Number of answers \n
            `nscount`: Number of authority records \n
            `arcount`: Number of additional records \n

            (Ampratio) \n
            `query.msglen`: Length of the query message \n
            `msglen`: Length of the response message \n
            `amp1`: Ampratio of the response message \n
            `amp2`: Ampratio of the response message (excluding the query) \n

            (Sections) \n
            `section[<section_name>]`: sectionData object, <section_name> = "QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL"  \n
                `secname`: Section name \n
            `section["QUESTION"].` \n
                `answer_qname`: Answer qname \n
                `rrclass`: RR class \n
                `rrtype`: RR type \n
            `section["ANSWER"].` \n
                `record[]`: a list of answerData object, the members of it are \n
                    `rrname`: RR name \n
                    `ttl`: Answer TTL \n
                    `rrclass`: RR class \n
                    `rrtype`: RR type \n
                    `rdata`: RR data \n
            `section["ADDITONAL"].` \n
                `optrr`: opt_rr object \n
                    `edns_version`: edns version \n
                    `udp_payload`: udp payload \n
                    `flags`: edns opt flags \n
                    `ercode`: edns error code \n
                    `ercode_name`: edns error code name \n
                    `options`: edns options \n
                        `code`: opt code, \n
                        `code_name`: opt code name, \n
                        `length`: opt data length, \n
                        `data`: opt data \n
                            NSID(3):  \n
                            `id`: nsid \n
                            `human_readable`: human readable data \n

                            DAU(5), DHU(6), NHU(7): \n
                            `name`: opt name (e.g. DAU, DHU, NHU) \n
                            `data`: opt data \n

                            ECS(8): \n
                            `address`: ip address \n
                            `source`: source prefix length \n
                            `scope`: scope prefix length \n

                            EDE(15): \n
                            `info_code`: info code \n
                            `info_code_desc`: info code description \n
                            `extra_text`: extra text \n
    """

    sys.excepthook = excepthook
    random_init()

    if VERBOSE == 3:
        args = args[1:]
    qname, qtype, qclass = parse_args(args)

    try:
        qtype_val = qt.get_val(qtype)
    except KeyError:
        raise UsageError("ERROR: invalid query type: {}\n".format(qtype))

    try:
        qclass_val = qc.get_val(qclass)
    except KeyError:
        raise UsageError("ERROR: invalid query class: {}\n".format(qclass))

    query = DNSquery(qname, qtype_val, qclass_val)

    try:
        server_addr, port, family, _ = \
                     get_socketparams(options["server"], options["port"],
                                      options["af"], socket.SOCK_DGRAM)
    except socket.gaierror as e:
        raise ErrorMessage("bad server: %s (%s)" % (options["server"], e))

    if options["do_zonewalk"]:
        zonewalk(server_addr, port, family, qname, options)
        sys.exit(0)


    request = query.get_message()

    if (qtype == "AXFR") or (qtype == "IXFR" and options["use_tcp"]):
        do_axfr(query, request, server_addr, port, family)
        sys.exit(0)

    # the rest is for non AXFR queries ..

    response = None

    if options["https"]:
        t1 = time.time()
        responsepkt = send_request_https(request, options["https_url"])
        t2 = time.time()
        if responsepkt:
            response = DNSresponse(family, query, responsepkt)
            vprint(";; HTTPS response from %s, %d bytes, in %.3f sec" %
                  (options["https_url"], response.msglen, (t2-t1)), 1, VERBOSE)
        else:
            vprint(";; HTTPS response failure from %s" % options["https_url"], 1, VERBOSE)
            return 2

    elif options["tls"]:
        t1 = time.time()
        responsepkt = send_request_tls(request, server_addr,
                                       options["tls_port"], family,
                                       hostname=options["tls_hostname"])
        t2 = time.time()
        if responsepkt:
            response = DNSresponse(family, query, responsepkt)
            vprint(";; TLS response from %s, %d bytes, in %.3f sec" %
                  ((server_addr, options["tls_port"]), response.msglen, (t2-t1)), 1, VERBOSE)
        else:
            vprint(";; TLS response failure from %s, %d" %
                  (server_addr, options["tls_port"]), 1, VERBOSE)
            if not options["tls_fallback"]:
                return 2

    elif not options["use_tcp"]:
        t1 = time.time()
        (responsepkt, responder_addr) = \
                      send_request_udp(request, server_addr, port, family,
                                       ITIMEOUT, RETRIES)
        t2 = time.time()
        if not responsepkt:
            raise ErrorMessage("No response from server")
        response = DNSresponse(family, query, responsepkt)
        if not response.tc:
            vprint(";; UDP response from %s, %d bytes, in %.3f sec" %
                  (responder_addr, response.msglen, (t2-t1)), 1, VERBOSE)

    if options["use_tcp"] or (response and response.tc) \
       or (options["tls"] and options["tls_fallback"] and not response):
        if response and response.tc:
            if options["ignore"]:
                vprint(";; UDP Response was truncated.", 1, VERBOSE)
            else:
                vprint(";; UDP Response was truncated. Retrying using TCP ...", 1, VERBOSE)
        if options["tls"] and options["tls_fallback"] and not response:
            vprint(";; TLS fallback to TCP ...", 1, VERBOSE)
        if not options["ignore"]:
            t1 = time.time()
            responsepkt = send_request_tcp(request, server_addr, port, family)
            t2 = time.time()
            response = DNSresponse(family, query, responsepkt)
            vprint(";; TCP response from %s, %d bytes, in %.3f sec" %
                  ((server_addr, port), response.msglen, (t2-t1)), 1, VERBOSE)

    response.decode_all(VERBOSE)
    dprint("Compression pointer dereferences=%d" % Stats.compression_cnt)

    return response
