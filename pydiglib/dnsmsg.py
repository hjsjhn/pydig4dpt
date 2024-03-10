"""
dnsmsg.py - dns message parsing routines

"""

import socket
import struct
import math
import random

from .options import options
from .common import ErrorMessage
from .rdata import decode_rr, print_optrr, get_optrr
from .name import name_from_wire_message, name_from_text, name_match
from .dnsparam import qt, qc, rc
from .edns import OptRR
from .util import randomize_case, vprint


class DNSquery:
    """DNS Query class"""

    def __init__(self, qname, qtype, qclass):
        if options["do_0x20"]:
            self.qname = randomize_case(qname)
            self.orig_qname = self.qname
        else:
            self.qname = qname
        if not options["emptyquestion"]:
            self.qname = name_from_text(self.qname)
        self.qtype = qtype
        self.qclass = qclass
        self.set_txid()
        self.set_flags()
        self.set_section_counts()
        self.mk_question()
        self.authority = b''
        self.additional = b''
        if (qtype == 251) and options["serial"]:                    # IXFR
            self.add_soa(options["serial"])
        self.msglen_without_opt = 12 + len(self.question) + len(self.authority)
        if options["do_tsig"]:
            self.tsig = options["tsig"]
            self.msglen_without_opt += self.tsig.get_rr_length()
        if options["use_edns"]:
            self.mk_additional()
        self.mk_header_fields()
        self.assemble_message()
        if options["do_tsig"]:
            self.add_tsig()
            # tsig is computed over the entire message before adding the
            # TSIG RR. So we need to re-assemble the message again now.
            self.assemble_message()
        self.msglen = len(self.message)

    def get_message(self):
        """return wire format DNS query message"""
        return self.message

    def get_length(self):
        """Return length of wire format query message"""
        return self.msglen

    def set_txid(self):
        """return transaction ID"""
        if options["msgid"]:
            self.txid = options["msgid"]
        else:
            self.txid = random.randint(1, 65535)

    def set_flags(self):
        """Set DNS header flags"""
        self.qr = 0
        self.opcode = 0
        self.aa = options["aa"]
        self.tc = 0
        self.rd = options["rd"]
        self.ra = 0
        self.z = 0
        self.ad = options["ad"]
        self.cd = options["cd"]
        self.rcode = 0

    def set_section_counts(self):
        """Set section counts"""
        if options["emptyquestion"]:
            self.qdcount = 0
        else:
            self.qdcount = 1
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

    def mk_header_fields(self):
        """Construct wire format message header fields"""
        self.packed_txid = struct.pack('!H', self.txid)
        flags = (self.qr << 15) + \
                (self.opcode << 11) + \
                (self.aa << 10) + \
                (self.tc << 9) + \
                (self.rd << 8) + \
                (self.ra << 7) + \
                (self.z << 6) + \
                (self.ad << 5) + \
                (self.cd << 4) + \
            self.rcode
        self.flags = struct.pack('!H', flags)
        self.packed_qdcount = struct.pack('!H', self.qdcount)
        self.packed_ancount = struct.pack('!H', self.ancount)
        self.packed_nscount = struct.pack('!H', self.nscount)
        self.packed_arcount = struct.pack('!H', self.arcount)

    def mk_question(self):
        """Construct wire question section"""
        if options["emptyquestion"]:
            self.question = b""
        else:
            wire_qname = self.qname.wire()
            self.question = wire_qname + struct.pack('!H', self.qtype) + \
                struct.pack('!H', self.qclass)

    def mk_additional(self):
        """Construct wire format additional section"""
        Opt = OptRR(options["edns_version"],
                    options["bufsize"],
                    flags=options["edns_flags"],
                    dnssec_ok=options["dnssec_ok"])
        self.arcount += 1
        self.additional = Opt.mk_optrr(msglen=self.msglen_without_opt)

    def assemble_message(self):
        """Create assembled wire format query message"""
        self.message = self.packed_txid + \
            self.flags + \
            self.packed_qdcount + \
            self.packed_ancount + \
            self.packed_nscount + \
            self.packed_arcount + \
            self.question + \
            self.authority + \
            self.additional

    def add_soa(self, serial):
        """Add SOA RRset to Authority section (for IXFR queries)"""
        self.rd = 0
        self.nscount += 1
        self.packed_nscount = struct.pack('!H', self.nscount)
        rrname = b'\xc0\x0c'             # pointer to earlier qname
        rrtype = struct.pack('!H', qt.get_val("SOA"))
        rrclass = b'\x00\x01'
        ttl = b'\x00\x00\x00\x00'
        rdata = b'\x00' + \
                b'\x00' + \
                struct.pack('!I', serial) + \
                b'\x00\x00\x00\x00' + \
                b'\x00\x00\x00\x00' + \
                b'\x00\x00\x00\x00' + \
                b'\x00\x00\x00\x00'
        rdlen = struct.pack('!H', len(rdata))
        self.authority = rrname + rrtype + rrclass + ttl + \
            rdlen + rdata

    def add_tsig(self):
        """Add TSIG RR to additional section"""
        self.tsig_rr = self.tsig.mk_request_tsig(self.txid, self.message)
        self.arcount += 1
        self.packed_arcount = struct.pack('!H', self.arcount)
        self.additional += self.tsig_rr

    def __repr__(self):
        return "<DNSquery: {},{},{}>".format(self.qname, self.qtype, self.qclass)


class DNSresponse:
    """DNS Response class"""

    cnt_compression = 0
    sections = ["QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL"]
    print_section_bitmap = 0b1111           # default: print all sections

    class sectionData:
        """Class to hold section data"""
        class answerData:
            rrname = ''
            ttl = 0
            rrclass = ''
            rrtype = ''
            rdata = ''
            def __init__(self, rrname, ttl, rrclass, rrtype, rdata):
                self.rrname = rrname
                self.ttl = ttl
                self.rrclass = rrclass
                self.rrtype = rrtype
                self.rdata = rdata

        def __init__(self, secname, rcode, rrcount, is_axfr, offset, message, query):
            self.rcode = rcode
            self.message = message
            self.offset = offset
            answer_qname = None
            if rrcount and (not is_axfr):
                self.secname = secname
            if secname == "QUESTION":
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, self.offset = \
                        self.decode_question(self.offset)
                    answer_qname = rrname
                    if is_axfr:
                        continue
                    self.answer_qname = answer_qname.text()
                    self.rrclass = qc.get_name(rrclass)
                    self.rrtype = qc.get_name(rrtype)
                    self.question_matched(answer_qname, rrtype, rrclass, query)
            else:
                self.record = []
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, ttl, rdata, self.offset = \
                        decode_rr(self.message, self.offset, options["hexrdata"])
                    # print("\n-------\n", secname, rrname, rrtype, rrclass, ttl, rdata, offset, "\n-------")
                    if is_axfr and (secname != "ANSWER"):
                        continue
                    elif not options["generic"] and rrtype == 41:
                        self.optrr = get_optrr(rcode, rrclass, ttl, rdata)
                    else:
                        self.record.append(self.answerData(rrname.text, ttl, qc.get_name(rrclass), qc.get_name(rrtype), rdata))
                        # self.rrname = rrname.text()
                        # self.ttl = ttl
                        # self.rrclass = qc.get_name(rrclass)
                        # self.rrtype = qc.get_name(rrtype)
                        # self.rdata = rdata

        def decode_question(self, offset):
            """decode question section of a DNS message"""
            domainname, offset = name_from_wire_message(self.message, offset)
            rrtype, rrclass = struct.unpack(
                "!HH", self.message[offset:offset+4])
            offset += 4
            return (domainname, rrtype, rrclass, offset)

        def question_matched(self, qname, qtype, qclass, query):
            """Check that answer matches question"""
            self.question_match = True
            if self.rcode in [0, 3]:
                if (not name_match(qname, query.qname, options["do_0x20"])) \
                        or (qtype != query.qtype) \
                        or (qclass != query.qclass):
                    self.question_match = False
            return

    def __init__(self, family, query, msg, used_tcp=False, checkid=True):
        self.family = family
        self.query = query
        self.message = msg
        self.section: {str: self.sectionData} = {}
        self.msglen = len(self.message)
        self.used_tcp = used_tcp
        self.decode_header(checkid)

    def decode_header(self, checkid=True):
        """Decode a DNS protocol header"""
        self.txid, flags, self.qdcount, self.ancount, self.nscount, \
            self.arcount = struct.unpack('!HHHHHH', self.message[:12])
        if checkid and (self.txid != self.query.txid):
            # Should continue listening for a valid response here (ideally)
            raise ErrorMessage("got response with id: %ld (expecting %ld)" %
                               (self.txid, self.query.txid))
        self.qr = flags >> 15
        self.opcode = (flags >> 11) & 0xf
        self.aa = (flags >> 10) & 0x1
        self.tc = (flags >> 9) & 0x1
        self.rd = (flags >> 8) & 0x1
        self.ra = (flags >> 7) & 0x1
        self.z = (flags >> 6) & 0x1
        self.ad = (flags >> 5) & 0x1
        self.cd = (flags >> 4) & 0x1
        self.rcode = (flags) & 0xf

    def get_ampratio(self, VERBOSE=0):
        """Print packet amplification ratios - these are estimations"""
        if self.family == socket.AF_INET:
            overhead = 42                # Ethernet + IPv4 + UDP header
        elif self.family == socket.AF_INET6:
            overhead = 62                # Ethernet + IPv6 + UDP header
        else:
            overhead = 0                 # shouldn't happen

        # amp1: ratio of only the DNS response payload & query payload
        # amp2: estimated ratio of the full packets assuming Ethernet link
        amp1 = (self.msglen * 1.0/self.query.msglen)
        w_qsize = self.query.msglen + overhead
        w_rsize = self.msglen + \
            overhead * math.ceil(self.msglen/(1500.0-overhead))
        amp2 = w_rsize/w_qsize

        self.amp1 = amp1
        self.amp2 = amp2
        vprint(";; Size query=%d, response=%d, amp1=%.2f amp2=%.2f" %
                (self.query.msglen, self.msglen, amp1, amp2), 2, VERBOSE)

    def get_preamble(self, VERBOSE=0):
        """Get preamble of a DNS response message"""
        if options["do_0x20"]:
            self.qname_0x20 = self.query.qname
            # print(";; 0x20-hack qname: %s" % self.query.qname)
        self.rcode_name = rc.get_name(self.rcode)
        vprint(";; rcode=%d(%s), id=%d" %
              (self.rcode, rc.get_name(self.rcode), self.txid), 2, VERBOSE)
        vprint(";; qr=%d opcode=%d aa=%d tc=%d rd=%d ra=%d z=%d ad=%d cd=%d" %
              (self.qr,
               self.opcode,
               self.aa,
               self.tc,
               self.rd,
               self.ra,
               self.z,
               self.ad,
               self.cd), 3, VERBOSE)
        vprint(";; question=%d, answer=%d, authority=%d, additional=%d" %
              (self.qdcount, self.ancount, self.nscount, self.arcount), 3, VERBOSE)
        self.get_ampratio(VERBOSE)

    def print_rr(self, rrname, ttl, rrtype, rrclass, rdata):
        """Print RR in presentation format"""
        print("%s\t%d\t%s\t%s\t%s" %
              (rrname.text(), ttl,
               qc.get_name(rrclass), qt.get_name(rrtype), rdata))
        return

    def decode_question(self, offset):
        """decode question section of a DNS message"""
        domainname, offset = name_from_wire_message(self.message, offset)
        rrtype, rrclass = struct.unpack("!HH", self.message[offset:offset+4])
        offset += 4
        return (domainname, rrtype, rrclass, offset)

    def question_matched(self, qname, qtype, qclass):
        """Check that answer matches question"""
        if self.rcode in [0, 3]:
            if (not name_match(qname, self.query.qname, options["do_0x20"])) \
                    or (qtype != self.query.qtype) \
                    or (qclass != self.query.qclass):
                print("*** WARNING: Answer didn't match question!\n")
        return

    def decode_sections(self, is_axfr=False, VERBOSE=0):
        """Decode message sections and print contents"""
        offset = 12                     # skip over DNS header
        answer_qname = None

        for (secname, rrcount) in zip(self.sections,
                                      [self.qdcount, self.ancount, self.nscount, self.arcount]):
            if not rrcount:
                continue
            self.section[secname] = self.sectionData(
                secname, self.rcode, rrcount, is_axfr, offset, self.message, self.query)
            offset = self.section[secname].offset

    def decode_all(self, VERBOSE=0):
        """Decode all info about the DNS response message"""
        self.get_preamble(VERBOSE)
        self.decode_sections(VERBOSE=VERBOSE)

    def __repr__(self):
        return "<DNSresponse: {},{},{}>".format(
            self.query.qname, self.query.qtype, self.query.qclass)
