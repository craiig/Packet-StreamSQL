/* -*- P4_16 -*- */

/*
 * P4 streaming joins
 *
    Switch receives two packet streams, one sending (adId, impression_time) on
    srcPort 11111 and the other sending (adId, click_time) on srcPort 22222. 
    A click for a particular ad is assumed to occur exactly 1 unit after that ad
    was impressed upon the user, but the click packets may arrive out of order.
    To mitigate this, each stream can buffer up to 100 packets before the buffer
    starts to get overwritten with new packet data.  


 */

#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROT_UDP = 0x11; 
const bit<16> DPORT = 0x0da2; // 3490
const bit<16> IMPR_PORT = 0x2b67; // 11111 srcPort of ad impression stream
const bit<16> CLICK_PORT = 0x56ce; // 22222 srcPort of ad click stream

typedef bit<9>  egressSpec_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> macAddr_t;

// bit vector with index i to tell whether a tuple with adId == i is in the cache 
// (test whether reg_ages[i] == 1 or 0)
register<bit<1>>(100) reg_impr_adId; 
register<bit<1>>(100) reg_click_adId;
register<bit<32>>(100) reg_impr_time;
register<bit<32>>(100) reg_click_time;
  

/*
 * Standard ethernet header 
 */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}


/*
 * Standard ipv4 header 
 */
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


/*
 * Standard udp header 
 */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

/*
 * This is a custom protocol header for the filter. We'll use 
 * ethertype 0x1234
 */
header impression_t {
    bit<32> adId;
    bit<32> impr_time;
}

header click_t {
    bit<32> adId;
    bit<32> click_time;
}

header result_t {
    bit<32> adId;
    bit<32> impr_time;
    bit<32> click_time;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    udp_t           udp;
    impression_t    impression;
    click_t         click;
    result_t        result;
}

 
struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {


    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4    : parse_ipv4;
            default      : accept;
        }
    }
        
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROT_UDP : parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.srcPort) {
            IMPR_PORT   :   parse_impression;
            CLICK_PORT  :   parse_click;
            default :   accept;
        }
    }

    state parse_impression {
        packet.extract(hdr.impression);
        transition accept;
    }

    state parse_click {
        packet.extract(hdr.click);
        transition accept;
    }

}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
            
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
    }
        size = 1024;
        default_action = drop();
    }

    action update_impr_regs() {
        reg_impr_adId.write(hdr.impression.adId, 1);
        reg_impr_time.write(hdr.impression.adId, hdr.impression.impr_time);
    }

    action update_click_regs() {
        reg_click_adId.write(hdr.click.adId, 1);
        reg_click_time.write(hdr.click.adId, hdr.click.click_time);
    }

    apply {
        if(hdr.ipv4.isValid()) {
            if(hdr.impression.isValid()) {
                update_impr_regs();
            } else if(hdr.click.isValid()) {
                update_click_regs();
            }
            
            ipv4_lpm.apply();

        } else {
            drop();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
   
    // bit<32> tmp;
    // count.read(tmp, 0);
    // count.write(0, tmp + 1);

    action drop() {
        mark_to_drop();
    }

    action joinImpr() {
        hdr.result.setValid();
        hdr.result.adId = hdr.impression.adId;
        hdr.result.impr_time = hdr.impression.impr_time;
        reg_click_time.read(hdr.result.click_time, hdr.impression.adId);
        hdr.impression.setInvalid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.udp.length_ = hdr.udp.length_ + 4;
        hdr.udp.checksum = 0;   // udp checksum is optional. Set to 0
    }

    action joinClick() {
        hdr.result.setValid();
        hdr.result.adId = hdr.click.adId;
        hdr.result.click_time = hdr.click.click_time;
        reg_impr_time.read(hdr.result.impr_time, hdr.click.adId);
        hdr.click.setInvalid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.udp.length_ = hdr.udp.length_ + 4;
        hdr.udp.checksum = 0;   // udp checksum is optional. Set to 0
    }

    apply { 
        if(hdr.ipv4.isValid()) {
            if(hdr.impression.isValid()) {
                
                bit<1> tmp;
                reg_click_adId.read(tmp, hdr.impression.adId);
                
                if(tmp == 1) {
                    joinImpr();
                } else {
                    drop();
                }
            } else if(hdr.click.isValid()) {
                
                bit<1> tmp;
                reg_impr_adId.read(tmp, hdr.click.adId);

                if(tmp == 1) {
                    joinClick();
                } else {
                    drop();
                }
            }
        }
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

    // update_checksum(hdr.tcp.isValid(), { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    // update_checksum_with_payload(
    //     hdr.tcp.isValid(), 
    //         { hdr.ipv4.srcAddr, 
    //         hdr.ipv4.dstAddr, 
    //         8w0, 
    //         hdr.ipv4.protocol, 
    //         meta.meta.tcpLength, 
    //         hdr.tcp.srcPort, 
    //         hdr.tcp.dstPort, 
    //         hdr.tcp.seqNo, 
    //         hdr.tcp.ackNo, 
    //         hdr.tcp.dataOffset, 
    //         hdr.tcp.res, 
    //         hdr.tcp.flags, 
    //         hdr.tcp.window, 
    //         hdr.tcp.urgentPtr }, 
    //         hdr.tcp.checksum, 
    //         HashAlgorithm.csum16);

    // update_checksum(
    //     hdr.udp.isValid(),
    //         { hdr.udp.srcPort,
    //         hdr.udp.dstPort,
    //         hdr.udp.length_,
    //         hdr.ipv4.srcAddr,
    //         hdr.ipv4.dstAddr,
    //         hdr.tupleVal.age,
    //         hdr.tupleVal.height,
    //         hdr.tupleVal.weight,
    //         hdr.tupleVal.name},
    //         hdr.udp.checksum,
    //         HashAlgorithm.csum16);

    }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.impression);
        packet.emit(hdr.click);
        packet.emit(hdr.result);

    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;