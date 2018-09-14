/* -*- P4_16 -*- */

/*
 * P4 static joins
 *
 * The switch receives a packet from the stream, joins the packet on 'age' colmumn 
    with static match/action tables containing (age, zip_code) tuples. Output packet is the
    inner join (age, height, weight, name, zip_code)
    
    example: tuples = (int age, int height, int weight, varchar 10 name)

    SELECT age, height, weight, name, zip_code
    FROM tuples
    INNER JOIN static_table ON tuples.age = static_table.age
    WHERE name = 'alice'

    result = (int age, varchar 10 name, int count)

 * If an unknown operation is specified or the header is not valid, the packet
 * is dropped 
 */

#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROT_UDP = 0x11; 
const bit<16> DPORT = 0x0da2; // 3490
const bit<32> MY_AGE = 0x00000032; // 50
const bit<80> MY_NAME = 0x616c6963650000000000; // alice


typedef bit<9>  egressSpec_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> macAddr_t;

typedef bit<32> zip_code_t;

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
header tuple_t {
    bit<32> age;
    bit<32> height;
    bit<32> weight;
    bit<80> name;
}

header result_t {
    bit<32> age;
    bit<32> height;
    bit<32> weight;
    bit<80> name;
    zip_code_t zip_code;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    udp_t       udp;
    tuple_t     tupleVal;
    result_t    result;
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
        transition select(hdr.udp.dstPort) {
            DPORT   :   parse_tuple;
            default :   accept;
        }
    }

    state parse_tuple {
        packet.extract(hdr.tupleVal);
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

    apply {
        if(hdr.tupleVal.isValid() && hdr.ipv4.isValid()) {
            // if(hdr.tupleVal.name == MY_NAME) {
            if(hdr.tupleVal.age <= MY_AGE) {
                ipv4_lpm.apply();
            } else {
                drop();
            }

        } else if(hdr.ipv4.isValid()) {
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
   
    action drop() {
        mark_to_drop();
    }

    // join occurs here. ipv4 and udp length fields both increase when tuple fields/columns are added
    action update_headers(zip_code_t z) {
        hdr.result.setValid();
        hdr.result.age = hdr.tupleVal.age;
        hdr.result.name = hdr.tupleVal.name;
        hdr.result.height = hdr.tupleVal.height;
        hdr.result.weight = hdr.tupleVal.weight;
        hdr.result.zip_code = z;
        hdr.tupleVal.setInvalid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.udp.length_ = hdr.udp.length_ + 4;
        hdr.udp.checksum = 0;   // udp checksum is optional. Set to 0
    }


    table join_exact {
        key = {
            hdr.tupleVal.name: exact;
        }
        actions = {
            update_headers;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply { 
        if(hdr.tupleVal.isValid() && hdr.ipv4.isValid()) {
            join_exact.apply();
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
        packet.emit(hdr.tupleVal);
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