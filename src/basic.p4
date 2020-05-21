/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_GVT = 0x666;

const bit<32> TYPE_PROP = 0x1919;
const bit<32> TYPE_REQ = 0x1515;
const bit<32> TYPE_DEL = 0x1313;

#define TOTAL_NUMBER_OF_PROCESSES 2
#define INFINITE 1000000

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*GVT definitions*/
typedef bit<32> lpid_t;
typedef bit<32> value_t;
typedef bit<32> round_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

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

header gvt_t{
    bit<32> type;
    lpid_t pid;
    value_t value;
    round_t round;
}

struct metadata {
    bit<32> readedValue;
    bit<32> currentGVT;
    bit<32> numProposals;
    bit<32> minLVT;
}

struct headers {
    ethernet_t     ethernet;
    ipv4_t             ipv4;
    gvt_t               gvt;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
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
            TYPE_IPV4: parse_ipv4;
            TYPE_GVT: parse_gvt;
            default: accept;
        }
    }

    state parse_gvt {
        packet.extract(hdr.gvt);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

register<bit<32>>(TOTAL_NUMBER_OF_PROCESSES) LvtValues;
register<bit<32>>(1) GVT;
//register<bit<32>>(1) numProposalsPerRound;

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    

    action start_round(){
      GVT.write(0, 0);
      LvtValues.write(0, 0);
      LvtValues.write(1, 0);
    }

    action multicast() {
        standard_metadata.mcast_grp = 1;
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
        default_action = NoAction();
    }
    
    apply {
        /*we need to steer packets through different functions here*/
        if(hdr.gvt.type == TYPE_PROP){
          GVT.read(meta.currentGVT, 0);
          /*if the value is equal to the GVT we dont need to check anything*/
          if(meta.currentGVT <= hdr.gvt.value){
            LvtValues.write(hdr.gvt.pid, hdr.gvt.value);
            meta.minLVT = hdr.gvt.value;


            /*begin while*/
            LvtValues.read(meta.readedValue, 0);
            if(meta.readedValue < meta.minLVT){
              meta.minLVT = meta.readedValue;
            }

            LvtValues.read(meta.readedValue, 1);
            if(meta.readedValue < meta.minLVT){
              meta.minLVT = meta.readedValue;
            }
            /*end `while`*/

            if(meta.minLVT != meta.currentGVT){
              GVT.write(0, meta.minLVT);
              hdr.gvt.value = meta.minLVT;
              multicast(); 
            }

            //meta.numProposals = meta.numProposals + 1;
            //numProposalsPerRound.write(0, meta.numProposals);
            //send_to_gvt_c.apply();
            /*TODO: else drop the packet*/
          }
        } else if(hdr.gvt.type == TYPE_REQ){
          start_round();
        }

        /*TODO: deliver simulation packet to end host */
        if (hdr.ipv4.isValid()) {
          ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { } 
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.gvt);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
