#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parser.p4"


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}



register<bit<32>>(TOTAL_NUMBER_OF_PROCESSES) LvtValues;
register<bit<32>>(1) GVT;

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;i
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

          LvtValues.write(hdr.gvt.pid, hdr.gvt.value);
          /*if the value is equal to the GVT we dont need to check anything*/
          if(meta.currentGVT <= hdr.gvt.value){
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

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { } 
}

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

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;