#include <core.p4>
#include <v1model.p4>
#include "include/headers.p4"
#include "include/parser.p4"


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

register<bit<32>>(TOTAL_NUMBER_OF_PROCESSES) LvtValues;
register<bit<32>>(1) GVT;
//register<bit<32>>(1) PrepareOk;
//register<bit<32>>(1) RoundNumber;

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

    action start_execution(){
      GVT.write(0, 0);
      LvtValues.write(0, 0);
      LvtValues.write(1, 0);
      //PrepareOk.write(0, 0);
      //RoundNumber.write(0, 0);
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

        if(hdr.gvt.isValid()){
          /*we need to steer packets through different functions here*/
          if(hdr.gvt.type == TYPE_PROP && meta.iterator == 0){
            GVT.read(meta.currentGVT, 0);
            //TODO: check for round number
            /*check for conditions to start a new gvt computation*/
            if(meta.currentGVT < hdr.gvt.value){
              LvtValues.write(hdr.gvt.pid, hdr.gvt.value);
              //trigger metadata to start GVT calculation
              meta.iterator = 1;
              /*TODO: you could calculate if the new value would 
              create a new before before multicasting. It would prevent 2n messages... :)*/
              multicast();      
            }else{
              /*If the value is less or equal to the GVT
              we dont need to check anything, just drop it*/
              drop();
            }
          } else if(hdr.gvt.type == TYPE_REQ){
            start_execution();
          }

          if(meta.iterator > 0 ){  /*this condition is to start the GVT computation*/ 
            /*if is the first iteration*/ 
            if(meta.iterator == 1){
              LvtValues.read(meta.minLVT, 0); 
              GVT.read(meta.currentGVT, 0);     
            } 
            /*note that we do not consider 
            a scenario with zero processes */
            LvtValues.read(meta.readedValue, meta.iterator);
            /*selecting the less gvt time*/
            if(meta.readedValue < meta.minLVT){
              meta.minLVT = meta.readedValue;
            }
            /*iterates through the register array*/
            meta.iterator = meta.iterator + 1;
            /*if it is the last iteration*/
            if(meta.iterator == TOTAL_NUMBER_OF_PROCESSES){
              if(meta.currentGVT != meta.minLVT){
                /*update GVT and multicast the new value for processes*/
                GVT.write(0, meta.minLVT);
                hdr.gvt.value = meta.minLVT;
                hdr.gvt.type = TYPE_DEL;
                multicast(); 
              }
            }else{
              resubmit(meta);
            }
          } 
        }

        /*TODO: deliver packet to end host */
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