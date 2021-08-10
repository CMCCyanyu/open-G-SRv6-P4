/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>


typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header Ethernet_h {
    MacAddress dstAddr;
    MacAddress srcAddr;
    bit<16>   etherType;
}


header IPv6_h {
    bit<4>    version;
    bit<8>    class;
    bit<20>   flowlabel;
    bit<16>   payloadlength;
    bit<8>    nextheader;
    bit<8>    hoplimit;
    IPv6Address srcAddr;
    IPv6Address dstAddr;
}


header SRH_h {
    bit<8> nextheader;
    bit<8> hdrextlen;
    bit<8> routingtype;
    bit<8> segmentleft;
    bit<8> lastentry;
    bit<8> flags;
    bit<16> tag;
}

header dst_SID_h {
    bit<128> sid0;
}

header mid_var_h {
    bit<128> mid;
}

header last_SID_h {
    bit<128> last_sid;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

 struct my_ingress_headers_t {
    Ethernet_h         ethernet;
    IPv6_h             ipv6;

    SRH_h              srh;
    
    //dst_SID_h sidh0;
    //last_SID_h sidhl;
}

struct my_ingress_metadata_t {
    bit<1> is_end_label;
	last_SID_h active_sid;
    mid_var_h[30] mid_h;
    
}

parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
	
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    
    state meta_init {
        meta.is_end_label = 0;
        //meta.active_sid = 0;
        //meta.useless = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x86dd:  parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextheader) {
            43 : parse_srh;
            default : accept;
        }
    }

    state parse_srh {
        pkt.extract(hdr.srh);
        transition parse_mid_sid;
    }

    state parse_mid_sid {
        transition select(hdr.srh.segmentleft) {
            2 : parse_sid0;
            3 : parse_sid1;
            4 : parse_sid2;
            5 : parse_sid3;
            6 : parse_sid4;
            7 : parse_sid5;
            8 : parse_sid6;
            9 : parse_sid7;
            10 : parse_sid8;
            11 : parse_sid9;

            12 : parse_sid10;
            13 : parse_sid11;
            14 : parse_sid12;
            15 : parse_sid13;
            16 : parse_sid14;
            17 : parse_sid15;
            18 : parse_sid16;
            19 : parse_sid17;
            20 : parse_sid18;
            21 : parse_sid19;
            
            22 : parse_sid20;
            23 : parse_sid21;
            24 : parse_sid22;
            25 : parse_sid23;
            26 : parse_sid24;
            27 : parse_sid25;
            28 : parse_sid26;
            29 : parse_sid27;
            30 : parse_sid28;
            31 : parse_sid29;
            /*
            32 : parse_sid30;
            33 : parse_sid31;
            34 : parse_sid32;
            35 : parse_sid33;
            36 : parse_sid34;
            37 : parse_sid35;
            38 : parse_sid36;
            39 : parse_sid37;
            40 : parse_sid38;
            41 : parse_sid39;
            
            42 : parse_sid40;
            43 : parse_sid41;
            44 : parse_sid42;
            45 : parse_sid43;
            46 : parse_sid44;
            47 : parse_sid45;
            48 : parse_sid46;
            49 : parse_sid47;
            50 : parse_sid48;
            51 : parse_sid49;
            
            52 : parse_sid50;
            53 : parse_sid51;
            54 : parse_sid52;
            55 : parse_sid53;
            56 : parse_sid54;
            57 : parse_sid55;
            58 : parse_sid56;
            59 : parse_sid57;
            60 : parse_sid58;*/
            default : accept;
        }
    }
    
    state parse_sid0 {
        pkt.extract(meta.mid_h[0]);
        transition parse_last_sid;
    }
    state parse_sid1 {
        pkt.extract(meta.mid_h[1]);
        transition parse_sid0;
    }
    state parse_sid2 {
        pkt.extract(meta.mid_h[2]);
        transition parse_sid1;
    }
    state parse_sid3 {
        pkt.extract(meta.mid_h[3]);
        transition parse_sid2;
    }
    state parse_sid4 {
        pkt.extract(meta.mid_h[4]);
        transition parse_sid3;
    }
    state parse_sid5 {
        pkt.extract(meta.mid_h[5]);
        transition parse_sid4;
    }
    state parse_sid6 {
        pkt.extract(meta.mid_h[6]);
        transition parse_sid5;
    }
    state parse_sid7 {
        pkt.extract(meta.mid_h[7]);
        transition parse_sid6;
    }
    state parse_sid8 {
        pkt.extract(meta.mid_h[8]);
        transition parse_sid7;
    }
    state parse_sid9 {
        pkt.extract(meta.mid_h[9]);
        transition parse_sid8;
    }
    state parse_sid10 {
        pkt.extract(meta.mid_h[10]);
        transition parse_sid9;
    }
    state parse_sid11 {
        pkt.extract(meta.mid_h[11]);
        transition parse_sid10;
    }
    state parse_sid12 {
        pkt.extract(meta.mid_h[12]);
        transition parse_sid11;
    }
    state parse_sid13 {
        pkt.extract(meta.mid_h[13]);
        transition parse_sid12;
    }
    state parse_sid14 {
        pkt.extract(meta.mid_h[14]);
        transition parse_sid13;
    }
    state parse_sid15 {
        pkt.extract(meta.mid_h[15]);
        transition parse_sid14;
    }
    state parse_sid16 {
        pkt.extract(meta.mid_h[16]);
        transition parse_sid15;
    }
    state parse_sid17 {
        pkt.extract(meta.mid_h[17]);
        transition parse_sid16;
    }
    state parse_sid18 {
        pkt.extract(meta.mid_h[18]);
        transition parse_sid17;
    }
    state parse_sid19 {
        pkt.extract(meta.mid_h[19]);
        transition parse_sid18;
    }
    
    state parse_sid20 {
        pkt.extract(meta.mid_h[20]);
        transition parse_sid19;
    }
    state parse_sid21 {
        pkt.extract(meta.mid_h[21]);
        transition parse_sid20;
    }
    state parse_sid22 {
        pkt.extract(meta.mid_h[22]);
        transition parse_sid21;
    }
    state parse_sid23 {
        pkt.extract(meta.mid_h[23]);
        transition parse_sid22;
    }
    state parse_sid24 {
        pkt.extract(meta.mid_h[24]);
        transition parse_sid23;
    }
    state parse_sid25 {
        pkt.extract(meta.mid_h[25]);
        transition parse_sid24;
    }
    state parse_sid26 {
        pkt.extract(meta.mid_h[26]);
        transition parse_sid25;
    }
    state parse_sid27 {
        pkt.extract(meta.mid_h[27]);
        transition parse_sid26;
    }
    state parse_sid28 {
        pkt.extract(meta.mid_h[28]);
        transition parse_sid27;
    }
    state parse_sid29 {
        pkt.extract(meta.mid_h[29]);
        transition parse_sid28;
    }
    /*
    state parse_sid30 {
        pkt.extract(meta.mid_h[30]);
        transition parse_sid29;
    }
    state parse_sid31 {
        pkt.extract(meta.mid_h[31]);
        transition parse_sid30;
    }
    state parse_sid32 {
        pkt.extract(meta.mid_h[32]);
        transition parse_sid31;
    }
    state parse_sid33 {
        pkt.extract(meta.mid_h[33]);
        transition parse_sid32;
    }
    state parse_sid34 {
        pkt.extract(meta.mid_h[34]);
        transition parse_sid33;
    }
    state parse_sid35 {
        pkt.extract(meta.mid_h[35]);
        transition parse_sid34;
    }
    state parse_sid36 {
        pkt.extract(meta.mid_h[36]);
        transition parse_sid35;
    }
    state parse_sid37 {
        pkt.extract(meta.mid_h[37]);
        transition parse_sid36;
    }
    state parse_sid38 {
        pkt.extract(meta.mid_h[38]);
        transition parse_sid37;
    }
    state parse_sid39 {
        pkt.extract(meta.mid_h[39]);
        transition parse_sid38;
    }

    state parse_sid40 {
        pkt.extract(meta.mid_h[40]);
        transition parse_sid39;
    }
    state parse_sid41 {
        pkt.extract(meta.mid_h[41]);
        transition parse_sid40;
    }
    state parse_sid42 {
        pkt.extract(meta.mid_h[42]);
        transition parse_sid41;
    }
    state parse_sid43 {
        pkt.extract(meta.mid_h[43]);
        transition parse_sid42;
    }
    state parse_sid44 {
        pkt.extract(meta.mid_h[44]);
        transition parse_sid43;
    }
    state parse_sid45 {
        pkt.extract(meta.mid_h[45]);
        transition parse_sid44;
    }
    state parse_sid46 {
        pkt.extract(meta.mid_h[46]);
        transition parse_sid45;
    }
    state parse_sid47 {
        pkt.extract(meta.mid_h[47]);
        transition parse_sid46;
    }
    state parse_sid48 {
        pkt.extract(meta.mid_h[48]);
        transition parse_sid47;
    }
    state parse_sid49 {
        pkt.extract(meta.mid_h[49]);
        transition parse_sid48;
    }
    
    state parse_sid50 {
        pkt.extract(meta.mid_h[50]);
        transition parse_sid49;
    }
    state parse_sid51 {
        pkt.extract(meta.mid_h[51]);
        transition parse_sid50;
    }
    state parse_sid52 {
        pkt.extract(meta.mid_h[52]);
        transition parse_sid51;
    }
    state parse_sid53 {
        pkt.extract(meta.mid_h[53]);
        transition parse_sid52;
    }
    state parse_sid54 {
        pkt.extract(meta.mid_h[54]);
        transition parse_sid53;
    }
    state parse_sid55 {
        pkt.extract(meta.mid_h[55]);
        transition parse_sid54;
    }
    state parse_sid56 {
        pkt.extract(meta.mid_h[56]);
        transition parse_sid55;
    }
    state parse_sid57 {
        pkt.extract(meta.mid_h[57]);
        transition parse_sid56;
    }
    state parse_sid58 {
        pkt.extract(meta.mid_h[58]);
        transition parse_sid57;
    }*/

    state parse_last_sid {
        pkt.extract(meta.active_sid);
        transition accept;
    }

}

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
//#ifdef BYPASS_EGRESS
//        ig_tm_md.bypass_egress = 1;
//#endif
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

	action set_end_label() {
		meta.is_end_label = 1;
	}

    table match_inport {
        key = {ig_intr_md.ingress_port : exact;}
        actions = {send;drop;}
        default_action = send(64);
        size = 512;
    }
  
    table ipv6_lpm {
        key     = { hdr.ipv6.dstAddr : lpm; }
        actions = { send; drop; }
        
        default_action = send(64);
        size           = 512;
    }

	table match_end {
		key = {hdr.ipv6.dstAddr:exact;}
		actions = {set_end_label;}
		size = 512;
	}
    
    apply {
        match_inport.apply();
		if (match_end.apply().hit) {
			hdr.srh.segmentleft = hdr.srh.segmentleft - 1;
			hdr.ipv6.dstAddr = meta.active_sid.last_sid;
		}

        if (hdr.ipv6.isValid()) {
            ipv6_lpm.apply();
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
        /*
        pkt.emit(meta.mid_h[58]);
        pkt.emit(meta.mid_h[57]);
        pkt.emit(meta.mid_h[56]);
        pkt.emit(meta.mid_h[55]);
        pkt.emit(meta.mid_h[54]);
        pkt.emit(meta.mid_h[53]);
        pkt.emit(meta.mid_h[52]);
        pkt.emit(meta.mid_h[51]);
        pkt.emit(meta.mid_h[50]);
        pkt.emit(meta.mid_h[49]);
        pkt.emit(meta.mid_h[48]);
        pkt.emit(meta.mid_h[47]);
        pkt.emit(meta.mid_h[46]);
        pkt.emit(meta.mid_h[45]);
        pkt.emit(meta.mid_h[44]);
        pkt.emit(meta.mid_h[43]);
        pkt.emit(meta.mid_h[42]);
        pkt.emit(meta.mid_h[41]);
        pkt.emit(meta.mid_h[40]);
        pkt.emit(meta.mid_h[39]);
        pkt.emit(meta.mid_h[38]);
        pkt.emit(meta.mid_h[37]);
        pkt.emit(meta.mid_h[36]);
        pkt.emit(meta.mid_h[35]);
        pkt.emit(meta.mid_h[34]);
        pkt.emit(meta.mid_h[33]);
        pkt.emit(meta.mid_h[32]);
        pkt.emit(meta.mid_h[31]);
        pkt.emit(meta.mid_h[30]);*/
        pkt.emit(meta.mid_h[29]);
        pkt.emit(meta.mid_h[28]);
        pkt.emit(meta.mid_h[27]);
        pkt.emit(meta.mid_h[26]);
        pkt.emit(meta.mid_h[25]);
        pkt.emit(meta.mid_h[24]);
        pkt.emit(meta.mid_h[23]);
        pkt.emit(meta.mid_h[22]);
        pkt.emit(meta.mid_h[21]);
        pkt.emit(meta.mid_h[20]);
        pkt.emit(meta.mid_h[19]);
        pkt.emit(meta.mid_h[18]);
        pkt.emit(meta.mid_h[17]);
        pkt.emit(meta.mid_h[16]);
        pkt.emit(meta.mid_h[15]);
        pkt.emit(meta.mid_h[14]);
        pkt.emit(meta.mid_h[13]);
        pkt.emit(meta.mid_h[12]);
        pkt.emit(meta.mid_h[11]);
        pkt.emit(meta.mid_h[10]);
        pkt.emit(meta.mid_h[9]);
        pkt.emit(meta.mid_h[8]);
        pkt.emit(meta.mid_h[7]);
        pkt.emit(meta.mid_h[6]);
        pkt.emit(meta.mid_h[5]);
        pkt.emit(meta.mid_h[4]);
        pkt.emit(meta.mid_h[3]);
        pkt.emit(meta.mid_h[2]);
        pkt.emit(meta.mid_h[1]);
        pkt.emit(meta.mid_h[0]);
        pkt.emit(meta.active_sid);
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
