from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp, icmp
from typing import Dict, Any
from ryu.ofproto.ofproto_v1_3 import OFPR_NO_MATCH, OFPR_ACTION, OFPR_INVALID_TTL
from ryu.utils import hex_array

import telemetry_writer

IDLE_TIMEOUT: int = 0
HARD_TIMEOUT: int = 0


class LearningSwitch:
    """Handles L2 learning switch functionality with more specific flows."""

    def __init__(self) -> None:
        self.mac_to_port: Dict[int, Dict[str, int]] = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: ofp_event.EventOFPSwitchFeatures) -> None:
        """Install table-miss flow entry on switch connection."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table 0 default / low-priority flow
        inst = [parser.OFPInstructionGotoTable(table_id=1)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=0,
            match=parser.OFPMatch(),  # matches everything
            instructions=inst
        )
        datapath.send_msg(mod)

        # Table 1 table-miss, send to controller
        inst_controller = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS,
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )]
        mod_controller = parser.OFPFlowMod(
            datapath=datapath,
            table_id=1,
            priority=0,
            match=parser.OFPMatch(),
            instructions=inst_controller
        )
        datapath.send_msg(mod_controller)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: ofp_event.EventOFPPacketIn) -> None:
        """Handle packet-in events, perform L2 learning and install more specific flows."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port: int = msg.match['in_port']

        if msg.reason == OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst, src = eth.dst, eth.src

        dpid: int = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn source MAC
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        out_port: int = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Build a more specific match dictionary based on packet type, start with in_port
        match_dict: Dict[str, Any] = {"in_port": in_port}

        # Parse L3/L4 if present
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        arp_pkt = pkt.get_protocol(arp.arp)

        priority = 10  # Default L2 priority

        if arp_pkt:
            # ARP packets - match on L2 + eth_type
            match_dict["eth_src"] = src
            match_dict["eth_dst"] = dst
            match_dict["eth_type"] = 0x0806
            priority = 15

        elif ip_pkt:
            # For IP traffic, match on IP 5-tuple, not MAC addresses
            # This ensures each unique flow gets its own entry
            match_dict["eth_type"] = 0x0800
            match_dict["ipv4_src"] = ip_pkt.src
            match_dict["ipv4_dst"] = ip_pkt.dst
            match_dict["ip_proto"] = ip_pkt.proto
            priority = 20

            if tcp_pkt:
                match_dict["tcp_src"] = tcp_pkt.src_port
                match_dict["tcp_dst"] = tcp_pkt.dst_port
                match_dict["tcp_flags"] = tcp_pkt.bits
                priority = 30

            elif udp_pkt:
                match_dict["udp_src"] = udp_pkt.src_port
                match_dict["udp_dst"] = udp_pkt.dst_port
                priority = 30

            elif icmp_pkt:
                # ICMP - could add type/code if needed
                priority = 25
        else:
            # Non-IP, non-ARP traffic - use L2 matching
            match_dict["eth_src"] = src
            match_dict["eth_dst"] = dst

        # Install flow to avoid packet_in next time
        # Only install if we know the destination port (not flooding)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(**match_dict)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            # Install flow in table 0 (dataplane traffic)
            # If no match in table 0, packet goes to table 1 (controller)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    table_id=0,
                    priority=priority,
                    match=match,
                    instructions=inst,
                    idle_timeout=IDLE_TIMEOUT,
                    hard_timeout=HARD_TIMEOUT,
                    flags=ofproto.OFPFF_SEND_FLOW_REM
                )
            else:
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    table_id=0,
                    priority=priority,
                    match=match,
                    instructions=inst,
                    idle_timeout=IDLE_TIMEOUT,
                    hard_timeout=HARD_TIMEOUT,
                    flags=ofproto.OFPFF_SEND_FLOW_REM
                )
            datapath.send_msg(mod)

        # Send packet out
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

        details: str = (f"buffer_id={msg.buffer_id}, "
                        f"total_len={msg.total_len}, "
                        f"reason={reason}, "
                        f"table_id={msg.table_id}, "
                        f"cookie={msg.cookie}, "
                        f"match={msg.match}, "
                        f"msg_data={hex_array(msg.data) if msg.data else None}, "
                        f"in_port={in_port}, "
                        f"dst={dst}, "
                        f"src={src}, "
                        f"priority={priority}")

        # Log event
        telemetry_writer.log_event(
            dpid=dpid,
            event_type="packet_in",
            details=details
        )
