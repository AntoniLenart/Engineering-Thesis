from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from typing import Dict, Any
from ryu.ofproto.ofproto_v1_3 import OFPR_NO_MATCH, OFPR_ACTION, OFPR_INVALID_TTL
from ryu.utils import hex_array

import telemetry_writer


IDLE_TIMEOUT: int = 10
HARD_TIMEOUT: int = 20


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
        dst: str = eth.dst
        src: str = eth.src

        dpid: int = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port: int = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Build a more specific match dictionary
        match_dict: Dict[str, Any] = {"in_port": in_port, "eth_src": src, "eth_dst": dst}

        # Parse L3/L4 if present
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        tcp_flag_counts: Dict[str, int] = {"S": 0, "A": 0, "F": 0, "R": 0}

        if ip_pkt:
            match_dict["eth_type"] = 0x0800
            match_dict["ip_proto"] = ip_pkt.proto
            match_dict["ipv4_src"] = ip_pkt.src
            match_dict["ipv4_dst"] = ip_pkt.dst

            if tcp_pkt:
                match_dict["tcp_src"] = tcp_pkt.src_port
                match_dict["tcp_dst"] = tcp_pkt.dst_port
                # Count flags from the triggering packet as an initial indicator
                flags = tcp_pkt.bits  # Ryu tcp.tcp.bits is an int mask
                # Map common bits -> letters (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04)
                if flags & 0x02:
                    tcp_flag_counts["S"] += 1
                if flags & 0x10:
                    tcp_flag_counts["A"] += 1
                if flags & 0x01:
                    tcp_flag_counts["F"] += 1
                if flags & 0x04:
                    tcp_flag_counts["R"] += 1

            elif udp_pkt:
                match_dict["udp_src"] = udp_pkt.src_port
                match_dict["udp_dst"] = udp_pkt.dst_port

        # Install flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(**match_dict)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            # include timeouts for telemetry experiments
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        buffer_id=msg.buffer_id,
                                        priority=1,  # set higher than table-miss
                                        match=match,
                                        instructions=inst,
                                        idle_timeout=IDLE_TIMEOUT,
                                        hard_timeout=HARD_TIMEOUT,
                                        flags=ofproto.OFPFF_SEND_FLOW_REM)  # request flow removed msg
            else:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        priority=1,  # set higher than table-miss
                                        match=match,
                                        instructions=inst,
                                        idle_timeout=IDLE_TIMEOUT,
                                        hard_timeout=HARD_TIMEOUT,
                                        flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)

        # Send packet out
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
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
                        f"tcp_flags={tcp_flag_counts if tcp_pkt else None}")

        # Log event
        telemetry_writer.log_event(dpid=dpid,
                                   event_type="packet_in",
                                   details=details)
