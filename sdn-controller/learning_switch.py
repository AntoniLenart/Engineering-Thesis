from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet
from typing import Dict

import telemetry_writer


class LearningSwitch:
    """Handles L2 learning switch functionality."""

    def __init__(self) -> None:
        self.mac_to_port: Dict[int, Dict[str, int]] = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: ofp_event.EventOFPSwitchFeatures) -> None:
        """Install table-miss flow entry on switch connection."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: ofp_event.EventOFPPacketIn) -> None:
        """Handle packet-in events and perform L2 learning."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port: int = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst: str = eth.dst
        src: str = eth.src

        dpid: int = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port: int = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst,
                                    eth_src=src)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        buffer_id=msg.buffer_id,
                                        priority=1,
                                        match=match,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        priority=1,
                                        match=match,
                                        instructions=inst)
            datapath.send_msg(mod)

        # Send packet out
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

        # Log event
        telemetry_writer.log_event(dpid=dpid,
                                   event_type="packet_in",
                                   details=f"in_port={in_port}, dst={dst}, src={src}")
