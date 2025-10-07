from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from typing import Any, Dict
from ryu.ofproto.ofproto_v1_3 import (OFPRR_IDLE_TIMEOUT, OFPRR_HARD_TIMEOUT, OFPRR_DELETE, OFPRR_GROUP_DELETE,
                                      OFPPR_ADD, OFPPR_DELETE, OFPPR_MODIFY)

import telemetry_writer

POLL_INTERVAL: float = 1.0


class TelemetryMonitor:
    """Handles telemetry collection and statistics monitoring."""

    def __init__(self, datapaths: Dict[int, Any]) -> None:
        self.datapaths = datapaths
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self) -> None:
        """Periodically request statistics from all connected switches."""
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(POLL_INTERVAL)

    @staticmethod
    def _request_stats(dp: Any) -> None:
        """Send statistics requests to a datapath."""
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofproto.OFPP_ANY))
        dp.send_msg(parser.OFPFlowStatsRequest(dp))
        dp.send_msg(parser.OFPTableStatsRequest(dp))

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(ev: ofp_event.EventOFPPortStatsReply) -> None:
        """Handle port statistics replies."""
        dpid: int = ev.msg.datapath.id
        telemetry_writer.write_port_stats(dpid, ev.msg.body)

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(ev: ofp_event.EventOFPPortDescStatsReply) -> None:
        """Handle port description statistics replies.
           It is triggered once when the switch connects."""
        dpid: int = ev.msg.datapath.id
        telemetry_writer.write_port_desc(dpid, ev.msg.body)

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(ev: ofp_event.EventOFPFlowStatsReply) -> None:
        """Handle flow statistics replies."""
        dpid: int = ev.msg.datapath.id
        telemetry_writer.write_flow_stats(dpid, ev.msg.body)

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def table_stats_reply_handler(ev: ofp_event.EventOFPTableStatsReply) -> None:
        """Handle table statistics replies."""
        dpid: int = ev.msg.datapath.id
        telemetry_writer.write_table_stats(dpid, ev.msg.body)

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(ev: ofp_event.EventOFPFlowRemoved) -> None:
        """Handle flow removed events."""
        dpid: int = ev.msg.datapath.id
        msg = ev.msg

        if msg.reason == OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        details: str = (f"cookie={msg.cookie}, "
                        f"priority={msg.priority}, "
                        f"reason={reason}, "
                        f"duration_sec={getattr(msg, 'duration_sec', '')}, "
                        f"duration_nsec={getattr(msg, 'duration_nsec', '')}, "
                        f"idle_timeout={msg.idle_timeout}, "
                        f"hard_timeout={msg.hard_timeout}, "
                        f"packet_count={msg.packet_count}, "
                        f"byte_count={msg.byte_count}, "
                        f"match={str(msg.match)}, ")
        telemetry_writer.log_event(dpid, "flow_removed", details)

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(ev: ofp_event.EventOFPPortStatus) -> None:
        """Handle port status change events."""
        dpid: int = ev.msg.datapath.id
        msg = ev.msg
        if msg.reason == OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'
        desc = ev.msg.desc
        details: str = (f"reason={reason}, "
                        f"advertised={desc.advertised}, "
                        f"curr={desc.curr}, "
                        f"curr_speed={desc.curr_speed}, "
                        f"hw_addr={desc.hw_addr}, "
                        f"max_speed={desc.max_speed}, "
                        f"name={desc.name}, "
                        f"peer={desc.peer}, "
                        f"port_no={desc.port_no}, "
                        f"state={desc.state}, "
                        f"supported={desc.supported}")
        telemetry_writer.log_event(dpid, "port_status", details)
