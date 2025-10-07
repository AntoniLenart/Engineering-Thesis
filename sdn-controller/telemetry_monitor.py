from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from typing import Any, Dict

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
        stat = ev.msg
        details: str = (f"priority={stat.priority}, match={stat.match}, "
                        f"duration_sec={getattr(stat, 'duration_sec', '')}, "
                        f"packet_count={stat.packet_count}, byte_count={stat.byte_count}, "
                        f"reason={stat.reason}")
        telemetry_writer.log_event(dpid, "flow_removed", details)

    @staticmethod
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(ev: ofp_event.EventOFPPortStatus) -> None:
        """Handle port status change events."""
        dpid: int = ev.msg.datapath.id
        reason: int = ev.msg.reason
        desc = ev.msg.desc
        details: str = (f"reason={reason}, port_no={desc.port_no}, hw_addr={desc.hw_addr}, "
                        f"config={desc.config}, state={desc.state}")
        telemetry_writer.log_event(dpid, "port_status", details)
