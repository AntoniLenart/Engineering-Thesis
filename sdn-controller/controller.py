from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from typing import Dict, Any

from learning_switch import LearningSwitch
from telemetry_monitor import TelemetryMonitor


class SimpleSwitchFullTelemetry(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.datapaths: Dict[int, Any] = {}

        # Initialize components
        self.learning_switch = LearningSwitch()
        self.telemetry_monitor = TelemetryMonitor(self.datapaths)

    # ==================== SWITCH INITIALIZATION ====================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures)
    def switch_features_handler(self, ev: ofp_event.EventOFPSwitchFeatures) -> None:
        """Delegate to learning switch handler."""
        self.learning_switch.switch_features_handler(ev)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev: ofp_event.EventOFPStateChange) -> None:
        """Track datapath connections and disconnections."""
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            # Request port description once when switch connects
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    # ==================== PACKET PROCESSING ====================

    @set_ev_cls(ofp_event.EventOFPPacketIn)
    def packet_in_handler(self, ev: ofp_event.EventOFPPacketIn) -> None:
        """Delegate to learning switch handler."""
        self.learning_switch.packet_in_handler(ev)

    # ==================== STATISTICS REPLY HANDLERS ====================

    @set_ev_cls(ofp_event.EventOFPPortStatsReply)
    def port_stats_reply_handler(self, ev: ofp_event.EventOFPPortStatsReply) -> None:
        """Delegate to telemetry monitor handler."""
        TelemetryMonitor.port_stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply)
    def port_desc_reply_handler(self, ev: ofp_event.EventOFPPortDescStatsReply) -> None:
        """Delegate to telemetry monitor handler."""
        TelemetryMonitor.port_desc_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply)
    def flow_stats_reply_handler(self, ev: ofp_event.EventOFPFlowStatsReply) -> None:
        """Delegate to telemetry monitor handler."""
        TelemetryMonitor.flow_stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPTableStatsReply)
    def table_stats_reply_handler(self, ev: ofp_event.EventOFPTableStatsReply) -> None:
        """Delegate to telemetry monitor handler."""
        TelemetryMonitor.table_stats_reply_handler(ev)

    # ==================== EVENT HANDLERS ====================

    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def flow_removed_handler(self, ev: ofp_event.EventOFPFlowRemoved) -> None:
        """Delegate to telemetry monitor handler."""
        TelemetryMonitor.flow_removed_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatus)
    def port_status_handler(self, ev: ofp_event.EventOFPPortStatus) -> None:
        """Delegate to telemetry monitor handler."""
        TelemetryMonitor.port_status_handler(ev)
