"""
流量分析引擎
"""
import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger('wifi_analyzer.analyzer')


@dataclass
class TrafficFlow:
    """流量流定义"""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    packet_count: int = 0
    byte_count: int = 0
    start_time: float = 0
    end_time: float = 0

    packets: List = field(default_factory=list)


@dataclass
class TrafficStatistics:
    """流量统计"""
    total_packets: int = 0
    total_bytes: int = 0

    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # 协议分布
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    protocol_bytes: Dict[str, int] = field(default_factory=dict)

    # 端口统计
    port_counts: Dict[int, int] = field(default_factory=dict)

    # 时间范围
    start_time: float = 0
    end_time: float = 0

    def get_protocol_percentage(self, protocol: str) -> float:
        """获取协议占比百分比"""
        if self.total_packets == 0:
            return 0.0
        return (self.protocol_counts.get(protocol, 0) / self.total_packets) * 100


class TrafficAnalyzer:
    """流量分析引擎"""

    def __init__(self):
        # 流统计
        self.flows: Dict[str, TrafficFlow] = {}

        # 协议统计
        self.protocol_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {'packets': 0, 'bytes': 0}
        )

        # 设备统计
        self.device_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {
                'packets_sent': 0,
                'packets_received': 0,
                'bytes_sent': 0,
                'bytes_received': 0
            }
        )

        # 端口统计
        self.port_stats: Dict[int, Dict[str, int]] = defaultdict(
            lambda: {'packets': 0, 'bytes': 0}
        )

        # 速率计算
        self._rate_window: List[Tuple[float, int]] = []  # (timestamp, packet_count)
        self._start_time: float = 0
        self._last_update: float = 0

        # 全局统计
        self.statistics = TrafficStatistics()

    def process_packet(self, packet: Any) -> Optional[TrafficFlow]:
        """
        处理数据包并更新统计
        :param packet: ParsedPacket对象
        :return: TrafficFlow对象（如果是新流）
        """
        from core.parser.protocol_parser import ParsedPacket

        # 获取时间戳
        current_time = packet.timestamp if hasattr(packet, 'timestamp') else time.time()

        if self._start_time == 0:
            self._start_time = current_time

        self._last_update = current_time

        # 更新全局统计
        self.statistics.total_packets += 1
        self.statistics.total_bytes += packet.length

        # 创建流标识
        flow_key = self._generate_flow_key(packet)

        # 更新流统计
        flow = self._update_flow(flow_key, packet, current_time)

        # 更新协议统计
        protocol = packet.protocol if hasattr(packet, 'protocol') else 'Unknown'
        self.protocol_stats[protocol]['packets'] += 1
        self.protocol_stats[protocol]['bytes'] += packet.length

        # 更新设备统计
        if packet.src_ip:
            self.device_stats[packet.src_ip]['packets_sent'] += 1
            self.device_stats[packet.src_ip]['bytes_sent'] += packet.length

        if packet.dst_ip:
            self.device_stats[packet.dst_ip]['packets_received'] += 1
            self.device_stats[packet.dst_ip]['bytes_received'] += packet.length

        # 更新端口统计
        if packet.src_port:
            self.port_stats[packet.src_port]['packets'] += 1
            self.port_stats[packet.src_port]['bytes'] += packet.length

        if packet.dst_port:
            self.port_stats[packet.dst_port]['packets'] += 1
            self.port_stats[packet.dst_port]['bytes'] += packet.length

        # 更新速率
        self._update_rate(current_time)

        return flow

    def _generate_flow_key(self, packet) -> str:
        """生成流标识"""
        src_ip = packet.src_ip or ''
        dst_ip = packet.dst_ip or ''
        src_port = packet.src_port or 0
        dst_port = packet.dst_port or 0
        protocol = packet.protocol if hasattr(packet, 'protocol') else 'Unknown'

        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"

    def _update_flow(self, flow_key: str, packet, current_time: float) -> TrafficFlow:
        """更新流统计"""
        if flow_key not in self.flows:
            # 创建新流
            flow = TrafficFlow(
                flow_id=flow_key,
                src_ip=packet.src_ip or '',
                dst_ip=packet.dst_ip or '',
                src_port=packet.src_port or 0,
                dst_port=packet.dst_port or 0,
                protocol=packet.protocol if hasattr(packet, 'protocol') else 'Unknown',
                start_time=current_time,
                end_time=current_time
            )
            self.flows[flow_key] = flow
        else:
            flow = self.flows[flow_key]

        # 更新流统计
        flow.packet_count += 1
        flow.byte_count += packet.length
        flow.end_time = current_time

        return flow

    def _update_rate(self, current_time: float) -> None:
        """更新速率计算"""
        # 记录最近的数据包
        self._rate_window.append((current_time, self.statistics.total_packets))

        # 保留最近10秒的数据
        cutoff_time = current_time - 10.0
        self._rate_window = [
            (t, c) for t, c in self._rate_window
            if t >= cutoff_time
        ]

        # 计算速率
        if len(self._rate_window) >= 2:
            first_time, first_count = self._rate_window[0]
            last_time, last_count = self._rate_window[-1]

            duration = last_time - first_time
            if duration > 0:
                packet_diff = last_count - first_count
                self.statistics.packets_per_second = packet_diff / duration

                # 假设平均包大小估算字节速率
                avg_packet_size = self.statistics.total_bytes / self.statistics.total_packets
                self.statistics.bytes_per_second = self.statistics.packets_per_second * avg_packet_size

    def get_statistics(self) -> TrafficStatistics:
        """获取当前统计"""
        self.statistics.protocol_counts = {
            k: v['packets'] for k, v in self.protocol_stats.items()
        }
        self.statistics.protocol_bytes = {
            k: v['bytes'] for k, v in self.protocol_stats.items()
        }
        self.statistics.port_counts = {
            k: v['packets'] for k, v in self.port_stats.items()
        }
        self.statistics.start_time = self._start_time
        self.statistics.end_time = self._last_update

        return self.statistics

    def get_top_talkers(self, n: int = 10) -> List[Tuple[str, Dict]]:
        """
        获取流量最大的设备
        :param n: 返回数量
        :return: [(ip, stats_dict)]
        """
        sorted_devices = sorted(
            self.device_stats.items(),
            key=lambda x: x[1]['bytes_sent'] + x[1]['bytes_received'],
            reverse=True
        )
        return sorted_devices[:n]

    def get_top_flows(self, n: int = 10) -> List[TrafficFlow]:
        """
        获取流量最大的流
        :param n: 返回数量
        :return: [TrafficFlow]
        """
        sorted_flows = sorted(
            self.flows.values(),
            key=lambda f: f.byte_count,
            reverse=True
        )
        return sorted_flows[:n]

    def get_protocol_distribution(self) -> Dict[str, float]:
        """
        获取协议分布百分比
        :return: {protocol: percentage}
        """
        total_packets = self.statistics.total_packets
        if total_packets == 0:
            return {}

        return {
            proto: (stats['packets'] / total_packets) * 100
            for proto, stats in self.protocol_stats.items()
        }

    def get_active_flows(self, timeout: int = 60) -> List[TrafficFlow]:
        """
        获取活跃流
        :param timeout: 超时时间（秒）
        :return: 活跃流列表
        """
        current_time = time.time()
        return [
            flow for flow in self.flows.values()
            if current_time - flow.end_time < timeout
        ]

    def get_flow_count(self) -> int:
        """获取流数量"""
        return len(self.flows)

    def clear_statistics(self) -> None:
        """清除统计"""
        self.flows.clear()
        self.protocol_stats.clear()
        self.device_stats.clear()
        self.port_stats.clear()
        self._rate_window.clear()
        self._start_time = 0
        self._last_update = 0
        self.statistics = TrafficStatistics()

    def get_flow_by_key(self, flow_key: str) -> Optional[TrafficFlow]:
        """根据key获取流"""
        return self.flows.get(flow_key)