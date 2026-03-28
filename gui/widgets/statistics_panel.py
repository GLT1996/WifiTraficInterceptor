"""
统计面板
"""
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QGroupBox, QGridLayout
from PyQt6.QtCore import Qt
from typing import Dict

from core.analyzer.traffic_analyzer import TrafficStatistics


class StatisticsPanel(QWidget):
    """统计面板"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """设置UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # 全局统计组
        global_group = QGroupBox("Traffic Statistics")
        global_layout = QGridLayout(global_group)

        self.total_packets_label = QLabel("0")
        self.total_bytes_label = QLabel("0")
        self.rate_pps_label = QLabel("0.0")
        self.rate_bps_label = QLabel("0.0 KB/s")

        global_layout.addWidget(QLabel("Total Packets:"), 0, 0)
        global_layout.addWidget(self.total_packets_label, 0, 1)
        global_layout.addWidget(QLabel("Total Bytes:"), 1, 0)
        global_layout.addWidget(self.total_bytes_label, 1, 1)
        global_layout.addWidget(QLabel("Packets/sec:"), 2, 0)
        global_layout.addWidget(self.rate_pps_label, 2, 1)
        global_layout.addWidget(QLabel("Bytes/sec:"), 3, 0)
        global_layout.addWidget(self.rate_bps_label, 3, 1)

        layout.addWidget(global_group)

        # 协议分布组
        protocol_group = QGroupBox("Protocol Distribution")
        protocol_layout = QVBoxLayout(protocol_group)

        self.protocol_labels = {}
        protocols = ['TCP', 'UDP', 'HTTP', 'DNS', 'HTTPS', 'Other']

        for proto in protocols:
            label = QLabel(f"{proto}: 0 (0%)")
            self.protocol_labels[proto] = label
            protocol_layout.addWidget(label)

        layout.addWidget(protocol_group)

        # Top Talkers组
        talkers_group = QGroupBox("Top Talkers")
        talkers_layout = QVBoxLayout(talkers_group)

        self.talkers_labels = []
        for i in range(5):
            label = QLabel("-")
            self.talkers_labels.append(label)
            talkers_layout.addWidget(label)

        layout.addWidget(talkers_group)

        # 添加弹性空间
        layout.addStretch()

    def update_statistics(self, stats: TrafficStatistics) -> None:
        """更新统计信息"""
        # 全局统计
        self.total_packets_label.setText(str(stats.total_packets))
        self.total_bytes_label.setText(self._format_bytes(stats.total_bytes))
        self.rate_pps_label.setText(f"{stats.packets_per_second:.1f}")
        self.rate_bps_label.setText(self._format_bytes_per_second(stats.bytes_per_second))

        # 协议分布
        proto_dist = {}
        if stats.total_packets > 0:
            proto_dist = {
                proto: (count / stats.total_packets) * 100
                for proto, count in stats.protocol_counts.items()
            }

        for proto, label in self.protocol_labels.items():
            count = stats.protocol_counts.get(proto, 0)
            percent = proto_dist.get(proto, 0)
            label.setText(f"{proto}: {count} ({percent:.1f}%)")

        # 更新Other
        other_count = stats.protocol_counts.get('Other', 0)
        other_percent = proto_dist.get('Other', 0)
        self.protocol_labels['Other'].setText(f"Other: {other_count} ({other_percent:.1f}%)")

    def update_top_talkers(self, talkers: list) -> None:
        """更新Top Talkers"""
        for i, label in enumerate(self.talkers_labels):
            if i < len(talkers):
                ip, stats = talkers[i]
                total_bytes = stats['bytes_sent'] + stats['bytes_received']
                label.setText(f"{ip}: {self._format_bytes(total_bytes)}")
            else:
                label.setText("-")

    def _format_bytes(self, bytes_count: int) -> str:
        """格式化字节数"""
        if bytes_count >= 1024 * 1024 * 1024:
            return f"{bytes_count / (1024*1024*1024):.2f} GB"
        elif bytes_count >= 1024 * 1024:
            return f"{bytes_count / (1024*1024):.2f} MB"
        elif bytes_count >= 1024:
            return f"{bytes_count / 1024:.2f} KB"
        else:
            return f"{bytes_count} B"

    def _format_bytes_per_second(self, bps: float) -> str:
        """格式化字节速率"""
        if bps >= 1024 * 1024:
            return f"{bps / (1024*1024):.2f} MB/s"
        elif bps >= 1024:
            return f"{bps / 1024:.2f} KB/s"
        else:
            return f"{bps:.1f} B/s"