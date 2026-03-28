"""
过滤器对话框
"""
import re
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QComboBox, QPushButton, QGroupBox, QLabel
)
from PyQt6.QtCore import Qt


class FilterDialog(QDialog):
    """过滤器对话框"""

    def __init__(self, parent=None, current_filter: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Packet Filter")
        self.setMinimumWidth(400)
        self.current_filter = current_filter
        self._setup_ui()
        self._parse_current_filter()

    def _setup_ui(self) -> None:
        """设置UI"""
        layout = QVBoxLayout(self)

        # BPF过滤器
        bpf_group = QGroupBox("BPF Filter Expression")
        bpf_layout = QVBoxLayout(bpf_group)

        self.filter_edit = QLineEdit()
        self.filter_edit.setText(self.current_filter)
        self.filter_edit.setPlaceholderText("e.g., tcp port 80, udp, host 192.168.1.1")
        bpf_layout.addWidget(self.filter_edit)

        # 常用过滤器
        presets_label = QLabel("Common Filters:")
        bpf_layout.addWidget(presets_label)

        self.preset_combo = QComboBox()
        self.preset_combo.addItem("No Filter", "")
        self.preset_combo.addItem("TCP only", "tcp")
        self.preset_combo.addItem("UDP only", "udp")
        self.preset_combo.addItem("HTTP (port 80)", "tcp port 80")
        self.preset_combo.addItem("HTTPS (port 443)", "tcp port 443")
        self.preset_combo.addItem("DNS", "udp port 53")
        self.preset_combo.addItem("ICMP", "icmp")
        self.preset_combo.addItem("ARP", "arp")
        self.preset_combo.currentIndexChanged.connect(self._on_preset_changed)
        bpf_layout.addWidget(self.preset_combo)

        layout.addWidget(bpf_group)

        # 快速过滤组
        quick_group = QGroupBox("Quick Filters")
        quick_layout = QFormLayout(quick_group)

        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("e.g., 192.168.1.100")
        quick_layout.addRow("IP Address:", self.ip_edit)

        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("e.g., 80, 443")
        quick_layout.addRow("Port:", self.port_edit)

        self.proto_combo = QComboBox()
        self.proto_combo.addItem("Any", "")
        self.proto_combo.addItem("TCP", "tcp")
        self.proto_combo.addItem("UDP", "udp")
        self.proto_combo.addItem("ICMP", "icmp")
        quick_layout.addRow("Protocol:", self.proto_combo)

        layout.addWidget(quick_group)

        # 按钮
        button_layout = QHBoxLayout()

        apply_button = QPushButton("Apply")
        apply_button.clicked.connect(self._apply_filter)
        button_layout.addWidget(apply_button)

        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self._clear_filter)
        button_layout.addWidget(clear_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

    def _on_preset_changed(self, index: int) -> None:
        """预设过滤器改变"""
        filter_text = self.preset_combo.currentData()
        if filter_text:
            self.filter_edit.setText(filter_text)

    def _apply_filter(self) -> None:
        """应用过滤器"""
        # 构建过滤器表达式
        filter_parts = []

        # 快速过滤 - IP
        ip = self.ip_edit.text().strip()
        if ip:
            filter_parts.append(f"host {ip}")

        # 快速过滤 - 端口
        port = self.port_edit.text().strip()
        if port:
            proto = self.proto_combo.currentData()
            if proto:
                filter_parts.append(f"{proto} port {port}")
            else:
                filter_parts.append(f"port {port}")

        # 快速过滤 - 协议
        proto = self.proto_combo.currentData()
        if proto and not port:
            filter_parts.append(proto)

        # 合并快速过滤
        quick_filter = " and ".join(filter_parts) if filter_parts else ""

        # BPF表达式
        bpf = self.filter_edit.text().strip()

        # 合并所有过滤器
        if bpf and quick_filter:
            self.filter_edit.setText(f"({bpf}) and {quick_filter}")
        elif quick_filter:
            self.filter_edit.setText(quick_filter)
        # 如果只有 BPF，保持不变

        self.accept()

    def _clear_filter(self) -> None:
        """清除过滤器"""
        self.filter_edit.clear()
        self.ip_edit.clear()
        self.port_edit.clear()
        self.proto_combo.setCurrentIndex(0)
        self.preset_combo.setCurrentIndex(0)
        self.accept()

    def _parse_current_filter(self) -> None:
        """解析当前过滤器并填充字段"""
        if not self.current_filter:
            return

        # 显示在 BPF 编辑框中
        self.filter_edit.setText(self.current_filter)

        # 尝试解析简单的过滤器
        filter_lower = self.current_filter.lower()

        # 解析 host x.x.x.x
        host_match = re.search(r'host\s+(\d+\.\d+\.\d+\.\d+)', filter_lower)
        if host_match:
            self.ip_edit.setText(host_match.group(1))

        # 解析端口
        port_match = re.search(r'port\s+(\d+)', filter_lower)
        if port_match:
            self.port_edit.setText(port_match.group(1))

        # 解析协议
        for proto in ['tcp', 'udp', 'icmp']:
            if proto in filter_lower:
                index = self.proto_combo.findData(proto)
                if index >= 0:
                    self.proto_combo.setCurrentIndex(index)
                break

    def get_filter(self) -> str:
        """获取过滤器表达式"""
        return self.filter_edit.text().strip()