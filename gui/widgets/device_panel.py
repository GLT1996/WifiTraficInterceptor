"""
设备面板
"""
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
from typing import List

from core.analyzer.device_tracker import DeviceInfo


class DevicePanel(QWidget):
    """设备面板"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """设置UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # 设备表格
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(['MAC', 'IP', 'Vendor', 'Device Type', 'Packets'])

        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # 设置列宽
        self.table.setColumnWidth(0, 120)  # MAC
        self.table.setColumnWidth(1, 100)  # IP
        self.table.setColumnWidth(2, 80)   # Vendor
        self.table.setColumnWidth(3, 80)   # Device Type
        self.table.setColumnWidth(4, 60)   # Packets

        layout.addWidget(self.table)

    def update_devices(self, devices: List[DeviceInfo]) -> None:
        """更新设备列表"""
        self.table.setRowCount(len(devices))

        for i, device in enumerate(devices):
            # MAC地址
            mac_item = QTableWidgetItem(device.mac_address)
            self.table.setItem(i, 0, mac_item)

            # IP地址（取第一个）
            ip_str = list(device.ip_addresses)[0] if device.ip_addresses else "-"
            ip_item = QTableWidgetItem(ip_str)
            self.table.setItem(i, 1, ip_item)

            # 厂商
            vendor_item = QTableWidgetItem(device.vendor or "Unknown")
            self.table.setItem(i, 2, vendor_item)

            # 设备类型
            type_item = QTableWidgetItem(device.device_type or "Unknown")
            self.table.setItem(i, 3, type_item)

            # 数据包数
            count_item = QTableWidgetItem(str(device.packet_count))
            count_item.setData(Qt.ItemDataRole.DisplayRole, device.packet_count)
            self.table.setItem(i, 4, count_item)

    def clear_devices(self) -> None:
        """清除设备列表"""
        self.table.setRowCount(0)