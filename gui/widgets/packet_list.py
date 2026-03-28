"""
数据包列表视图
"""
from PyQt6.QtWidgets import QTableView, QHeaderView, QAbstractItemView, QWidget, QVBoxLayout
from PyQt6.QtCore import QAbstractTableModel, Qt, QModelIndex, pyqtSignal
from PyQt6.QtGui import QColor, QBrush
from typing import List, Any
import time

from core.parser.protocol_parser import ParsedPacket


class PacketListModel(QAbstractTableModel):
    """数据包列表模型"""

    HEADERS = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']

    # 协议颜色映射
    PROTOCOL_COLORS = {
        'TCP': QColor(200, 255, 200),      # 浅绿
        'UDP': QColor(200, 200, 255),      # 浅蓝
        'HTTP': QColor(255, 255, 200),     # 浅黄
        'HTTPS': QColor(255, 230, 230),    # 浅粉
        'DNS': QColor(255, 200, 200),      # 浅红
        'TLS': QColor(230, 230, 255),      # 浅紫
        'ICMP': QColor(255, 200, 255),     # 浅紫红
        'ARP': QColor(200, 255, 255),      # 浅青
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.packets: List[ParsedPacket] = []
        self._max_packets = 10000

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self.packets)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        packet = self.packets[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return str(packet.packet_id)
            elif col == 1:
                # 时间格式化
                if hasattr(packet, 'timestamp'):
                    return f"{packet.timestamp:.6f}"
                return ""
            elif col == 2:
                return packet.get_source_address()
            elif col == 3:
                return packet.get_destination_address()
            elif col == 4:
                return packet.protocol
            elif col == 5:
                return str(packet.length)
            elif col == 6:
                return packet.summary

        elif role == Qt.ItemDataRole.BackgroundRole:
            return self.PROTOCOL_COLORS.get(packet.protocol, QColor(255, 255, 255))

        elif role == Qt.ItemDataRole.ToolTipRole:
            return packet.summary

        return None

    def add_packet(self, packet: ParsedPacket) -> None:
        """添加数据包"""
        # 限制最大数量
        if len(self.packets) >= self._max_packets:
            self.beginRemoveRows(QModelIndex(), 0, 0)
            self.packets.pop(0)
            self.endRemoveRows()

        self.beginInsertRows(QModelIndex(), len(self.packets), len(self.packets))
        self.packets.append(packet)
        self.endInsertRows()

    def clear(self) -> None:
        """清除所有数据包"""
        self.beginResetModel()
        self.packets.clear()
        self.endResetModel()

    def get_packet(self, index: QModelIndex) -> ParsedPacket:
        """获取指定位置的数据包"""
        if index.isValid() and index.row() < len(self.packets):
            return self.packets[index.row()]
        return None

    def set_max_packets(self, max_count: int) -> None:
        """设置最大显示数量"""
        self._max_packets = max_count


class PacketListWidget(QWidget):
    """数据包列表视图"""

    packet_selected = pyqtSignal(object)  # 选中数据包时发送信号

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """设置UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # 表格视图
        self.table = QTableView()
        self.model = PacketListModel()
        self.table.setModel(self.model)

        # 配置表格
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)  # 实时数据不适合排序
        self.table.verticalHeader().setVisible(False)

        # 设置列宽
        self.table.setColumnWidth(0, 60)    # No.
        self.table.setColumnWidth(1, 120)   # Time
        self.table.setColumnWidth(2, 180)   # Source
        self.table.setColumnWidth(3, 180)   # Destination
        self.table.setColumnWidth(4, 80)    # Protocol
        self.table.setColumnWidth(5, 70)    # Length
        # Info列自动拉伸

        # 连接选择信号
        self.table.selectionModel().currentRowChanged.connect(self._on_selection_changed)

        layout.addWidget(self.table)

    def _on_selection_changed(self, current: QModelIndex, previous: QModelIndex) -> None:
        """选择改变时的处理"""
        packet = self.model.get_packet(current)
        if packet:
            self.packet_selected.emit(packet)

    def add_packet(self, packet: ParsedPacket) -> None:
        """添加数据包"""
        self.model.add_packet(packet)

        # 自动滚动到底部
        self.table.scrollToBottom()

    def clear_packets(self) -> None:
        """清除所有数据包"""
        self.model.clear()

    def get_packet_count(self) -> int:
        """获取数据包数量"""
        return self.model.rowCount()