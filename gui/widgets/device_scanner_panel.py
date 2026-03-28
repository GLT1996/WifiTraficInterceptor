"""
设备扫描面板 - 显示局域网设备并允许选择目标
"""
import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QCheckBox, QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QColor

from core.mitm import NetworkScanner, DeviceInfo

logger = logging.getLogger('wifi_analyzer.gui')


class ScanThread(QThread):
    """扫描线程"""
    devices_found = pyqtSignal(list)
    scan_finished = pyqtSignal()

    def __init__(self, scanner: NetworkScanner, interface: str = None, network_range: str = None):
        super().__init__()
        self.scanner = scanner
        self.interface = interface
        self.network_range = network_range

    def run(self):
        try:
            devices = self.scanner.scan(
                interface=self.interface,
                network_range=self.network_range
            )
            self.devices_found.emit(devices)
        finally:
            self.scan_finished.emit()


class DeviceScannerPanel(QWidget):
    """设备扫描面板"""

    # 信号
    devices_updated = pyqtSignal(list)  # 设备列表更新
    targets_changed = pyqtSignal(list)  # 目标选择改变

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = NetworkScanner()
        self.devices: list = []
        self.selected_targets: list = []
        self._scan_thread: ScanThread = None
        self._current_interface: str = None  # 当前选择的接口
        self._current_network_range: str = None  # 当前网络范围

        self._setup_ui()

    def _setup_ui(self) -> None:
        """设置UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # 控制按钮
        control_layout = QHBoxLayout()

        self.scan_button = QPushButton("扫描网络")
        self.scan_button.clicked.connect(self._start_scan)
        control_layout.addWidget(self.scan_button)

        self.status_label = QLabel("就绪")
        control_layout.addWidget(self.status_label)

        control_layout.addStretch()

        layout.addLayout(control_layout)

        # 设备表格
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(['选择', 'IP地址', 'MAC地址', '厂商', '类型'])

        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)

        self.table.setColumnWidth(0, 50)   # 选择
        self.table.setColumnWidth(1, 100)  # IP
        self.table.setColumnWidth(2, 130)  # MAC
        self.table.setColumnWidth(3, 80)   # 厂商
        self.table.setColumnWidth(4, 80)   # 类型

        layout.addWidget(self.table)

        # 底部信息
        info_layout = QHBoxLayout()

        self.device_count_label = QLabel("设备: 0")
        info_layout.addWidget(self.device_count_label)

        self.target_count_label = QLabel("已选目标: 0")
        info_layout.addWidget(self.target_count_label)

        info_layout.addStretch()

        self.select_all_button = QPushButton("全选")
        self.select_all_button.clicked.connect(self._select_all)
        info_layout.addWidget(self.select_all_button)

        self.deselect_all_button = QPushButton("取消全选")
        self.deselect_all_button.clicked.connect(self._deselect_all)
        info_layout.addWidget(self.deselect_all_button)

        layout.addLayout(info_layout)

    def _start_scan(self) -> None:
        """开始扫描"""
        if self._scan_thread and self._scan_thread.isRunning():
            return

        # 清除之前的选择
        self.selected_targets = []
        self.targets_changed.emit([])

        self.scan_button.setEnabled(False)
        self.status_label.setText("正在扫描...")
        self.table.setRowCount(0)
        self.target_count_label.setText("已选目标: 0")

        # 创建扫描线程，传递接口和网络范围
        self._scan_thread = ScanThread(
            self.scanner,
            interface=self._current_interface,
            network_range=self._current_network_range
        )
        self._scan_thread.devices_found.connect(self._on_devices_found)
        self._scan_thread.scan_finished.connect(self._on_scan_finished)
        self._scan_thread.start()

    def _on_devices_found(self, devices: list) -> None:
        """扫描完成"""
        self.devices = devices
        self._update_table()

    def _on_scan_finished(self) -> None:
        """扫描结束"""
        self.scan_button.setEnabled(True)
        self.status_label.setText(f"找到 {len(self.devices)} 个设备")
        self.device_count_label.setText(f"设备: {len(self.devices)}")

        self.devices_updated.emit(self.devices)

    def _update_table(self) -> None:
        """更新表格"""
        self.table.setRowCount(len(self.devices))
        self._checkboxes = []

        for i, device in enumerate(self.devices):
            # 复选框
            checkbox = QCheckBox()
            checkbox.setEnabled(not device.is_gateway and not device.is_self)
            checkbox.stateChanged.connect(lambda state, d=device: self._on_checkbox_changed(d, state))
            self._checkboxes.append(checkbox)

            checkbox_widget = QWidget()
            checkbox_layout = QHBoxLayout(checkbox_widget)
            checkbox_layout.addWidget(checkbox)
            checkbox_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            checkbox_layout.setContentsMargins(0, 0, 0, 0)
            self.table.setCellWidget(i, 0, checkbox_widget)

            # IP地址
            ip_item = QTableWidgetItem(device.ip)
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(i, 1, ip_item)

            # MAC地址
            mac_item = QTableWidgetItem(device.mac)
            mac_item.setFlags(mac_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(i, 2, mac_item)

            # 厂商
            vendor_item = QTableWidgetItem(device.vendor)
            vendor_item.setFlags(vendor_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(i, 3, vendor_item)

            # 类型
            type_str = ""
            if device.is_gateway:
                type_str = "网关"
            elif device.is_self:
                type_str = "本机"
            else:
                type_str = "设备"

            type_item = QTableWidgetItem(type_str)
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)

            # 网关和本机用不同颜色
            if device.is_gateway:
                type_item.setBackground(QColor(200, 255, 200))
            elif device.is_self:
                type_item.setBackground(QColor(200, 200, 255))

            self.table.setItem(i, 4, type_item)

    def _on_checkbox_changed(self, device: DeviceInfo, state: int) -> None:
        """复选框状态改变"""
        if state == Qt.CheckState.Checked.value:
            if device not in self.selected_targets:
                self.selected_targets.append(device)
        else:
            if device in self.selected_targets:
                self.selected_targets.remove(device)

        self.target_count_label.setText(f"已选目标: {len(self.selected_targets)}")
        self.targets_changed.emit(self.selected_targets)

    def _select_all(self) -> None:
        """全选"""
        self.selected_targets = [d for d in self.devices if not d.is_gateway and not d.is_self]
        self._update_checkboxes()
        self.targets_changed.emit(self.selected_targets)

    def _deselect_all(self) -> None:
        """取消全选"""
        self.selected_targets = []
        self._update_checkboxes()
        self.targets_changed.emit(self.selected_targets)

    def _update_checkboxes(self) -> None:
        """更新复选框状态"""
        if not hasattr(self, '_checkboxes'):
            return

        for i, checkbox in enumerate(self._checkboxes):
            if i < len(self.devices):
                device = self.devices[i]
                checkbox.blockSignals(True)
                checkbox.setChecked(device in self.selected_targets)
                checkbox.blockSignals(False)

        self.target_count_label.setText(f"已选目标: {len(self.selected_targets)}")

    def get_selected_targets(self) -> list:
        """获取选中的目标"""
        return self.selected_targets

    def get_devices(self) -> list:
        """获取所有设备"""
        return self.devices

    def set_interface(self, interface: str, ip_address: str = None) -> None:
        """
        设置当前网络接口

        :param interface: 接口名称
        :param ip_address: 接口IP地址（用于推断网络范围）
        """
        self._current_interface = interface

        # 根据IP地址推断网络范围
        if ip_address and ip_address != "No IP":
            parts = ip_address.split('.')
            if len(parts) == 4:
                self._current_network_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                logger.info(f"Set network range based on interface IP: {self._current_network_range}")
        else:
            self._current_network_range = None