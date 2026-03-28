"""
设置对话框
"""
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QFormLayout, QLineEdit, QSpinBox, QCheckBox, QPushButton,
    QGroupBox, QFileDialog, QMessageBox, QLabel
)
from PyQt6.QtCore import Qt

from config import Settings


class SettingsDialog(QDialog):
    """设置对话框"""

    def __init__(self, parent=None, settings: Settings = None):
        super().__init__(parent)
        self.settings = settings or Settings()
        self.setWindowTitle("Settings")
        self.setMinimumWidth(500)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """设置UI"""
        layout = QVBoxLayout(self)

        # 标签页
        tabs = QTabWidget()

        # 捕获设置页
        capture_tab = self._create_capture_tab()
        tabs.addTab(capture_tab, "Capture")

        # WiFi设置页
        wifi_tab = self._create_wifi_tab()
        tabs.addTab(wifi_tab, "WiFi")

        # 显示设置页
        display_tab = self._create_display_tab()
        tabs.addTab(display_tab, "Display")

        layout.addWidget(tabs)

        # 按钮
        button_layout = QHBoxLayout()

        save_button = QPushButton("Save")
        save_button.clicked.connect(self._save_settings)
        button_layout.addWidget(save_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

    def _create_capture_tab(self) -> QWidget:
        """创建捕获设置页"""
        widget = QWidget()
        layout = QFormLayout(widget)

        # 缓冲区大小
        self.buffer_size_spin = QSpinBox()
        self.buffer_size_spin.setRange(100, 10000)
        self.buffer_size_spin.setValue(self.settings.capture.buffer_size)
        layout.addRow("Buffer Size:", self.buffer_size_spin)

        # 截断长度
        self.snap_length_spin = QSpinBox()
        self.snap_length_spin.setRange(64, 65535)
        self.snap_length_spin.setValue(self.settings.capture.snap_length)
        layout.addRow("Snap Length:", self.snap_length_spin)

        # 混杂模式
        self.promiscuous_check = QCheckBox()
        self.promiscuous_check.setChecked(self.settings.capture.promiscuous)
        layout.addRow("Promiscuous Mode:", self.promiscuous_check)

        return widget

    def _create_wifi_tab(self) -> QWidget:
        """创建WiFi设置页"""
        widget = QWidget()
        layout = QFormLayout(widget)

        # SSID
        self.ssid_edit = QLineEdit()
        self.ssid_edit.setText(self.settings.wifi.ssid)
        layout.addRow("SSID:", self.ssid_edit)

        # 密码
        self.password_edit = QLineEdit()
        self.password_edit.setText(self.settings.wifi.password)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Password:", self.password_edit)

        # 解密开关
        self.decryption_check = QCheckBox()
        self.decryption_check.setChecked(self.settings.wifi.decryption_enabled)
        layout.addRow("Enable Decryption:", self.decryption_check)

        # 说明
        info_label = QLabel("Note: WiFi decryption requires Wireshark to be installed.")
        layout.addRow(info_label)

        return widget

    def _create_display_tab(self) -> QWidget:
        """创建显示设置页"""
        widget = QWidget()
        layout = QFormLayout(widget)

        # 最大显示数量
        self.max_packets_spin = QSpinBox()
        self.max_packets_spin.setRange(100, 100000)
        self.max_packets_spin.setValue(self.settings.display.max_packets_display)
        layout.addRow("Max Packets Display:", self.max_packets_spin)

        # 自动滚动
        self.auto_scroll_check = QCheckBox()
        self.auto_scroll_check.setChecked(self.settings.display.auto_scroll)
        layout.addRow("Auto Scroll:", self.auto_scroll_check)

        # 协议颜色
        self.color_check = QCheckBox()
        self.color_check.setChecked(self.settings.display.color_by_protocol)
        layout.addRow("Color by Protocol:", self.color_check)

        return widget

    def _save_settings(self) -> None:
        """保存设置"""
        self.settings.capture.buffer_size = self.buffer_size_spin.value()
        self.settings.capture.snap_length = self.snap_length_spin.value()
        self.settings.capture.promiscuous = self.promiscuous_check.isChecked()

        self.settings.wifi.ssid = self.ssid_edit.text()
        self.settings.wifi.password = self.password_edit.text()
        self.settings.wifi.decryption_enabled = self.decryption_check.isChecked()

        self.settings.display.max_packets_display = self.max_packets_spin.value()
        self.settings.display.auto_scroll = self.auto_scroll_check.isChecked()
        self.settings.display.color_by_protocol = self.color_check.isChecked()

        # 配置WiFi解密
        if self.settings.wifi.decryption_enabled and self.settings.wifi.ssid and self.settings.wifi.password:
            from core.capture import WiFiDecryptor
            decryptor = WiFiDecryptor(self.settings.wifi.ssid, self.settings.wifi.password)
            if decryptor.configure_wireshark_decryption():
                QMessageBox.information(self, "Success", "WiFi decryption configured successfully")
            else:
                QMessageBox.warning(self, "Warning", "Failed to configure WiFi decryption")

        self.accept()

    def get_settings(self) -> Settings:
        """获取设置"""
        return self.settings