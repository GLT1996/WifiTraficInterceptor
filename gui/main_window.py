"""
主窗口
"""
import sys
import logging
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QStatusBar, QToolBar, QMenuBar, QDockWidget,
    QMessageBox, QApplication, QLabel, QComboBox, QPushButton,
    QListView
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QShortcut

from core.capture import PacketCaptureEngine, InterfaceManager
from core.parser import ParserRegistry
from core.analyzer import TrafficAnalyzer, DeviceTracker
from core.mitm import MITMManager
from config import Settings
from gui.widgets import (
    PacketListWidget, PacketDetailWidget,
    StatisticsPanel, DevicePanel, FlowGraphWidget
)
from gui.widgets.device_scanner_panel import DeviceScannerPanel
from gui.dialogs import SettingsDialog, FilterDialog

logger = logging.getLogger('wifi_analyzer.gui')


class InitializeThread(QThread):
    """MITM初始化和启动线程 - 避免阻塞UI"""
    initialized = pyqtSignal(bool)  # 初始化完成信号
    started = pyqtSignal(bool, str)  # 启动完成信号 (成功, 错误信息)

    def __init__(self, mitm_manager: MITMManager, interface: str, targets: list):
        super().__init__()
        self.mitm_manager = mitm_manager
        self.interface = interface
        self.targets = targets

    def run(self):
        """在后台线程执行初始化和启动"""
        # 第一步：初始化
        success = self.mitm_manager.initialize(self.interface)
        if not success:
            self.initialized.emit(False)
            return

        self.initialized.emit(True)

        # 第二步：启动（也在后台执行）
        success, error_msg = self.mitm_manager.start(self.targets)
        self.started.emit(success, error_msg)


class MainWindow(QMainWindow):
    """主窗口"""

    # 信号
    capture_started = pyqtSignal()
    capture_stopped = pyqtSignal()
    mitm_started = pyqtSignal()
    mitm_stopped = pyqtSignal()

    def __init__(self, settings: Settings = None):
        super().__init__()
        self.settings = settings or Settings()

        # 核心组件
        self.interface_manager = InterfaceManager()
        self.capture_engine = None
        self.traffic_analyzer = TrafficAnalyzer()
        self.device_tracker = DeviceTracker()
        self.mitm_manager = MITMManager()

        # 状态
        self.is_capturing = False
        self.is_mitm_active = False
        self.packet_counter = 0
        self._init_thread: InitializeThread = None  # 初始化线程
        self._packet_buffer: list = []  # 数据包缓冲
        self._buffer_timer: QTimer = None  # 缓冲处理定时器
        self._max_packets_in_list: int = 5000  # 列表最大显示数量

        # 初始化UI
        self._setup_window()
        self._setup_menubar()
        self._setup_toolbar()
        self._setup_central_widget()
        self._setup_dock_widgets()
        self._setup_statusbar()
        self._setup_timer()

        # 连接信号
        self._connect_signals()

        # 初始化扫描面板的默认接口（需要在 _setup_dock_widgets 之后）
        self._init_default_interface()

        logger.info("MainWindow initialized")

    def _init_default_interface(self) -> None:
        """初始化默认接口"""
        interfaces = self.interface_manager.get_interfaces()
        if interfaces:
            default_iface = interfaces[0]
            self.scanner_panel.set_interface(default_iface.name, default_iface.ip_address)
            logger.info(f"Default interface set: {default_iface.name} ({default_iface.ip_address})")

    def _setup_window(self) -> None:
        """设置窗口属性"""
        self.setWindowTitle("WiFi Traffic Interceptor")
        self.setGeometry(100, 100, 1500, 900)
        self.setMinimumSize(1000, 700)

    def _setup_menubar(self) -> None:
        """设置菜单栏"""
        menubar = self.menuBar()

        # 文件菜单
        file_menu = menubar.addMenu("File")

        export_json_action = QAction("Export to JSON", self)
        export_json_action.triggered.connect(self._export_json)
        file_menu.addAction(export_json_action)

        export_csv_action = QAction("Export to CSV", self)
        export_csv_action.triggered.connect(self._export_csv)
        file_menu.addAction(export_csv_action)

        file_menu.addSeparator()

        clear_action = QAction("Clear Data", self)
        clear_action.triggered.connect(self._clear_data)
        file_menu.addAction(clear_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence("Ctrl+Q"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # 捕获菜单
        capture_menu = menubar.addMenu("Capture")

        start_action = QAction("Start Capture", self)
        start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(start_action)

        stop_action = QAction("Stop Capture", self)
        stop_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(stop_action)

        capture_menu.addSeparator()

        interfaces_action = QAction("Refresh Interfaces", self)
        interfaces_action.triggered.connect(self._refresh_interfaces)
        capture_menu.addAction(interfaces_action)

        # MITM菜单（新增）
        mitm_menu = menubar.addMenu("MITM Attack")

        scan_action = QAction("Scan Network", self)
        scan_action.triggered.connect(self._show_scanner_panel)
        mitm_menu.addAction(scan_action)

        mitm_menu.addSeparator()

        self.start_mitm_action = QAction("Start Interception", self)
        self.start_mitm_action.triggered.connect(self.start_mitm)
        mitm_menu.addAction(self.start_mitm_action)

        self.stop_mitm_action = QAction("Stop Interception", self)
        self.stop_mitm_action.triggered.connect(self.stop_mitm)
        self.stop_mitm_action.setEnabled(False)
        mitm_menu.addAction(self.stop_mitm_action)

        # 分析菜单
        analyze_menu = menubar.addMenu("Analyze")

        stats_action = QAction("Statistics", self)
        stats_action.triggered.connect(self._show_statistics)
        analyze_menu.addAction(stats_action)

        flows_action = QAction("Top Flows", self)
        flows_action.triggered.connect(self._show_top_flows)
        analyze_menu.addAction(flows_action)

        # 设置菜单
        settings_menu = menubar.addMenu("Settings")

        settings_action = QAction("Preferences", self)
        settings_action.triggered.connect(self._show_settings)
        settings_menu.addAction(settings_action)

        # 帮助菜单
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_toolbar(self) -> None:
        """设置工具栏"""
        toolbar = self.addToolBar("Main Toolbar")
        toolbar.setMovable(False)

        # 接口选择
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(350)  # 增加宽度以显示完整信息
        self._populate_interfaces()
        toolbar.addWidget(self.interface_combo)

        toolbar.addSeparator()

        # 普通捕获按钮
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        toolbar.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        toolbar.addWidget(self.stop_button)

        toolbar.addSeparator()

        # MITM按钮（新增）
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.clicked.connect(self._show_scanner_panel)
        toolbar.addWidget(self.scan_button)

        self.mitm_button = QPushButton("Start Interception")
        self.mitm_button.clicked.connect(self._toggle_mitm)
        self.mitm_button.setStyleSheet("background-color: #ff9800; color: white;")
        toolbar.addWidget(self.mitm_button)

        toolbar.addSeparator()

        # 过滤器按钮
        filter_button = QPushButton("Filter")
        filter_button.clicked.connect(self._show_filter_dialog)
        toolbar.addWidget(filter_button)

        toolbar.addSeparator()

        # 清除按钮
        clear_button = QPushButton("Clear All")
        clear_button.clicked.connect(self._clear_data)
        clear_button.setStyleSheet("background-color: #9e9e9e; color: white;")
        toolbar.addWidget(clear_button)

        # 设置按钮
        settings_button = QPushButton("Settings")
        settings_button.clicked.connect(self._show_settings)
        toolbar.addWidget(settings_button)

    def _populate_interfaces(self) -> None:
        """填充接口列表"""
        self.interface_combo.clear()
        interfaces = self.interface_manager.get_interfaces()

        for iface in interfaces:
            # 判断接口类型
            if iface.is_wifi:
                iface_type = "[WiFi]"
            elif "ethernet" in iface.name.lower() or "以太网" in iface.name:
                iface_type = "[Ethernet]"
            else:
                iface_type = ""

            # 处理空IP的情况
            ip_addr = iface.ip_address if iface.ip_address else "No IP"

            # 显示格式：[类型] IP地址 - 接口名称
            display_name = f"{iface_type} {ip_addr} - {iface.name}"
            self.interface_combo.addItem(display_name, iface.name)

        # 设置下拉框样式，避免空白问题
        self.interface_combo.setView(QListView())
        self.interface_combo.view().setStyleSheet("""
            QListView {
                background-color: white;
                color: black;
            }
            QListView::item {
                padding: 5px;
            }
            QListView::item:hover {
                background-color: #e3f2fd;
            }
            QListView::item:selected {
                background-color: #bbdefb;
            }
        """)

    def _setup_central_widget(self) -> None:
        """设置中心区域"""
        # 数据包列表
        self.packet_list = PacketListWidget()
        self.packet_list.packet_selected.connect(self._on_packet_selected)

        # 数据包详情
        self.packet_detail = PacketDetailWidget()

        # 分割器
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.packet_list)
        splitter.addWidget(self.packet_detail)
        splitter.setSizes([600, 300])

        self.setCentralWidget(splitter)

    def _setup_dock_widgets(self) -> None:
        """设置停靠窗口"""
        # 设备扫描面板（新增）
        self.scanner_dock = QDockWidget("Network Scanner", self)
        self.scanner_panel = DeviceScannerPanel()
        self.scanner_panel.targets_changed.connect(self._on_targets_changed)
        self.scanner_dock.setWidget(self.scanner_panel)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.scanner_dock)

        # 设备面板
        self.device_dock = QDockWidget("Connected Devices", self)
        self.device_panel = DevicePanel()
        self.device_dock.setWidget(self.device_panel)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.device_dock)

        # 统计面板
        self.stats_dock = QDockWidget("Statistics", self)
        self.stats_panel = StatisticsPanel()
        self.stats_dock.setWidget(self.stats_panel)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.stats_dock)

        # 流量图
        self.graph_dock = QDockWidget("Traffic Graph", self)
        self.flow_graph = FlowGraphWidget()
        self.graph_dock.setWidget(self.flow_graph)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.graph_dock)

    def _setup_statusbar(self) -> None:
        """设置状态栏"""
        self.statusbar = self.statusBar()

        # 状态标签
        self.status_label = QLabel("Ready")
        self.statusbar.addWidget(self.status_label)

        # MITM状态标签（新增）
        self.mitm_status_label = QLabel("MITM: Inactive")
        self.mitm_status_label.setStyleSheet("color: gray;")
        self.statusbar.addWidget(self.mitm_status_label)

        # 数据包计数
        self.packet_count_label = QLabel("Packets: 0")
        self.statusbar.addPermanentWidget(self.packet_count_label)

        # 流量速率
        self.rate_label = QLabel("Rate: 0 pps")
        self.statusbar.addPermanentWidget(self.rate_label)

        # 设备计数
        self.device_count_label = QLabel("Devices: 0")
        self.statusbar.addPermanentWidget(self.device_count_label)

    def _setup_timer(self) -> None:
        """设置更新定时器"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._update_ui)
        self.update_timer.start(500)  # 每500ms更新一次

        # 数据包缓冲处理定时器
        self._buffer_timer = QTimer()
        self._buffer_timer.timeout.connect(self._process_buffered_packets)
        self._buffer_timer.start(100)  # 每100ms批量处理一次

    def _connect_signals(self) -> None:
        """连接信号"""
        self.capture_started.connect(self._on_capture_started)
        self.capture_stopped.connect(self._on_capture_stopped)
        self.mitm_started.connect(self._on_mitm_started)
        self.mitm_stopped.connect(self._on_mitm_stopped)

        # 接口选择改变时更新扫描面板
        self.interface_combo.currentIndexChanged.connect(self._on_interface_changed)

    def _on_interface_changed(self, index: int) -> None:
        """接口选择改变"""
        iface_name = self.interface_combo.currentData()
        if iface_name:
            # 获取接口IP地址
            for iface in self.interface_manager.get_interfaces():
                if iface.name == iface_name:
                    self.scanner_panel.set_interface(iface_name, iface.ip_address)
                    logger.info(f"Interface changed to: {iface_name} ({iface.ip_address})")
                    break

    # ========== 捕获功能 ==========

    def start_capture(self) -> None:
        """开始捕获"""
        if self.is_capturing:
            return

        # 获取选中的接口
        iface_name = self.interface_combo.currentData()
        if not iface_name:
            QMessageBox.warning(self, "Warning", "Please select a network interface")
            return

        # 创建捕获引擎
        self.capture_engine = PacketCaptureEngine(iface_name)
        self.capture_engine.register_callback(self._packet_callback)

        # 应用保存的过滤器
        if self.settings.capture.filter_expression:
            self.capture_engine.set_filter(self.settings.capture.filter_expression)
            logger.info(f"Applied saved filter: {self.settings.capture.filter_expression}")

        # 开始捕获
        if self.capture_engine.start_capture():
            self.is_capturing = True
            self.capture_started.emit()
        else:
            QMessageBox.critical(self, "Error", "Failed to start capture")

    def stop_capture(self) -> None:
        """停止捕获"""
        if not self.is_capturing:
            return

        if self.capture_engine:
            self.capture_engine.stop_capture()

        self.is_capturing = False
        self.capture_stopped.emit()

    def _packet_callback(self, packet) -> None:
        """数据包回调（从捕获线程调用）- 使用缓冲机制"""
        # 将数据包加入缓冲区，而不是立即处理
        self._packet_buffer.append(packet)

    def _process_buffered_packets(self) -> None:
        """批量处理缓冲的数据包（在主线程，定时触发）"""
        if not self._packet_buffer:
            return

        # 取出缓冲区的数据包
        packets = self._packet_buffer[:]
        self._packet_buffer.clear()

        # 批量处理（限制每次处理数量，避免卡顿）
        batch_size = min(50, len(packets))
        for packet in packets[:batch_size]:
            self._handle_single_packet(packet)

        # 剩余的包放回缓冲区，下次处理
        if len(packets) > batch_size:
            self._packet_buffer.extend(packets[batch_size:])

    def _handle_single_packet(self, raw_packet) -> None:
        """处理单个数据包"""
        self.packet_counter += 1
        parsed_packet = ParserRegistry.parse_packet(raw_packet, self.packet_counter)

        # 更新分析器
        self.traffic_analyzer.process_packet(parsed_packet)
        self.device_tracker.process_packet(parsed_packet)

        # 更新数据包列表（限制数量）
        if self.packet_list.get_packet_count() < self._max_packets_in_list:
            self.packet_list.add_packet(parsed_packet)

    def _on_capture_started(self) -> None:
        """捕获开始时的UI更新"""
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.interface_combo.setEnabled(False)

        # 显示过滤器状态
        if self.settings.capture.filter_expression:
            self.status_label.setText(f"Capturing (Filter: {self.settings.capture.filter_expression})")
        else:
            self.status_label.setText("Capturing...")
        logger.info("Capture started")

    def _on_capture_stopped(self) -> None:
        """捕获停止时的UI更新"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.status_label.setText("Stopped")

        stats = self.capture_engine.get_statistics() if self.capture_engine else None
        if stats:
            logger.info(f"Capture stopped: {stats.total_packets} packets")

    # ========== MITM功能 ==========

    def _show_scanner_panel(self) -> None:
        """显示扫描面板并开始扫描"""
        self.scanner_dock.show()
        self.scanner_dock.raise_()
        self.scanner_panel._start_scan()

    def _on_targets_changed(self, targets) -> None:
        """目标选择改变"""
        count = len(targets)
        if count > 0:
            self.mitm_button.setText(f"Intercept ({count} targets)")
        else:
            self.mitm_button.setText("Start Interception")

    def _toggle_mitm(self) -> None:
        """切换MITM状态"""
        if self.is_mitm_active:
            self.stop_mitm()
        else:
            self.start_mitm()

    def start_mitm(self) -> None:
        """开始MITM攻击"""
        if self.is_mitm_active:
            return

        # 检查是否有选中的目标
        targets = self.scanner_panel.get_selected_targets()
        if not targets:
            QMessageBox.warning(
                self, "Warning",
                "Please select at least one target device.\n\n"
                "1. Click 'Scan Network' to discover devices\n"
                "2. Check the devices you want to intercept\n"
                "3. Click 'Start Interception'"
            )
            return

        # 确认对话框
        reply = QMessageBox.question(
            self, "Confirm Interception",
            f"You are about to intercept traffic from {len(targets)} device(s).\n\n"
            f"This will perform ARP spoofing on:\n" +
            "\n".join([f"  - {t.ip} ({t.vendor})" for t in targets[:5]]) +
            (f"\n  ... and {len(targets)-5} more" if len(targets) > 5 else "") +
            "\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # 更新UI状态
        self.mitm_button.setText("Starting...")
        self.mitm_button.setEnabled(False)
        self.status_label.setText("Starting MITM... Please wait")
        logger.info("Starting MITM in background thread")

        # 在后台线程执行初始化和启动
        iface_name = self.interface_combo.currentData()
        self._init_thread = InitializeThread(self.mitm_manager, iface_name, targets)
        self._init_thread.started.connect(self._on_mitm_thread_finished)
        self._init_thread.start()

    def _on_mitm_thread_finished(self, success: bool, error_msg: str) -> None:
        """MITM后台线程完成回调（在主线程）"""
        # 恢复按钮状态
        self.mitm_button.setEnabled(True)

        if not success:
            self.mitm_button.setText("Start Interception")
            self.status_label.setText("Ready")
            QMessageBox.critical(
                self, "Error",
                f"Failed to start MITM attack.\n\n"
                f"Reason: {error_msg}\n\n"
                f"Troubleshooting:\n"
                f"1. Run as Administrator\n"
                f"2. Make sure Npcap is installed\n"
                f"3. Make sure targets have valid MAC addresses"
            )
            return

        # 开始捕获（如果还没开始）
        if not self.is_capturing:
            self.start_capture()

        # 更新状态
        self.is_mitm_active = True
        self.mitm_started.emit()

    def stop_mitm(self) -> None:
        """停止MITM攻击"""
        if not self.is_mitm_active:
            return

        self.mitm_manager.stop()
        self.is_mitm_active = False
        self.mitm_stopped.emit()

    def _on_mitm_started(self) -> None:
        """MITM开始时的UI更新"""
        self.mitm_button.setText("Stop Interception")
        self.mitm_button.setStyleSheet("background-color: #f44336; color: white;")
        self.start_mitm_action.setEnabled(False)
        self.stop_mitm_action.setEnabled(True)
        self.mitm_status_label.setText("MITM: Active")
        self.mitm_status_label.setStyleSheet("color: red; font-weight: bold;")
        self.status_label.setText(f"Intercepting {len(self.scanner_panel.get_selected_targets())} targets...")
        logger.info("MITM attack started")
        logger.info(f"Gateway: {self.mitm_manager.gateway_ip}")
        logger.info(f"Targets: {len(self.scanner_panel.get_selected_targets())}")

        # 不显示弹窗，改为在状态栏显示信息，避免阻塞UI
        # 用户可以从状态栏看到MITM状态

    def _on_mitm_stopped(self) -> None:
        """MITM停止时的UI更新"""
        count = len(self.scanner_panel.get_selected_targets())
        self.mitm_button.setText(f"Intercept ({count} targets)" if count > 0 else "Start Interception")
        self.mitm_button.setStyleSheet("background-color: #ff9800; color: white;")
        self.start_mitm_action.setEnabled(True)
        self.stop_mitm_action.setEnabled(False)
        self.mitm_status_label.setText("MITM: Inactive")
        self.mitm_status_label.setStyleSheet("color: gray;")
        self.status_label.setText("Ready")
        logger.info("MITM attack stopped")

    # ========== UI更新 ==========

    def _update_ui(self) -> None:
        """更新UI"""
        # 更新状态栏
        self.packet_count_label.setText(f"Packets: {self.packet_counter}")

        if self.capture_engine:
            stats = self.capture_engine.get_statistics()
            self.rate_label.setText(f"Rate: {stats.packets_per_second:.1f} pps")

        self.device_count_label.setText(f"Devices: {self.device_tracker.get_device_count()}")

        # 更新统计面板
        stats = self.traffic_analyzer.get_statistics()
        self.stats_panel.update_statistics(stats)

        # 更新设备面板
        devices = self.device_tracker.get_active_devices()
        self.device_panel.update_devices(devices)

        # 更新流量图
        if self.capture_engine:
            stats = self.capture_engine.get_statistics()
            self.flow_graph.update_data(
                stats.packets_per_second,
                stats.bytes_per_second
            )

        # 更新MITM状态
        if self.is_mitm_active:
            mitm_status = self.mitm_manager.get_status()
            self.mitm_status_label.setText(
                f"MITM: Active | Targets: {mitm_status.target_count} | Packets: {mitm_status.packet_count}"
            )

    def _on_packet_selected(self, packet) -> None:
        """数据包选中时的处理"""
        self.packet_detail.show_packet_detail(packet)

    def _refresh_interfaces(self) -> None:
        """刷新接口列表"""
        self.interface_manager.refresh()
        self._populate_interfaces()

    def _show_filter_dialog(self) -> None:
        """显示过滤器对话框"""
        # 获取当前过滤器
        current_filter = self.settings.capture.filter_expression
        dialog = FilterDialog(self, current_filter)
        if dialog.exec():
            filter_expr = dialog.get_filter()
            # 保存过滤器到设置
            self.settings.capture.filter_expression = filter_expr

            if self.capture_engine:
                # 如果正在捕获，需要重启才能应用新过滤器
                if self.is_capturing:
                    reply = QMessageBox.question(
                        self, "Apply Filter",
                        f"Filter: {filter_expr if filter_expr else 'No filter'}\n\n"
                        f"Applying a new filter requires restarting the capture.\n\n"
                        f"Restart capture now?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    if reply == QMessageBox.StandardButton.Yes:
                        self.capture_engine.set_filter(filter_expr)
                        self.stop_capture()
                        self.start_capture()
                        self.status_label.setText(f"Capturing (Filter: {filter_expr})" if filter_expr else "Capturing...")
                else:
                    self.capture_engine.set_filter(filter_expr)
                    logger.info(f"Filter set: {filter_expr}")
            else:
                # 还没开始捕获，保存过滤器到设置
                self.settings.capture.filter_expression = filter_expr
                logger.info(f"Filter saved for next capture: {filter_expr}")

    def _show_settings(self) -> None:
        """显示设置对话框"""
        dialog = SettingsDialog(self, self.settings)
        if dialog.exec():
            self.settings = dialog.get_settings()
            self.settings.save()

    def _show_statistics(self) -> None:
        """显示统计信息"""
        stats = self.traffic_analyzer.get_statistics()
        mitm_status = self.mitm_manager.get_status()

        QMessageBox.information(
            self, "Statistics",
            f"Total Packets: {stats.total_packets}\n"
            f"Total Bytes: {stats.total_bytes}\n"
            f"Active Flows: {self.traffic_analyzer.get_flow_count()}\n"
            f"Active Devices: {self.device_tracker.get_active_device_count()}\n\n"
            f"MITM Active: {mitm_status.is_active}\n"
            f"MITM Targets: {mitm_status.target_count}\n"
            f"ARP Packets Sent: {mitm_status.packet_count}"
        )

    def _show_top_flows(self) -> None:
        """显示Top Flows"""
        flows = self.traffic_analyzer.get_top_flows(10)
        flow_info = "\n".join([
            f"{f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port} ({f.protocol}): {f.byte_count} bytes"
            for f in flows
        ])
        QMessageBox.information(self, "Top Flows", flow_info or "No flows recorded")

    def _show_about(self) -> None:
        """显示关于信息"""
        QMessageBox.about(
            self, "About WiFi Traffic Interceptor",
            "WiFi Traffic Interceptor v2.0\n\n"
            "A tool for intercepting and analyzing WiFi network traffic.\n\n"
            "Features:\n"
            "- Network device scanning\n"
            "- ARP spoofing for traffic interception\n"
            "- Protocol analysis (TCP, UDP, HTTP, DNS)\n"
            "- Real-time traffic visualization\n\n"
            "⚠️ For educational and authorized security testing purposes only.\n"
            "Unauthorized use is illegal."
        )

    def _export_json(self) -> None:
        """导出为JSON"""
        QMessageBox.information(self, "Export", "Export feature requires database storage which is disabled.")

    def _export_csv(self) -> None:
        """导出为CSV"""
        QMessageBox.information(self, "Export", "Export feature requires database storage which is disabled.")

    def _clear_data(self) -> None:
        """清除数据"""
        reply = QMessageBox.question(
            self, "Clear Data",
            "Are you sure you want to clear all captured data?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.packet_list.clear_packets()
            self.traffic_analyzer.clear_statistics()
            self.device_tracker.clear_devices()
            self.packet_counter = 0
            self.flow_graph.clear_data()
            logger.info("Data cleared")

    def closeEvent(self, event) -> None:
        """窗口关闭事件"""
        # 停止MITM
        if self.is_mitm_active:
            self.stop_mitm()

        # 停止捕获
        if self.is_capturing:
            self.stop_capture()

        self.settings.save()
        event.accept()