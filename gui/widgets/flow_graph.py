"""
实时流量图
"""
import pyqtgraph as pg
from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtCore import QTimer
from collections import deque
import time


class FlowGraphWidget(QWidget):
    """实时流量图组件"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

        # 数据缓冲区 (保留最近60秒数据)
        self.time_data = deque(maxlen=600)
        self.pps_data = deque(maxlen=600)    # Packets per second
        self.bps_data = deque(maxlen=600)    # Bytes per second

        self.start_time = time.time()

    def _setup_ui(self) -> None:
        """设置UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # 创建图表
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground('w')
        self.plot_widget.setTitle("Real-time Traffic")
        self.plot_widget.setLabel('left', 'Rate')
        self.plot_widget.setLabel('bottom', 'Time', 's')
        self.plot_widget.addLegend()
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)

        # 两条曲线
        self.pps_curve = self.plot_widget.plot(
            pen=pg.mkPen('b', width=2),
            name='Packets/s'
        )
        self.bps_curve = self.plot_widget.plot(
            pen=pg.mkPen('r', width=2),
            name='KB/s'
        )

        layout.addWidget(self.plot_widget)

    def update_data(self, packets_per_second: float, bytes_per_second: float) -> None:
        """更新流量数据"""
        current_time = time.time() - self.start_time

        self.time_data.append(current_time)
        self.pps_data.append(packets_per_second)
        self.bps_data.append(bytes_per_second / 1000)  # 转换为KB/s

        # 更新曲线
        self.pps_curve.setData(list(self.time_data), list(self.pps_data))
        self.bps_curve.setData(list(self.time_data), list(self.bps_data))

    def clear_data(self) -> None:
        """清除数据"""
        self.time_data.clear()
        self.pps_data.clear()
        self.bps_data.clear()
        self.start_time = time.time()
        self.pps_curve.setData([], [])
        self.bps_curve.setData([], [])