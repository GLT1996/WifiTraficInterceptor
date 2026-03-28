"""
数据包捕获引擎
"""
import threading
import time
import logging
from queue import Queue, Empty
from typing import Callable, Optional, List, Dict, Any
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from scapy.all import sniff, conf
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = None

logger = logging.getLogger('wifi_analyzer.capture')


@dataclass
class CaptureStatistics:
    """捕获统计信息"""
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    dropped_packets: int = 0
    start_time: float = 0.0
    protocol_counts: Dict[str, int] = field(default_factory=dict)

    def update_rate(self) -> None:
        """更新速率"""
        if self.start_time > 0:
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                self.packets_per_second = self.total_packets / elapsed
                self.bytes_per_second = self.total_bytes / elapsed


class PacketCaptureEngine:
    """数据包捕获引擎"""

    def __init__(self, interface: str = None):
        self.interface = interface
        self.is_capturing = False
        self.packet_queue: Queue = Queue(maxsize=10000)
        self.callbacks: List[Callable] = []
        self.statistics = CaptureStatistics()
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._filter_expression: str = ""

    def set_interface(self, interface: str) -> None:
        """设置捕获接口"""
        self.interface = interface
        logger.info(f"Capture interface set to: {interface}")

    def set_filter(self, filter_expr: str) -> None:
        """设置BPF过滤器"""
        self._filter_expression = filter_expr
        logger.info(f"Filter set to: {filter_expr}")

    def register_callback(self, callback: Callable) -> None:
        """注册数据包回调函数"""
        self.callbacks.append(callback)
        logger.debug(f"Registered callback: {callback.__name__ if hasattr(callback, '__name__') else 'anonymous'}")

    def unregister_callback(self, callback: Callable) -> None:
        """取消注册回调函数"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    def start_capture(self) -> bool:
        """启动数据包捕获"""
        if self.is_capturing:
            logger.warning("Capture already running")
            return False

        if not self.interface:
            logger.error("No interface selected")
            return False

        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available, cannot capture")
            return False

        self.is_capturing = True
        self._stop_flag.clear()
        self.statistics = CaptureStatistics(start_time=time.time())

        # 启动捕获线程
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self._capture_thread.start()

        # 启动处理线程
        self._process_thread = threading.Thread(
            target=self._process_loop,
            daemon=True
        )
        self._process_thread.start()

        logger.info(f"Capture started on interface: {self.interface}")
        return True

    def stop_capture(self) -> None:
        """停止数据包捕获"""
        if not self.is_capturing:
            return

        self._stop_flag.set()
        self.is_capturing = False

        if self._capture_thread:
            self._capture_thread.join(timeout=2)

        self.statistics.update_rate()
        logger.info(f"Capture stopped. Total packets: {self.statistics.total_packets}")

    def _capture_loop(self) -> None:
        """捕获循环（Scapy）"""
        try:
            # 配置Scapy
            conf.iface = self.interface
            conf.promiscuous = True
            conf.sniff_socket = None

            logger.info(f"Starting capture on interface: {self.interface}")

            # 使用AsyncSniffer实现更好的控制
            from scapy.all import AsyncSniffer

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._packet_handler,
                filter=self._filter_expression if self._filter_expression else None,
                store=False
            )
            self._sniffer.start()

            # 保持线程运行直到停止
            while not self._stop_flag.is_set():
                time.sleep(0.1)

            # 停止sniffer
            if self._sniffer:
                self._sniffer.stop()

        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.is_capturing = False

    def _packet_handler(self, packet: Packet) -> None:
        """处理捕获的数据包"""
        try:
            # 更新统计
            self.statistics.total_packets += 1
            self.statistics.total_bytes += len(packet)

            # 协议统计
            proto = self._get_protocol_name(packet)
            self.statistics.protocol_counts[proto] = \
                self.statistics.protocol_counts.get(proto, 0) + 1

            # 加入队列
            if not self.packet_queue.full():
                self.packet_queue.put(packet, timeout=0.1)
            else:
                self.statistics.dropped_packets += 1
                logger.warning("Packet queue full, dropping packet")

        except Exception as e:
            logger.debug(f"Packet handler error: {e}")

    def _process_loop(self) -> None:
        """处理循环"""
        while not self._stop_flag.is_set():
            try:
                packet = self.packet_queue.get(timeout=0.5)
                self._dispatch_callbacks(packet)
            except Empty:
                continue
            except Exception as e:
                logger.debug(f"Process loop error: {e}")

    def _dispatch_callbacks(self, packet: Packet) -> None:
        """分发数据包到回调函数"""
        for callback in self.callbacks:
            try:
                callback(packet)
            except Exception as e:
                logger.debug(f"Callback error: {e}")

    def _get_protocol_name(self, packet: Packet) -> str:
        """获取协议名称"""
        layers = []

        # 遍历所有层
        for layer in packet.layers():
            layer_name = layer.__name__
            layers.append(layer_name)

        # 返回最高层协议
        if layers:
            return layers[-1]
        return "Unknown"

    def get_statistics(self) -> CaptureStatistics:
        """获取捕获统计"""
        self.statistics.update_rate()
        return self.statistics

    def get_queue_size(self) -> int:
        """获取队列大小"""
        return self.packet_queue.qsize()

    def is_running(self) -> bool:
        """检查是否正在捕获"""
        return self.is_capturing


class TsharkCaptureEngine(PacketCaptureEngine):
    """基于Tshark的捕获引擎（备用）"""

    def __init__(self, interface: str = None):
        super().__init__(interface)
        self.tshark_path = self._find_tshark()

    def _find_tshark(self) -> Optional[str]:
        """查找tshark路径"""
        import subprocess
        import shutil

        # 首先检查PATH
        tshark = shutil.which('tshark')
        if tshark:
            return tshark

        # Windows常见安装路径
        if platform.system() == 'Windows':
            common_paths = [
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe",
            ]
            for path in common_paths:
                if Path(path).exists():
                    return path

        return None

    def _capture_loop(self) -> None:
        """使用tshark捕获"""
        import subprocess

        if not self.tshark_path:
            logger.error("Tshark not found")
            return

        try:
            cmd = [
                self.tshark_path,
                '-i', self.interface,
                '-l',  # 行缓冲
                '-T', 'json',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', '_ws.col.Protocol',
                '-e', 'frame.len',
            ]

            if self._filter_expression:
                cmd.extend(['-f', self._filter_expression])

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            while not self._stop_flag.is_set():
                line = process.stdout.readline()
                if line:
                    # 解析JSON输出
                    self._parse_tshark_output(line)

        except Exception as e:
            logger.error(f"Tshark capture error: {e}")

    def _parse_tshark_output(self, line: str) -> None:
        """解析tshark JSON输出"""
        # 简化处理，实际需要完整JSON解析
        logger.debug(f"Received tshark output: {line[:100]}")