"""
数据包详情视图
"""
import gzip
import zlib
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QLabel, QSplitter, QTabWidget
)
from PyQt6.QtCore import Qt
from typing import Any

from core.parser.protocol_parser import ParsedPacket


class PacketDetailWidget(QWidget):
    """数据包详情视图"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_packet: ParsedPacket = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """设置UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # 分割器
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # 协议层级树
        self.protocol_tree = QTreeWidget()
        self.protocol_tree.setHeaderLabels(['Field', 'Value'])
        self.protocol_tree.setColumnWidth(0, 150)
        self.protocol_tree.setAlternatingRowColors(True)

        # 右侧选项卡
        self.tab_widget = QTabWidget()

        # 十六进制视图
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setStyleSheet("font-family: Consolas, 'Courier New', monospace; font-size: 11px;")
        self.tab_widget.addTab(self.hex_view, "Hex Dump")

        # 文本视图（显示 HTTP 等明文内容）
        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.text_view.setStyleSheet("font-family: Consolas, 'Courier New', monospace; font-size: 11px;")
        self.tab_widget.addTab(self.text_view, "Text/ASCII")

        splitter.addWidget(self.protocol_tree)
        splitter.addWidget(self.tab_widget)
        splitter.setSizes([400, 400])

        layout.addWidget(splitter)

    def show_packet_detail(self, packet: ParsedPacket) -> None:
        """显示数据包详情"""
        self.current_packet = packet
        self.protocol_tree.clear()

        if not packet:
            self.hex_view.clear()
            self.text_view.clear()
            return

        # 构建协议层级树
        root = QTreeWidgetItem(self.protocol_tree, ['Packet Details'])
        root.setExpanded(True)

        # 基本信息
        info_item = QTreeWidgetItem(root, ['Basic Info'])
        info_item.addChild(QTreeWidgetItem(['Packet ID', str(packet.packet_id)]))
        info_item.addChild(QTreeWidgetItem(['Timestamp', f"{packet.timestamp:.6f}"]))
        info_item.addChild(QTreeWidgetItem(['Length', str(packet.length)]))
        info_item.addChild(QTreeWidgetItem(['Protocol', packet.protocol]))
        info_item.addChild(QTreeWidgetItem(['Summary', packet.summary]))
        info_item.setExpanded(True)

        # 地址信息
        addr_item = QTreeWidgetItem(root, ['Addresses'])
        if packet.src_mac:
            addr_item.addChild(QTreeWidgetItem(['Source MAC', packet.src_mac]))
        if packet.dst_mac:
            addr_item.addChild(QTreeWidgetItem(['Destination MAC', packet.dst_mac]))
        if packet.src_ip:
            addr_item.addChild(QTreeWidgetItem(['Source IP', packet.src_ip]))
        if packet.dst_ip:
            addr_item.addChild(QTreeWidgetItem(['Destination IP', packet.dst_ip]))
        if packet.src_port:
            addr_item.addChild(QTreeWidgetItem(['Source Port', str(packet.src_port)]))
        if packet.dst_port:
            addr_item.addChild(QTreeWidgetItem(['Destination Port', str(packet.dst_port)]))
        addr_item.setExpanded(True)

        # 各协议层详情
        for layer_name, layer_data in packet.layers.items():
            layer_item = QTreeWidgetItem(root, [layer_name])
            self._add_layer_data(layer_item, layer_data)
            layer_item.setExpanded(layer_name in ['TCP', 'UDP', 'HTTP', 'DNS'])

        # 显示原始数据
        if packet.raw_packet:
            # 十六进制视图
            raw_hex = self._format_hex_dump(packet.raw_packet)
            self.hex_view.setPlainText(raw_hex)

            # 文本视图 - 尝试解码为文本
            text_content = self._extract_text_content(packet)
            self.text_view.setPlainText(text_content)
        else:
            self.hex_view.clear()
            self.text_view.clear()

    def _extract_text_content(self, packet: ParsedPacket) -> str:
        """提取文本内容（用于 HTTP 等明文协议）"""
        try:
            raw = packet.raw_packet

            # 尝试从 layers 中获取 HTTP 内容
            http_data = packet.layers.get('HTTP', {})

            # 构建 HTTP 文本显示
            lines = []

            # 如果有 HTTP 数据
            if http_data.get('type') == 'Request':
                method = http_data.get('method', '')
                uri = http_data.get('uri', '')
                host = http_data.get('host', '')
                version = http_data.get('version', 'HTTP/1.1')
                lines.append(f"=== HTTP Request ===")
                lines.append(f"{method} {uri} {version}")
                if host:
                    lines.append(f"Host: {host}")

                # 显示其他头部
                headers = http_data.get('headers', {})
                for key, value in headers.items():
                    if key.lower() not in ['host']:
                        lines.append(f"{key}: {value}")

            elif http_data.get('type') == 'Response':
                status = http_data.get('status_code', '')
                status_text = http_data.get('status_text', '')

                lines.append(f"=== HTTP Response ===")
                lines.append(f"HTTP/1.1 {status} {status_text}")

                # 显示头部
                headers = http_data.get('headers', {})
                for key, value in headers.items():
                    lines.append(f"{key}: {value}")

            # 尝试解码原始数据为文本
            try:
                # 查找 HTTP body（在 \r\n\r\n 之后）
                body_start = raw.find(b'\r\n\r\n')
                if body_start == -1:
                    body_start = raw.find(b'\n\n')

                if body_start != -1:
                    body = raw[body_start + 4:]
                    headers_raw = raw[:body_start]

                    if body:
                        lines.append(f"\n--- Body ({len(body)} bytes) ---")

                        # 解析头部信息
                        headers_lower = headers_raw.decode('utf-8', errors='ignore').lower()
                        is_gzip = 'content-encoding: gzip' in headers_lower or 'content-encoding:gzip' in headers_lower
                        is_deflate = 'content-encoding: deflate' in headers_lower
                        is_chunked = 'transfer-encoding: chunked' in headers_lower

                        # 先处理 chunked 编码
                        if is_chunked:
                            body = self._decode_chunked(body)
                            if body:
                                lines.append(f"[Chunked decoded, {len(body)} bytes]")

                        # 解压缩
                        if is_gzip:
                            decompressed = self._decompress_gzip(body)
                            if decompressed:
                                text = decompressed.decode('utf-8', errors='replace')
                                lines.append(f"[Gzip decompressed, {len(decompressed)} bytes]")
                                lines.append(text[:5000])
                            else:
                                lines.append("[Gzip decompress failed, showing raw]")
                                lines.append(self._decode_ascii(body))

                        elif is_deflate:
                            decompressed = self._decompress_deflate(body)
                            if decompressed:
                                text = decompressed.decode('utf-8', errors='replace')
                                lines.append(f"[Deflate decompressed, {len(decompressed)} bytes]")
                                lines.append(text[:5000])
                            else:
                                lines.append("[Deflate decompress failed, showing raw]")
                                lines.append(self._decode_ascii(body))

                        else:
                            # 尝试自动检测是否是压缩数据
                            if len(body) > 2:
                                # gzip 魔数: 1f 8b
                                if body[0:2] == b'\x1f\x8b':
                                    decompressed = self._decompress_gzip(body)
                                    if decompressed:
                                        text = decompressed.decode('utf-8', errors='replace')
                                        lines.append(f"[Auto-detected gzip, decompressed {len(decompressed)} bytes]")
                                        lines.append(text[:5000])
                                    else:
                                        lines.append("[Gzip detected but decompress failed]")
                                        lines.append(self._decode_ascii(body))
                                else:
                                    # 直接解码为文本
                                    text = body.decode('utf-8', errors='replace')
                                    lines.append(text[:5000])
                            else:
                                text = body.decode('utf-8', errors='replace')
                                lines.append(text[:5000])

                else:
                    # 没找到 body 分隔符，尝试解码全部
                    decoded = raw.decode('utf-8', errors='replace')
                    if lines:
                        lines.append("\n--- Raw Data ---")
                    lines.append(decoded[:3000])

            except Exception as e:
                lines.append(f"\n[Decode error: {e}]")
                lines.append(self._decode_ascii(raw))

            return '\n'.join(lines) if lines else self._decode_ascii(raw)

        except Exception as e:
            return f"Error extracting text: {e}"

    def _decompress_gzip(self, data: bytes) -> bytes:
        """解压 gzip 数据"""
        try:
            return gzip.decompress(data)
        except:
            pass

        # 尝试跳过 gzip 头部
        try:
            # gzip 格式: 10字节头 + 数据 + 8字节尾
            if len(data) > 18 and data[0:2] == b'\x1f\x8b':
                # 使用 zlib 解压 deflate 数据（跳过 gzip 头）
                return zlib.decompress(data[10:-8], -zlib.MAX_WBITS)
        except:
            pass

        return None

    def _decompress_deflate(self, data: bytes) -> bytes:
        """解压 deflate 数据"""
        try:
            return zlib.decompress(data)
        except:
            pass

        try:
            # 原始 deflate
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except:
            pass

        return None

    def _decode_chunked(self, data: bytes) -> bytes:
        """解码 chunked 传输编码"""
        try:
            result = bytearray()
            pos = 0

            while pos < len(data):
                # 查找 chunk 大小行
                line_end = data.find(b'\r\n', pos)
                if line_end == -1:
                    break

                # 解析 chunk 大小
                size_line = data[pos:line_end].decode('ascii', errors='ignore')
                try:
                    chunk_size = int(size_line.strip(), 16)
                except:
                    break

                if chunk_size == 0:
                    break

                # 提取 chunk 数据
                chunk_start = line_end + 2
                chunk_end = chunk_start + chunk_size

                if chunk_end > len(data):
                    break

                result.extend(data[chunk_start:chunk_end])

                # 移动到下一个 chunk
                pos = chunk_end + 2  # 跳过 \r\n

            return bytes(result)
        except:
            return data

    def _decode_ascii(self, data: bytes) -> str:
        """解码为可读 ASCII"""
        result = []
        for i in range(0, len(data), 64):
            chunk = data[i:i+64]
            # 只保留可打印字符
            text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            result.append(text)
        return '\n'.join(result)

    def _add_layer_data(self, parent: QTreeWidgetItem, data: dict) -> None:
        """添加协议层数据到树"""
        for key, value in data.items():
            if isinstance(value, dict):
                child = QTreeWidgetItem(parent, [key])
                self._add_layer_data(child, value)
                child.setExpanded(False)
            elif isinstance(value, list):
                child = QTreeWidgetItem(parent, [key, f"[{len(value)} items]"])
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        item_child = QTreeWidgetItem(child, [f"[{i}]"])
                        self._add_layer_data(item_child, item)
                    else:
                        QTreeWidgetItem(child, [f"[{i}]", str(item)])
            else:
                QTreeWidgetItem(parent, [key, str(value)])

    def _format_hex_dump(self, data: bytes) -> str:
        """格式化十六进制显示"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

            # 对齐
            hex_part = hex_part.ljust(47)
            lines.append(f"{i:08x}  {hex_part}  {ascii_part}")

        return '\n'.join(lines)

    def clear(self) -> None:
        """清除详情"""
        self.protocol_tree.clear()
        self.hex_view.clear()
        self.text_view.clear()
        self.current_packet = None