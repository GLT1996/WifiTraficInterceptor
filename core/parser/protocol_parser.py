"""
协议解析框架
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Type
from enum import Enum
import time
import logging

logger = logging.getLogger('wifi_analyzer.parser')


class ProtocolLayer(Enum):
    """协议层级"""
    PHYSICAL = 1      # 物理层
    DATA_LINK = 2     # 数据链路层 (Ethernet)
    NETWORK = 3       # 网络层 (IP)
    TRANSPORT = 4     # 传输层 (TCP/UDP)
    APPLICATION = 5   # 应用层 (HTTP/DNS等)


@dataclass
class ParsedPacket:
    """解析后的数据包结构"""
    # 基本信息
    packet_id: int
    timestamp: float
    length: int

    # 网络信息
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # 协议信息
    protocol: str = "Unknown"
    protocol_layers: List[str] = field(default_factory=list)

    # 解析后的各层数据
    layers: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # 摘要信息
    summary: str = ""

    # 原始数据
    raw_packet: bytes = field(default_factory=bytes)

    # 元数据
    is_encrypted: bool = False
    has_error: bool = False
    error_message: str = ""

    def get_layer_data(self, layer_name: str) -> Optional[Dict[str, Any]]:
        """获取指定层的数据"""
        return self.layers.get(layer_name)

    def get_source_address(self) -> str:
        """获取源地址字符串"""
        if self.src_port:
            return f"{self.src_ip}:{self.src_port}"
        return self.src_ip or self.src_mac or "Unknown"

    def get_destination_address(self) -> str:
        """获取目的地址字符串"""
        if self.dst_port:
            return f"{self.dst_ip}:{self.dst_port}"
        return self.dst_ip or self.dst_mac or "Unknown"


class ProtocolParser(ABC):
    """协议解析器基类"""

    @property
    @abstractmethod
    def name(self) -> str:
        """协议名称"""
        pass

    @property
    @abstractmethod
    def layer(self) -> ProtocolLayer:
        """协议所属层级"""
        pass

    @abstractmethod
    def parse(self, packet_data: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        解析协议数据
        :param packet_data: 待解析的数据（可以是原始字节或Scapy Packet）
        :param context: 解析上下文（包含已解析的上一层信息）
        :return: 解析后的数据字典
        """
        pass

    @abstractmethod
    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取协议摘要信息"""
        pass

    def can_parse(self, packet_data: Any) -> bool:
        """检查是否可以解析该数据"""
        return True


class ParserRegistry:
    """协议解析器注册中心"""

    _parsers: Dict[str, ProtocolParser] = {}
    _layer_order: List[ProtocolLayer] = [
        ProtocolLayer.DATA_LINK,
        ProtocolLayer.NETWORK,
        ProtocolLayer.TRANSPORT,
        ProtocolLayer.APPLICATION
    ]

    @classmethod
    def register(cls, parser: ProtocolParser) -> None:
        """注册解析器"""
        cls._parsers[parser.name] = parser
        logger.debug(f"Registered parser: {parser.name}")

    @classmethod
    def unregister(cls, name: str) -> None:
        """取消注册解析器"""
        if name in cls._parsers:
            del cls._parsers[name]

    @classmethod
    def get_parser(cls, name: str) -> Optional[ProtocolParser]:
        """获取解析器"""
        return cls._parsers.get(name)

    @classmethod
    def get_all_parsers(cls) -> Dict[str, ProtocolParser]:
        """获取所有解析器"""
        return cls._parsers.copy()

    @classmethod
    def parse_packet(cls, raw_packet: Any, packet_id: int = 0) -> ParsedPacket:
        """
        解析完整数据包
        :param raw_packet: 原始数据包（Scapy Packet或bytes）
        :param packet_id: 数据包序号
        :return: ParsedPacket对象
        """
        parsed = ParsedPacket(
            packet_id=packet_id,
            timestamp=time.time(),
            length=len(raw_packet) if raw_packet else 0,
            raw_packet=bytes(raw_packet) if raw_packet else bytes()
        )

        context = {}

        # 尝试使用Scapy Packet
        try:
            from scapy.packet import Packet
            if isinstance(raw_packet, Packet):
                parsed = cls._parse_scapy_packet(raw_packet, parsed, context)
            else:
                parsed = cls._parse_bytes_packet(raw_packet, parsed, context)
        except ImportError:
            parsed = cls._parse_bytes_packet(raw_packet, parsed, context)

        return parsed

    @classmethod
    def _parse_scapy_packet(cls, packet: Any, parsed: ParsedPacket, context: Dict) -> ParsedPacket:
        """解析Scapy Packet对象"""
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.http import HTTP

        parsed.timestamp = float(packet.time)
        parsed.length = len(packet)
        parsed.protocol_layers = [layer.__name__ for layer in packet.layers()]

        # Ethernet层
        if Ether in packet:
            parsed.src_mac = packet[Ether].src
            parsed.dst_mac = packet[Ether].dst
            parsed.layers['Ethernet'] = {
                'src': packet[Ether].src,
                'dst': packet[Ether].dst,
                'type': packet[Ether].type
            }

        # IP层
        if IP in packet:
            parsed.src_ip = packet[IP].src
            parsed.dst_ip = packet[IP].dst
            parsed.layers['IP'] = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'version': packet[IP].version,
                'ttl': packet[IP].ttl,
                'proto': packet[IP].proto,
                'id': packet[IP].id,
                'flags': str(packet[IP].flags)
            }
            context['ip_proto'] = packet[IP].proto

        # TCP层
        if TCP in packet:
            parsed.src_port = packet[TCP].sport
            parsed.dst_port = packet[TCP].dport
            parsed.protocol = 'TCP'
            parsed.layers['TCP'] = {
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack,
                'flags': str(packet[TCP].flags),
                'window': packet[TCP].window,
                'urgptr': packet[TCP].urgptr
            }

            # 根据端口推断应用协议
            app_proto = cls._guess_application_protocol(packet[TCP].sport, packet[TCP].dport)
            if app_proto:
                parsed.protocol = app_proto

        # UDP层
        if UDP in packet:
            parsed.src_port = packet[UDP].sport
            parsed.dst_port = packet[UDP].dport
            parsed.protocol = 'UDP'
            parsed.layers['UDP'] = {
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport,
                'length': packet[UDP].len
            }

            # 根据端口推断应用协议
            app_proto = cls._guess_application_protocol(packet[UDP].sport, packet[UDP].dport)
            if app_proto:
                parsed.protocol = app_proto

        # 生成摘要
        parsed.summary = cls._generate_summary(packet, parsed)

        return parsed

    @classmethod
    def _parse_bytes_packet(cls, data: bytes, parsed: ParsedPacket, context: Dict) -> ParsedPacket:
        """解析原始字节数据（备用方法）"""
        # 使用dpkt解析
        try:
            import dpkt

            # 尝试解析Ethernet帧
            try:
                eth = dpkt.ethernet.Ethernet(data)
                parsed.src_mac = f"{eth.src.hex()}"
                parsed.dst_mac = f"{eth.dst.hex()}"

                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    parsed.src_ip = f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}"
                    parsed.dst_ip = f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}"
                    parsed.layers['IP'] = {
                        'src': parsed.src_ip,
                        'dst': parsed.dst_ip,
                        'proto': ip.p
                    }

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        parsed.src_port = tcp.sport
                        parsed.dst_port = tcp.dport
                        parsed.protocol = 'TCP'
                        parsed.layers['TCP'] = {
                            'src_port': tcp.sport,
                            'dst_port': tcp.dport,
                            'flags': tcp.flags
                        }

                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        parsed.src_port = udp.sport
                        parsed.dst_port = udp.dport
                        parsed.protocol = 'UDP'
                        parsed.layers['UDP'] = {
                            'src_port': udp.sport,
                            'dst_port': udp.dport
                        }

            except Exception as e:
                logger.debug(f"dpkt parsing error: {e}")

        except ImportError:
            logger.warning("dpkt not available for bytes parsing")

        return parsed

    @classmethod
    def _guess_application_protocol(cls, src_port: int, dst_port: int) -> Optional[str]:
        """根据端口推断应用协议"""
        port_protocol_map = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT',
        }

        # 检查源端口和目的端口
        if dst_port in port_protocol_map:
            return port_protocol_map[dst_port]
        if src_port in port_protocol_map:
            return port_protocol_map[src_port]

        return None

    @classmethod
    def _generate_summary(cls, packet: Any, parsed: ParsedPacket) -> str:
        """生成数据包摘要"""
        summary_parts = []

        # 协议类型
        summary_parts.append(parsed.protocol)

        # 地址信息
        if parsed.src_ip and parsed.dst_ip:
            src = parsed.get_source_address()
            dst = parsed.get_destination_address()
            summary_parts.append(f"{src} -> {dst}")

        # 特定协议信息
        if parsed.protocol == 'DNS':
            dns_layer = parsed.layers.get('DNS', {})
            if dns_layer.get('query'):
                summary_parts.append(f"Query: {dns_layer['query']}")
            elif dns_layer.get('response'):
                summary_parts.append(f"Response: {dns_layer['response']}")

        elif parsed.protocol in ['HTTP', 'HTTPS']:
            http_layer = parsed.layers.get('HTTP', {})
            if http_layer.get('method'):
                summary_parts.append(f"{http_layer['method']} {http_layer.get('uri', '')}")

        elif parsed.protocol == 'TCP':
            tcp_layer = parsed.layers.get('TCP', {})
            flags = tcp_layer.get('flags', '')
            if flags:
                summary_parts.append(f"[{flags}]")

        return ' '.join(str(p) for p in summary_parts if p)