"""
IP协议解析器
"""
from typing import Dict, Any, Optional
from .protocol_parser import ProtocolParser, ProtocolLayer, ParsedPacket
import logging

logger = logging.getLogger('wifi_analyzer.parser')


class IPParser(ProtocolParser):
    """IP协议解析器"""

    @property
    def name(self) -> str:
        return "IP"

    @property
    def layer(self) -> ProtocolLayer:
        return ProtocolLayer.NETWORK

    def parse(self, packet_data: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """解析IP协议数据"""
        result = {}

        try:
            from scapy.layers.inet import IP

            if isinstance(packet_data, IP):
                result = {
                    'version': packet_data.version,
                    'header_length': packet_data.ihl * 4,
                    'total_length': packet_data.len,
                    'identification': packet_data.id,
                    'flags': {
                        'reserved': bool(packet_data.flags.rf),
                        'dont_fragment': bool(packet_data.flags.df),
                        'more_fragments': bool(packet_data.flags.mf)
                    },
                    'fragment_offset': packet_data.frag,
                    'ttl': packet_data.ttl,
                    'protocol': packet_data.proto,
                    'checksum': packet_data.chksum,
                    'src': packet_data.src,
                    'dst': packet_data.dst,
                    'options': []
                }

                # 协议号映射
                proto_map = {
                    1: 'ICMP',
                    2: 'IGMP',
                    6: 'TCP',
                    17: 'UDP',
                    41: 'IPv6',
                    47: 'GRE',
                    50: 'ESP',
                    51: 'AH',
                    89: 'OSPF',
                    132: 'SCTP'
                }
                result['protocol_name'] = proto_map.get(packet_data.proto, f'Unknown({packet_data.proto})')

                # 解析选项
                if packet_data.options:
                    for opt in packet_data.options:
                        result['options'].append(str(opt))

            else:
                # 使用dpkt解析
                import dpkt
                if isinstance(packet_data, dpkt.ip.IP):
                    result = {
                        'version': packet_data.v,
                        'header_length': packet_data.hl * 4,
                        'total_length': packet_data.len,
                        'identification': packet_data.id,
                        'ttl': packet_data.ttl,
                        'protocol': packet_data.p,
                        'src': '.'.join(str(b) for b in packet_data.src),
                        'dst': '.'.join(str(b) for b in packet_data.dst)
                    }

        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"IP parsing error: {e}")

        return result

    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取IP协议摘要"""
        if parsed_data.get('error'):
            return f"IP: Error - {parsed_data['error']}"

        src = parsed_data.get('src', '?')
        dst = parsed_data.get('dst', '?')
        proto = parsed_data.get('protocol_name', parsed_data.get('protocol', '?'))
        ttl = parsed_data.get('ttl', '?')

        return f"{src} -> {dst} [{proto}] TTL={ttl}"

    def can_parse(self, packet_data: Any) -> bool:
        """检查是否可以解析"""
        try:
            from scapy.layers.inet import IP
            import dpkt

            return isinstance(packet_data, IP) or isinstance(packet_data, dpkt.ip.IP)
        except:
            return False


class IPv6Parser(ProtocolParser):
    """IPv6协议解析器"""

    @property
    def name(self) -> str:
        return "IPv6"

    @property
    def layer(self) -> ProtocolLayer:
        return ProtocolLayer.NETWORK

    def parse(self, packet_data: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """解析IPv6协议数据"""
        result = {}

        try:
            from scapy.layers.inet6 import IPv6

            if isinstance(packet_data, IPv6):
                result = {
                    'version': 6,
                    'traffic_class': packet_data.tc,
                    'flow_label': packet_data.fl,
                    'payload_length': packet_data.plen,
                    'next_header': packet_data.nh,
                    'hop_limit': packet_data.hlim,
                    'src': packet_data.src,
                    'dst': packet_data.dst
                }

        except Exception as e:
            result['error'] = str(e)

        return result

    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取IPv6摘要"""
        src = parsed_data.get('src', '?')
        dst = parsed_data.get('dst', '?')
        nh = parsed_data.get('next_header', '?')

        return f"{src} -> {dst} [NextHeader={nh}]"