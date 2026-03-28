"""
UDP协议解析器
"""
from typing import Dict, Any
from .protocol_parser import ProtocolParser, ProtocolLayer
import logging

logger = logging.getLogger('wifi_analyzer.parser')


class UDPParser(ProtocolParser):
    """UDP协议解析器"""

    @property
    def name(self) -> str:
        return "UDP"

    @property
    def layer(self) -> ProtocolLayer:
        return ProtocolLayer.TRANSPORT

    def parse(self, packet_data: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """解析UDP协议数据"""
        result = {}

        try:
            from scapy.layers.inet import UDP

            if isinstance(packet_data, UDP):
                result = {
                    'src_port': packet_data.sport,
                    'dst_port': packet_data.dport,
                    'length': packet_data.len,
                    'checksum': packet_data.chksum,
                    'payload_length': len(packet_data.payload) if packet_data.payload else 0
                }

                # 根据端口推断应用协议
                result['application_protocol'] = self._guess_protocol(
                    packet_data.sport, packet_data.dport
                )

            else:
                import dpkt
                if isinstance(packet_data, dpkt.udp.UDP):
                    result = {
                        'src_port': packet_data.sport,
                        'dst_port': packet_data.dport,
                        'length': packet_data.ulen,
                        'checksum': packet_data.sum,
                        'payload_length': len(packet_data.data) if packet_data.data else 0
                    }

        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"UDP parsing error: {e}")

        return result

    def _guess_protocol(self, src_port: int, dst_port: int) -> str:
        """根据端口推断协议"""
        udp_ports = {
            53: 'DNS',
            67: 'DHCP-Server',
            68: 'DHCP-Client',
            69: 'TFTP',
            123: 'NTP',
            161: 'SNMP',
            162: 'SNMP-Trap',
            500: 'IKE',
            514: 'Syslog',
            1812: 'RADIUS',
            1900: 'SSDP',
            5353: 'mDNS',
            4500: 'IKE-NAT'
        }

        if dst_port in udp_ports:
            return udp_ports[dst_port]
        if src_port in udp_ports:
            return udp_ports[src_port]

        return 'Unknown'

    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取UDP协议摘要"""
        if parsed_data.get('error'):
            return f"UDP: Error - {parsed_data['error']}"

        src_port = parsed_data.get('src_port', '?')
        dst_port = parsed_data.get('dst_port', '?')
        length = parsed_data.get('length', '?')
        app_proto = parsed_data.get('application_protocol', '')

        summary = f"Port {src_port} -> {dst_port} Len={length}"
        if app_proto and app_proto != 'Unknown':
            summary += f" [{app_proto}]"

        return summary

    def can_parse(self, packet_data: Any) -> bool:
        """检查是否可以解析"""
        try:
            from scapy.layers.inet import UDP
            import dpkt

            return isinstance(packet_data, UDP) or isinstance(packet_data, dpkt.udp.UDP)
        except:
            return False