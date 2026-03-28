"""
TCP协议解析器
"""
from typing import Dict, Any
from .protocol_parser import ProtocolParser, ProtocolLayer
import logging

logger = logging.getLogger('wifi_analyzer.parser')


class TCPParser(ProtocolParser):
    """TCP协议解析器"""

    # TCP标志位
    FLAGS = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR'
    }

    @property
    def name(self) -> str:
        return "TCP"

    @property
    def layer(self) -> ProtocolLayer:
        return ProtocolLayer.TRANSPORT

    def parse(self, packet_data: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """解析TCP协议数据"""
        result = {}

        try:
            from scapy.layers.inet import TCP

            if isinstance(packet_data, TCP):
                # 解析标志位
                flags_str = str(packet_data.flags)
                flags_list = [self.FLAGS.get(f, f) for f in flags_str]

                result = {
                    'src_port': packet_data.sport,
                    'dst_port': packet_data.dport,
                    'seq_number': packet_data.seq,
                    'ack_number': packet_data.ack,
                    'data_offset': packet_data.dataofs * 4,
                    'reserved': packet_data.reserved,
                    'flags': flags_str,
                    'flags_list': flags_list,
                    'window_size': packet_data.window,
                    'checksum': packet_data.chksum,
                    'urgent_pointer': packet_data.urgptr,
                    'options': [],
                    'payload_length': len(packet_data.payload) if packet_data.payload else 0
                }

                # 解析TCP选项
                if packet_data.options:
                    for opt in packet_data.options:
                        opt_name = self._parse_tcp_option(opt)
                        result['options'].append(opt_name)

                # 分析TCP状态
                result['tcp_state_hint'] = self._analyze_tcp_state(flags_str)

            else:
                import dpkt
                if isinstance(packet_data, dpkt.tcp.TCP):
                    result = {
                        'src_port': packet_data.sport,
                        'dst_port': packet_data.dport,
                        'seq_number': packet_data.seq,
                        'ack_number': packet_data.ack,
                        'flags': packet_data.flags,
                        'window_size': packet_data.win,
                        'urgent_pointer': packet_data.urp,
                        'payload_length': len(packet_data.data) if packet_data.data else 0
                    }

        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"TCP parsing error: {e}")

        return result

    def _parse_tcp_option(self, option) -> str:
        """解析TCP选项"""
        option_names = {
            0: 'End of Options',
            1: 'No Operation',
            2: 'Maximum Segment Size',
            3: 'Window Scale',
            4: 'SACK Permitted',
            5: 'SACK',
            8: 'Timestamps',
            19: 'MD5 Signature',
            28: 'User Timeout',
            34: 'TCP Fast Open'
        }

        if hasattr(option, 'option'):
            name = option_names.get(option.option, f'Unknown({option.option})')
            if hasattr(option, 'length'):
                return f"{name} (len={option.length})"
            return name
        return str(option)

    def _analyze_tcp_state(self, flags_str: str) -> str:
        """分析TCP状态"""
        # 常见TCP状态分析
        if 'S' in flags_str and 'A' in flags_str:
            return 'SYN-ACK (Connection Response)'
        elif 'S' in flags_str:
            return 'SYN (Connection Request)'
        elif 'F' in flags_str and 'A' in flags_str:
            return 'FIN-ACK (Connection Close)'
        elif 'F' in flags_str:
            return 'FIN (Connection Close Request)'
        elif 'R' in flags_str:
            return 'RST (Connection Reset)'
        elif 'P' in flags_str and 'A' in flags_str:
            return 'PSH-ACK (Data Push)'
        elif 'A' in flags_str:
            return 'ACK'
        else:
            return 'Other'

    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取TCP协议摘要"""
        if parsed_data.get('error'):
            return f"TCP: Error - {parsed_data['error']}"

        src_port = parsed_data.get('src_port', '?')
        dst_port = parsed_data.get('dst_port', '?')
        flags = parsed_data.get('flags', '')
        seq = parsed_data.get('seq_number', '?')
        ack = parsed_data.get('ack_number', '?')
        win = parsed_data.get('window_size', '?')

        parts = [f"Port {src_port} -> {dst_port}"]
        if flags:
            parts.append(f"[{flags}]")
        parts.append(f"Seq={seq}")
        if 'A' in flags:
            parts.append(f"Ack={ack}")
        parts.append(f"Win={win}")

        return ' '.join(parts)

    def can_parse(self, packet_data: Any) -> bool:
        """检查是否可以解析"""
        try:
            from scapy.layers.inet import TCP
            import dpkt

            return isinstance(packet_data, TCP) or isinstance(packet_data, dpkt.tcp.TCP)
        except:
            return False