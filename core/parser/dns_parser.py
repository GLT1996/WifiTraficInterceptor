"""
DNS协议解析器
"""
from typing import Dict, Any, List
from .protocol_parser import ProtocolParser, ProtocolLayer
import logging

logger = logging.getLogger('wifi_analyzer.parser')


class DNSParser(ProtocolParser):
    """DNS协议解析器"""

    # DNS记录类型
    RECORD_TYPES = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        13: 'HINFO',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        41: 'OPT',
        43: 'DS',
        44: 'SSHFP',
        46: 'RRSIG',
        47: 'NSEC',
        48: 'DNSKEY',
        52: 'TLSA',
        255: 'ANY',
        257: 'CAA'
    }

    # DNS响应代码
    RESPONSE_CODES = {
        0: 'No Error',
        1: 'Format Error',
        2: 'Server Failure',
        3: 'Name Error (NXDOMAIN)',
        4: 'Not Implemented',
        5: 'Refused',
        6: 'Name Exists when it should not',
        7: 'RR Set Exists when it should not',
        8: 'RR Set that should exist does not',
        9: 'Not Authorized',
        10: 'Name not contained in zone',
        11: 'DSOTYPENI'
    }

    @property
    def name(self) -> str:
        return "DNS"

    @property
    def layer(self) -> ProtocolLayer:
        return ProtocolLayer.APPLICATION

    def parse(self, packet_data: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """解析DNS协议数据"""
        result = {}

        try:
            from scapy.layers.dns import DNS

            if DNS in packet_data:
                dns = packet_data[DNS]
                result = self._parse_scapy_dns(dns)

            else:
                import dpkt
                from scapy.layers.inet import UDP

                if UDP in packet_data and (packet_data[UDP].sport == 53 or packet_data[UDP].dport == 53):
                    payload = bytes(packet_data[UDP].payload)
                    if payload:
                        dns = dpkt.dns.DNS(payload)
                        result = self._parse_dpkt_dns(dns)

        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"DNS parsing error: {e}")

        return result

    def _parse_scapy_dns(self, dns) -> Dict[str, Any]:
        """解析Scapy DNS对象"""
        result = {
            'id': dns.id,
            'qr': dns.qr,  # 0=查询, 1=响应
            'opcode': dns.opcode,
            'authoritative': dns.aa,
            'truncated': dns.tc,
            'recursion_desired': dns.rd,
            'recursion_available': dns.ra,
            'rcode': dns.rcode,
            'rcode_text': self.RESPONSE_CODES.get(dns.rcode, 'Unknown'),
            'questions': [],
            'answers': [],
            'authority': [],
            'additional': []
        }

        # 解析问题部分
        if dns.qd:
            for q in dns.qd:
                qname = q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname)
                qtype = self.RECORD_TYPES.get(q.qtype, f'Type{q.qtype}')
                result['questions'].append({
                    'name': qname.rstrip('.'),
                    'type': qtype,
                    'class': 'IN' if q.qclass == 1 else f'Class{q.qclass}'
                })

        # 解析回答部分
        if dns.an:
            for a in dns.an:
                answer = self._parse_dns_record(a)
                result['answers'].append(answer)

        # 解析授权部分
        if dns.ns:
            for n in dns.ns:
                authority = self._parse_dns_record(n)
                result['authority'].append(authority)

        # 解析附加部分
        if dns.ar:
            for a in dns.ar:
                additional = self._parse_dns_record(a)
                result['additional'].append(additional)

        return result

    def _parse_dns_record(self, record) -> Dict[str, Any]:
        """解析DNS记录"""
        rname = record.rrname.decode() if isinstance(record.rrname, bytes) else str(record.rrname)
        rtype = self.RECORD_TYPES.get(record.type, f'Type{record.type}')

        result = {
            'name': rname.rstrip('.'),
            'type': rtype,
            'ttl': record.ttl,
            'data': ''
        }

        # 根据类型解析数据
        try:
            if rtype == 'A':
                result['data'] = record.rdata
            elif rtype == 'AAAA':
                result['data'] = record.rdata
            elif rtype == 'CNAME':
                result['data'] = record.rdata.decode() if isinstance(record.rdata, bytes) else str(record.rdata)
            elif rtype == 'MX':
                if hasattr(record.rdata, 'exchange'):
                    result['data'] = f"{record.rdata.preference} {record.rdata.exchange}"
            elif rtype == 'TXT':
                result['data'] = record.rdata.decode() if isinstance(record.rdata, bytes) else str(record.rdata)
            elif rtype == 'NS':
                result['data'] = record.rdata.decode() if isinstance(record.rdata, bytes) else str(record.rdata)
            elif rtype == 'PTR':
                result['data'] = record.rdata.decode() if isinstance(record.rdata, bytes) else str(record.rdata)
            else:
                result['data'] = str(record.rdata)
        except:
            result['data'] = 'Parse Error'

        return result

    def _parse_dpkt_dns(self, dns) -> Dict[str, Any]:
        """解析dpkt DNS对象"""
        result = {
            'id': dns.id,
            'qr': dns.qr,
            'opcode': dns.opcode,
            'rcode': dns.rcode,
            'questions': [],
            'answers': []
        }

        # 解析问题
        for q in dns.qd:
            result['questions'].append({
                'name': self._decode_dns_name(q.name),
                'type': self.RECORD_TYPES.get(q.type, f'Type{q.type}')
            })

        # 解析回答
        for a in dns.an:
            result['answers'].append({
                'name': self._decode_dns_name(a.name),
                'type': self.RECORD_TYPES.get(a.type, f'Type{a.type}'),
                'data': self._decode_dns_name(a.rdata) if a.type in [2, 5, 12, 15] else str(a.rdata)
            })

        return result

    def _decode_dns_name(self, name: bytes) -> str:
        """解码DNS名称"""
        try:
            if isinstance(name, bytes):
                parts = []
                i = 0
                while i < len(name):
                    length = name[i]
                    if length == 0:
                        break
                    if length >= 192:  # 指针
                        # 简化处理，不解析指针
                        break
                    i += 1
                    parts.append(name[i:i+length].decode('ascii', errors='ignore'))
                    i += length
                return '.'.join(parts).rstrip('.')
            return str(name)
        except:
            return str(name)

    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取DNS协议摘要"""
        if parsed_data.get('error'):
            return f"DNS: Error - {parsed_data['error']}"

        qr = parsed_data.get('qr', 0)
        questions = parsed_data.get('questions', [])
        answers = parsed_data.get('answers', [])
        rcode = parsed_data.get('rcode_text', '')

        if qr == 0:  # 查询
            if questions:
                q = questions[0]
                return f"Query: {q['name']} [{q['type']}]"
            return "DNS Query"

        else:  # 响应
            if answers:
                ans_data = [a['data'] for a in answers[:3]]
                return f"Response: {', '.join(ans_data)}" + (f" ({rcode})" if rcode != 'No Error' else "")
            return f"DNS Response ({rcode})"

    def can_parse(self, packet_data: Any) -> bool:
        """检查是否可以解析"""
        try:
            from scapy.layers.dns import DNS
            from scapy.layers.inet import UDP

            if DNS in packet_data:
                return True

            if UDP in packet_data:
                port = packet_data[UDP].sport
                if port == 53:
                    return True

        except:
            pass

        return False