"""
HTTP协议解析器
"""
from typing import Dict, Any, Optional
from .protocol_parser import ProtocolParser, ProtocolLayer
import logging

logger = logging.getLogger('wifi_analyzer.parser')


class HTTPParser(ProtocolParser):
    """HTTP协议解析器"""

    @property
    def name(self) -> str:
        return "HTTP"

    @property
    def layer(self) -> ProtocolLayer:
        return ProtocolLayer.APPLICATION

    def parse(self, packet_data: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """解析HTTP协议数据"""
        result = {}

        try:
            # 尝试Scapy HTTP层
            from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

            if HTTPRequest in packet_data:
                result = self._parse_http_request(packet_data[HTTPRequest])

            elif HTTPResponse in packet_data:
                result = self._parse_http_response(packet_data[HTTPResponse])

            elif HTTP in packet_data:
                # 一般HTTP层
                result = self._parse_generic_http(packet_data[HTTP])

            else:
                # 尝试从TCP payload解析
                result = self._parse_http_from_payload(packet_data)

        except ImportError:
            # Scapy HTTP层不可用，从payload解析
            result = self._parse_http_from_payload(packet_data)

        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"HTTP parsing error: {e}")

        return result

    def _parse_http_request(self, http_req) -> Dict[str, Any]:
        """解析HTTP请求"""
        result = {
            'type': 'Request',
            'method': http_req.Method.decode() if http_req.Method else 'Unknown',
            'uri': http_req.Path.decode() if http_req.Path else '/',
            'host': http_req.Host.decode() if http_req.Host else '',
            'version': 'HTTP/1.1' if http_req.Http_Version else 'Unknown',
            'headers': {},
            'user_agent': '',
            'content_type': '',
            'content_length': 0
        }

        # 解析头部
        if hasattr(http_req, 'headers'):
            for field in http_req.headers.fields:
                key = field[0].decode() if isinstance(field[0], bytes) else field[0]
                value = field[1].decode() if isinstance(field[1], bytes) else field[1]
                result['headers'][key] = value

                # 常见头部
                if key.lower() == 'user-agent':
                    result['user_agent'] = value
                elif key.lower() == 'content-type':
                    result['content_type'] = value
                elif key.lower() == 'content-length':
                    try:
                        result['content_length'] = int(value)
                    except:
                        pass
                elif key.lower() == 'referer':
                    result['referer'] = value
                elif key.lower() == 'cookie':
                    result['cookie'] = value

        return result

    def _parse_http_response(self, http_resp) -> Dict[str, Any]:
        """解析HTTP响应"""
        result = {
            'type': 'Response',
            'status_code': http_resp.Status_Code.decode() if http_resp.Status_Code else 'Unknown',
            'status_text': http_resp.Reason_phrase.decode() if http_resp.Reason_phrase else '',
            'version': 'HTTP/1.1',
            'headers': {},
            'content_type': '',
            'content_length': 0,
            'server': ''
        }

        # 解析头部
        if hasattr(http_resp, 'headers'):
            for field in http_resp.headers.fields:
                key = field[0].decode() if isinstance(field[0], bytes) else field[0]
                value = field[1].decode() if isinstance(field[1], bytes) else field[1]
                result['headers'][key] = value

                if key.lower() == 'content-type':
                    result['content_type'] = value
                elif key.lower() == 'content-length':
                    try:
                        result['content_length'] = int(value)
                    except:
                        pass
                elif key.lower() == 'server':
                    result['server'] = value
                elif key.lower() == 'location':
                    result['location'] = value

        return result

    def _parse_generic_http(self, http_layer) -> Dict[str, Any]:
        """解析通用HTTP层"""
        return {
            'type': 'Unknown',
            'raw_data': str(http_layer)
        }

    def _parse_http_from_payload(self, packet_data: Any) -> Dict[str, Any]:
        """从TCP payload解析HTTP"""
        result = {'type': 'Unknown'}

        try:
            from scapy.layers.inet import TCP

            if TCP in packet_data:
                payload = bytes(packet_data[TCP].payload)
                if payload:
                    # 尝试解析HTTP文本
                    text = payload.decode('utf-8', errors='ignore')

                    if text.startswith('HTTP/'):
                        # HTTP响应
                        lines = text.split('\r\n')
                        if lines:
                            status_line = lines[0]
                            parts = status_line.split(' ')
                            if len(parts) >= 2:
                                result = {
                                    'type': 'Response',
                                    'status_code': parts[1],
                                    'status_text': parts[2] if len(parts) > 2 else ''
                                }

                    elif any(text.startswith(method) for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']):
                        # HTTP请求
                        lines = text.split('\r\n')
                        if lines:
                            request_line = lines[0]
                            parts = request_line.split(' ')
                            if len(parts) >= 2:
                                result = {
                                    'type': 'Request',
                                    'method': parts[0],
                                    'uri': parts[1],
                                    'version': parts[2] if len(parts) > 2 else ''
                                }

        except Exception as e:
            logger.debug(f"Payload HTTP parsing error: {e}")

        return result

    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取HTTP协议摘要"""
        if parsed_data.get('error'):
            return f"HTTP: Error - {parsed_data['error']}"

        type_ = parsed_data.get('type', '')

        if type_ == 'Request':
            method = parsed_data.get('method', '?')
            uri = parsed_data.get('uri', '?')
            host = parsed_data.get('host', '')
            return f"{method} {uri}" + (f" Host: {host}" if host else "")

        elif type_ == 'Response':
            status = parsed_data.get('status_code', '?')
            text = parsed_data.get('status_text', '')
            return f"Response {status} {text}"

        return "HTTP Data"

    def can_parse(self, packet_data: Any) -> bool:
        """检查是否可以解析"""
        try:
            from scapy.layers.inet import TCP
            from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

            if HTTP in packet_data or HTTPRequest in packet_data or HTTPResponse in packet_data:
                return True

            if TCP in packet_data:
                payload = bytes(packet_data[TCP].payload)
                if payload:
                    text = payload.decode('utf-8', errors='ignore')
                    return text.startswith('HTTP/') or any(
                        text.startswith(m) for m in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']
                    )

        except:
            pass

        return False