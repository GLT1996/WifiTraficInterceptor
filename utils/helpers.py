"""
辅助函数
"""
import time
from datetime import datetime
from typing import Any, Dict, List


def format_timestamp(timestamp: float, format_type: str = "relative") -> str:
    """
    格式化时间戳
    :param timestamp: 时间戳
    :param format_type: relative, absolute, utc
    """
    if format_type == "relative":
        return f"{timestamp:.6f}"
    elif format_type == "absolute":
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    elif format_type == "utc":
        dt = datetime.utcfromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return str(timestamp)


def format_bytes(size: int) -> str:
    """格式化字节大小"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def format_duration(seconds: float) -> str:
    """格式化持续时间"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def truncate_string(s: str, max_length: int = 50) -> str:
    """截断字符串"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def safe_decode(data: bytes, encoding: str = 'utf-8') -> str:
    """安全解码字节"""
    try:
        return data.decode(encoding)
    except:
        return data.decode(encoding, errors='replace')


def get_color_for_protocol(protocol: str) -> tuple:
    """根据协议返回颜色"""
    colors = {
        'TCP': (200, 255, 200),
        'UDP': (200, 200, 255),
        'HTTP': (255, 255, 200),
        'HTTPS': (255, 230, 230),
        'DNS': (255, 200, 200),
        'TLS': (230, 230, 255),
        'ICMP': (255, 200, 255),
        'ARP': (200, 255, 255),
    }
    return colors.get(protocol, (255, 255, 255))


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """合并字典"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def calculate_checksum(data: bytes) -> int:
    """计算校验和"""
    if len(data) % 2:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        checksum += (data[i] << 8) + data[i + 1]

    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return ~checksum & 0xFFFF


class RateCalculator:
    """速率计算器"""

    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.samples: List[tuple] = []  # [(timestamp, count)]

    def add_sample(self, count: int) -> None:
        """添加样本"""
        self.samples.append((time.time(), count))

        # 保持窗口大小
        if len(self.samples) > self.window_size:
            self.samples.pop(0)

    def get_rate(self) -> float:
        """计算速率"""
        if len(self.samples) < 2:
            return 0.0

        first_time, first_count = self.samples[0]
        last_time, last_count = self.samples[-1]

        duration = last_time - first_time
        if duration <= 0:
            return 0.0

        return (last_count - first_count) / duration