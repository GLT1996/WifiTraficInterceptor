"""
网络工具函数
"""
import socket
import platform
import subprocess
import logging
from typing import List, Dict, Optional

logger = logging.getLogger('wifi_analyzer.utils')


def get_local_ip() -> str:
    """获取本机IP地址"""
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except:
        return "127.0.0.1"


def get_hostname(ip: str) -> Optional[str]:
    """根据IP获取主机名"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None


def is_valid_ip(ip: str) -> bool:
    """验证IP地址格式"""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def is_valid_mac(mac: str) -> bool:
    """验证MAC地址格式"""
    import re
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
    return re.match(pattern, mac) is not None


def ip_to_int(ip: str) -> int:
    """IP地址转整数"""
    if not is_valid_ip(ip):
        return 0
    parts = ip.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def int_to_ip(num: int) -> str:
    """整数转IP地址"""
    return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"


def get_network_range(ip: str, subnet_mask: str = "255.255.255.0") -> tuple:
    """获取网络范围"""
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(subnet_mask)

    network = ip_int & mask_int
    broadcast = network | (~mask_int & 0xFFFFFFFF)

    return (int_to_ip(network), int_to_ip(broadcast))


def check_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """检查端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def get_dns_servers() -> List[str]:
    """获取DNS服务器列表"""
    dns_servers = []

    if platform.system() == 'Windows':
        try:
            result = subprocess.run(
                ['ipconfig', '/all'],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split('\n')
            for line in lines:
                if 'DNS Servers' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        dns = parts[1].strip()
                        if is_valid_ip(dns):
                            dns_servers.append(dns)
        except Exception as e:
            logger.debug(f"Failed to get DNS servers: {e}")

    return dns_servers


def ping(host: str, timeout: float = 2.0) -> bool:
    """Ping测试"""
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(
                ['ping', '-n', '1', '-w', str(int(timeout * 1000)), host],
                capture_output=True, timeout=timeout + 1
            )
            return result.returncode == 0
        else:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(int(timeout)), host],
                capture_output=True, timeout=timeout + 1
            )
            return result.returncode == 0
    except:
        return False


def resolve_mac_from_ip(ip: str) -> Optional[str]:
    """从IP地址获取MAC（ARP表）"""
    if platform.system() == 'Windows':
        try:
            result = subprocess.run(
                ['arp', '-a', ip],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split('\n')
            for line in lines:
                if ip in line:
                    parts = line.strip().split()
                    for part in parts:
                        if is_valid_mac(part):
                            return part
        except:
            pass

    return None