"""
网卡接口管理器
"""
import platform
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass

try:
    from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger('wifi_analyzer.capture')


@dataclass
class InterfaceInfo:
    """网卡接口信息"""
    name: str
    ip_address: str
    mac_address: str
    description: str = ""
    is_up: bool = True
    is_wifi: bool = False


class InterfaceManager:
    """网卡接口管理器"""

    def __init__(self):
        self.interfaces: List[InterfaceInfo] = []
        self.selected_interface: Optional[str] = None
        self._scan_interfaces()

    def _scan_interfaces(self) -> None:
        """扫描可用网卡接口"""
        self.interfaces = []

        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, using fallback method")
            self._scan_interfaces_fallback()
            return

        try:
            for iface_name in get_if_list():
                try:
                    ip_addr = get_if_addr(iface_name)
                    mac_addr = get_if_hwaddr(iface_name)

                    # 过滤无效接口
                    if ip_addr == '0.0.0.0' or not mac_addr:
                        continue

                    interface = InterfaceInfo(
                        name=iface_name,
                        ip_address=ip_addr,
                        mac_address=mac_addr,
                        description=self._get_interface_description(iface_name),
                        is_wifi=self._check_wifi_interface(iface_name)
                    )
                    self.interfaces.append(interface)
                    logger.debug(f"Found interface: {iface_name} ({ip_addr})")

                except Exception as e:
                    logger.debug(f"Skipping interface {iface_name}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error scanning interfaces: {e}")
            self._scan_interfaces_fallback()

    def _scan_interfaces_fallback(self) -> None:
        """备用网卡扫描方法"""
        import socket

        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)

            # Windows平台使用netsh命令获取更多信息
            if platform.system() == 'Windows':
                import subprocess
                try:
                    result = subprocess.run(
                        ['netsh', 'interface', 'show', 'interface'],
                        capture_output=True, text=True, timeout=5,
                        encoding='gbk', errors='ignore'
                    )
                    # 解析netsh输出
                    lines = result.stdout.strip().split('\n')
                    for line in lines[3:]:  # 跳过标题行
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            name = parts[-1]
                            if local_ip:
                                interface = InterfaceInfo(
                                    name=name,
                                    ip_address=local_ip,
                                    mac_address="",
                                    description=name,
                                    is_up=parts[0] == 'Connected'
                                )
                                self.interfaces.append(interface)
                except Exception as e:
                    logger.debug(f"netsh fallback failed: {e}")

        except Exception as e:
            logger.error(f"Fallback interface scan failed: {e}")

    def _get_interface_description(self, iface_name: str) -> str:
        """获取网卡描述"""
        if platform.system() == 'Windows':
            # Windows上尝试获取更友好的名称
            import subprocess
            try:
                result = subprocess.run(
                    ['netsh', 'interface', 'show', 'interface', iface_name],
                    capture_output=True, text=True, timeout=2,
                    encoding='gbk', errors='ignore'
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'Type' in line or 'Interface' in line:
                            return line.strip()
            except:
                pass
        return iface_name

    def _check_wifi_interface(self, iface_name: str) -> bool:
        """检查是否为WiFi接口"""
        wifi_keywords = ['wi-fi', 'wireless', 'wlan', 'wifi', '802.11']
        name_lower = iface_name.lower()

        for keyword in wifi_keywords:
            if keyword in name_lower:
                return True

        return False

    def get_interfaces(self) -> List[InterfaceInfo]:
        """获取所有接口列表"""
        return self.interfaces

    def get_wifi_interfaces(self) -> List[InterfaceInfo]:
        """获取WiFi接口列表"""
        return [iface for iface in self.interfaces if iface.is_wifi]

    def select_interface(self, name: str) -> bool:
        """选择网卡接口"""
        for iface in self.interfaces:
            if iface.name == name:
                self.selected_interface = name
                logger.info(f"Selected interface: {name}")
                return True
        logger.warning(f"Interface not found: {name}")
        return False

    def get_selected_interface(self) -> Optional[InterfaceInfo]:
        """获取当前选中的接口"""
        if self.selected_interface:
            for iface in self.interfaces:
                if iface.name == self.selected_interface:
                    return iface
        return None

    def refresh(self) -> None:
        """重新扫描接口"""
        self._scan_interfaces()
        logger.info(f"Refreshed interfaces, found {len(self.interfaces)}")