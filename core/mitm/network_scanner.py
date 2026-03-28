"""
网络扫描器 - 扫描局域网内所有活跃设备
"""
import threading
import logging
from typing import List, Callable, Optional
from dataclasses import dataclass, field
import time

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger('wifi_analyzer.mitm')


@dataclass
class DeviceInfo:
    """设备信息"""
    ip: str
    mac: str
    vendor: str = "Unknown"
    hostname: str = ""
    is_gateway: bool = False
    is_self: bool = False
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def __str__(self) -> str:
        return f"{self.ip} ({self.mac}) - {self.vendor}"


class NetworkScanner:
    """网络扫描器 - 使用ARP扫描局域网设备"""

    # 常见厂商OUI前缀
    VENDOR_PREFIXES = {
        'Apple': ['00:03:93', '00:05:CA', '00:0A:27', '00:17:F2', '00:1B:63',
                  '00:1C:10', '00:1D:4F', '00:1E:52', '00:1F:71', '00:21:E9',
                  '00:22:41', '00:23:12', '00:25:00', '00:25:4B', '00:25:BC',
                  'A4:83:E7', 'AC:87:A3', 'B8:8D:12', 'BC:3B:AF', 'C0:63:94',
                  'DC:A4:CA', 'DC:9B:9C', 'E0:AC:CB', 'E8:04:0B', 'F0:98:9D'],
        'Samsung': ['00:00:F0', '00:07:4D', '00:12:FB', '00:16:6B', '00:17:8A',
                    '00:18:AF', '00:19:45', '00:1A:9F', '00:1B:52', '00:1C:62',
                    'A0:0B:BA', 'A4:C3:F0', 'B0:EC:71', 'B4:74:43', 'C0:97:27',
                    'CC:B1:1A', 'D8:63:75', 'DC:74:9F', 'E0:7C:62', 'F0:14:79'],
        'Huawei': ['00:0E:3D', '00:0F:E2', '00:11:92', '00:15:9B', '00:17:AB',
                   '00:18:82', '00:1A:A0', '00:1B:22', '00:1C:14', '00:1D:0D',
                   '0C:96:BF', '10:1D:00', '10:30:8B', '20:6B:E7', '28:ED:6A',
                   '30:07:4D', '34:6B:D3', '3C:D0:F8', '48:9E:BD', '4C:FB:D9',
                   '5C:8F:0E', '60:6D:C7', '64:9B:55', '70:6E:6D', '74:8B:F0',
                   '78:3E:53', '80:47:21', '84:10:45', '88:66:3A', '8C:71:F8',
                   '90:2B:34', '94:87:70', '98:6B:8E', '9C:2E:A1', 'A0:B7:65',
                   'B0:9F:BA', 'BC:8F:BE', 'C0:EE:FB', 'C8:E8:72', 'CC:96:88',
                   'D0:77:14', 'D8:37:3B', 'DC:2C:6A', 'E0:D4:64', 'E4:9E:9A',
                   'EC:9A:CB', 'F0:9F:C2', 'F4:D1:08', 'FC:64:BA'],
        'Xiaomi': ['00:0E:8F', '10:6F:3F', '18:59:36', '24:6F:28', '28:ED:E0',
                   '2C:96:E4', '34:80:B3', '38:1A:2A', '3C:BD:D8', '40:31:3C',
                   '44:09:20', '48:88:CA', '4C:4A:27', '50:EC:50', '54:EF:44',
                   '58:44:98', '5C:51:4F', '60:09:15', '64:5D:86', '68:96:4B',
                   '6C:5D:43', '70:1C:E7', '74:A3:E4', '78:02:F8', '7C:1E:52',
                   '80:8A:7F', '84:10:8C', '88:44:4F', '8C:79:5A', '90:39:BF',
                   '94:87:77', '98:27:82', '9C:2A:70', 'A0:20:17', 'A4:4E:32',
                   'A8:5E:45', 'AC:29:3A', 'B0:E2:35', 'B4:6B:FC', 'BC:1F:F4',
                   'C0:83:10', 'C4:0B:CB', 'C8:3B:01', 'CC:8E:8D', 'D0:61:DD',
                   'D4:5D:64', 'D8:1C:79', 'DC:7F:6C', 'E0:76:D0', 'E4:B2:FB',
                   'E8:99:C4', 'EC:9B:8B', 'F0:5C:77', 'F4:28:53', 'F8:A4:5F',
                   'FC:6D:3A'],
        'Dell': ['00:01:16', '00:02:55', '00:03:BA', '00:04:46', '00:05:1F',
                 '00:06:5B', '00:08:74', '00:09:3D', '00:0A:95', '00:0B:DB',
                 '00:0C:22', '00:0D:56', '00:0E:5E', '00:0F:1F', '00:10:18',
                 '00:11:43', '00:12:3F', '00:13:72', '00:14:22', '00:15:C5'],
        'HP': ['00:01:E6', '00:02:A5', '00:04:76', '00:05:5D', '00:06:5B',
               '00:08:88', '00:09:5B', '00:0A:EC', '00:0B:ED', '00:0C:EE',
               '00:0D:5D', '00:0E:7F', '00:0F:FE', '00:10:FF', '00:11:85'],
        'Lenovo': ['00:00:1B', '00:01:02', '00:02:55', '00:04:76', '00:05:5D',
                   '00:06:5B', '00:08:74', '00:09:3D', '00:0A:EC', '00:0B:ED',
                   '08:9E:08', '0C:8B:FC', '10:30:47', '14:5A:FC', '18:CF:5E',
                   '1C:4B:D6', '20:F4:1B', '28:CF:DA', '2C:DE:7E', '30:63:6B',
                   '34:DE:1A', '38:AE:ED', '3C:A0:F2', '40:AF:A8', '44:37:E6',
                   '48:5A:B6', '4C:7A:99', '50:7B:9D', '54:26:96', '58:00:E3',
                   '5C:26:0A', '60:EB:69', '64:5A:ED', '68:F7:2D', '6C:6A:97',
                   '70:F1:96', '74:E1:63', '78:24:AF', '7C:5A:F1', '80:FA:5B',
                   '84:7B:EB', '88:9F:FA', '8C:DE:52', '90:F0:52', '94:39:E5',
                   '98:83:89', '9C:7B:EF', 'A0:2A:F0', 'A4:83:E7', 'A8:1E:84',
                   'AC:72:8B', 'B0:98:E7', 'B4:B5:FE', 'B8:CA:3A', 'BC:17:B8',
                   'C0:38:96', 'C4:49:30', 'C8:5B:76', 'CC:2D:8B', 'D0:23:DB',
                   'D4:6A:EC', 'D8:38:FC', 'DC:FE:18', 'E0:31:9E', 'E4:90:7E',
                   'E8:6A:64', 'EC:9A:3F', 'F0:18:98', 'F4:39:09', 'F8:A9:63',
                   'FC:34:97'],
    }

    def __init__(self):
        self.devices: List[DeviceInfo] = []
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.is_scanning = False
        self._scan_thread: Optional[threading.Thread] = None

    def get_gateway(self) -> tuple:
        """获取网关IP和MAC地址"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available")
            return None, None

        try:
            # Windows: 使用更快的方式获取网关
            gateway_ip = None
            gateway_mac = None

            if hasattr(conf, 'route'):
                gateway_ip = conf.route.route("0.0.0.0")[2]

            if gateway_ip == "0.0.0.0" or not gateway_ip:
                # 使用 ipconfig 获取默认网关（更快）
                import subprocess
                try:
                    result = subprocess.run(
                        ['ipconfig'],
                        capture_output=True, text=True, timeout=2,
                        encoding='gbk', errors='ignore'
                    )
                    for line in result.stdout.split('\n'):
                        if 'Default Gateway' in line or '默认网关' in line:
                            parts = line.split(':')
                            if len(parts) > 1:
                                ip = parts[1].strip()
                                if self._is_valid_ip(ip) and ip != '0.0.0.0':
                                    gateway_ip = ip
                                    break
                except:
                    pass

            if not gateway_ip or gateway_ip == "0.0.0.0":
                return None, None

            # 获取网关MAC - 使用 ARP 缓存或快速 ping
            gateway_mac = self._get_mac_fast(gateway_ip)

            self.gateway_ip = gateway_ip
            self.gateway_mac = gateway_mac

            return gateway_ip, gateway_mac

        except Exception as e:
            logger.error(f"Failed to get gateway: {e}")
            return None, None

    def _get_mac_fast(self, ip: str) -> Optional[str]:
        """快速获取MAC地址 - 先查ARP缓存，再发送ARP"""
        import subprocess

        # 先尝试从 ARP 缓存读取（无需等待）
        try:
            result = subprocess.run(
                ['arp', '-a', ip],
                capture_output=True, text=True, timeout=2,
                encoding='gbk', errors='ignore'
            )
            for line in result.stdout.split('\n'):
                if ip in line:
                    # 解析 MAC 地址
                    parts = line.split()
                    for part in parts:
                        if '-' in part and len(part) == 17:  # MAC格式 xx-xx-xx-xx-xx-xx
                            mac = part.replace('-', ':').upper()
                            return mac
        except:
            pass

        # ARP缓存没有，先 ping 一下让它出现在缓存中
        try:
            subprocess.run(
                ['ping', '-n', '1', '-w', '100', ip],
                capture_output=True, timeout=1
            )
            # 再查 ARP 缓存
            result = subprocess.run(
                ['arp', '-a', ip],
                capture_output=True, text=True, timeout=1,
                encoding='gbk', errors='ignore'
            )
            for line in result.stdout.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if '-' in part and len(part) == 17:
                            mac = part.replace('-', ':').upper()
                            return mac
        except:
            pass

        # 最后才用 scapy ARP（最慢）
        return self._get_mac(ip)

    def _is_valid_ip(self, ip: str) -> bool:
        """验证IP地址"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except:
            return False

    def _get_mac(self, ip: str) -> Optional[str]:
        """获取指定IP的MAC地址（使用ARP）"""
        if not SCAPY_AVAILABLE:
            return None

        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # 减少超时时间
            result = srp(packet, timeout=1, retry=0, verbose=0)[0]

            if result:
                return result[0][1].hwsrc

        except Exception as e:
            logger.debug(f"Failed to get MAC for {ip}: {e}")

        return None

    def _lookup_vendor(self, mac: str) -> str:
        """根据MAC地址查找厂商"""
        if not mac:
            return "Unknown"

        mac_prefix = mac[:8].upper()

        for vendor, prefixes in self.VENDOR_PREFIXES.items():
            if mac_prefix in prefixes:
                return vendor

        # 尝试使用mac-vendor-lookup库
        try:
            from mac_vendor_lookup import MacLookup
            return MacLookup().lookup(mac)
        except:
            pass

        return "Unknown"

    def scan(self, interface: str = None, network_range: str = None,
             callback: Callable[[List[DeviceInfo]], None] = None,
             async_mode: bool = False) -> List[DeviceInfo]:
        """
        扫描网络

        :param interface: 网卡接口
        :param network_range: 网络范围 (如 192.168.1.0/24)
        :param callback: 扫描完成回调
        :param async_mode: 是否异步扫描
        :return: 设备列表
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available")
            return []

        if async_mode:
            self._scan_thread = threading.Thread(
                target=self._do_scan,
                args=(interface, network_range, callback),
                daemon=True
            )
            self.is_scanning = True
            self._scan_thread.start()
            return []

        return self._do_scan(interface, network_range, callback)

    def _do_scan(self, interface: str, network_range: str,
                 callback: Callable[[List[DeviceInfo]], None]) -> List[DeviceInfo]:
        """执行扫描"""
        self.devices = []

        try:
            # 获取网关信息（用于标识网关设备）
            gateway_ip, gateway_mac = self.get_gateway()

            # 如果没有指定网络范围，根据网关IP推断
            if not network_range and gateway_ip:
                parts = gateway_ip.split('.')
                network_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

            if not network_range:
                logger.error("Cannot determine network range")
                return []

            logger.info(f"Scanning network: {network_range} on interface: {interface or 'default'}")

            # 创建ARP请求包
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # 发送ARP请求 - 优化超时和重试
            kwargs = {
                'timeout': 4,       # 减少超时时间
                'verbose': 0,
                'retry': 1,         # 减少重试次数
                'inter': 0.05       # 更短的重试间隔
            }
            if interface:
                kwargs['iface'] = interface

            result = srp(packet, **kwargs)[0]

            # 获取本机IP和MAC
            local_ip = None
            local_mac = None

            # 方法1: 使用 scapy 获取接口 IP
            if interface and SCAPY_AVAILABLE:
                try:
                    from scapy.all import get_if_addr
                    local_ip = get_if_addr(interface)
                    if local_ip == '0.0.0.0':
                        local_ip = None
                except:
                    pass

            # 方法2: 创建 UDP socket 获取本机 IP（最可靠）
            if not local_ip:
                try:
                    import socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                except:
                    pass

            # 获取本机 MAC
            if interface and SCAPY_AVAILABLE:
                try:
                    from scapy.all import get_if_hwaddr
                    local_mac = get_if_hwaddr(interface)
                except:
                    pass

            logger.info(f"Local IP: {local_ip}, Local MAC: {local_mac}")

            # 解析结果
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc

                # 判断是否为网关
                is_gateway = (ip == gateway_ip)

                # 判断是否为本机（通过IP或MAC）
                is_self = (ip == local_ip) or (mac == local_mac)

                device = DeviceInfo(
                    ip=ip,
                    mac=mac,
                    vendor=self._lookup_vendor(mac),
                    is_gateway=is_gateway,
                    is_self=is_self
                )

                self.devices.append(device)

                # 记录设备信息
                device_type = "网关" if is_gateway else ("本机" if is_self else "设备")
                logger.info(f"Found: {ip} ({mac}) - {device_type}")

            # 添加网关（如果未在扫描结果中）
            if gateway_ip and gateway_mac:
                if not any(d.ip == gateway_ip for d in self.devices):
                    self.devices.insert(0, DeviceInfo(
                        ip=gateway_ip,
                        mac=gateway_mac,
                        vendor=self._lookup_vendor(gateway_mac),
                        is_gateway=True
                    ))
                    logger.info(f"Added gateway manually: {gateway_ip}")

            # 添加本机（如果未在扫描结果中）
            if local_ip and local_mac:
                if not any(d.ip == local_ip for d in self.devices):
                    self.devices.append(DeviceInfo(
                        ip=local_ip,
                        mac=local_mac,
                        vendor=self._lookup_vendor(local_mac),
                        is_self=True
                    ))
                    logger.info(f"Added local device manually: {local_ip}")

            logger.info(f"Found {len(self.devices)} devices")

        except Exception as e:
            logger.error(f"Scan error: {e}")

        finally:
            self.is_scanning = False

        if callback:
            callback(self.devices)

        return self.devices

    def get_devices(self) -> List[DeviceInfo]:
        """获取已扫描的设备列表"""
        return self.devices

    def get_device_by_ip(self, ip: str) -> Optional[DeviceInfo]:
        """根据IP获取设备"""
        for device in self.devices:
            if device.ip == ip:
                return device
        return None

    def stop_scan(self) -> None:
        """停止扫描"""
        self.is_scanning = False