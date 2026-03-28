"""
流量转发控制器 - 控制IP转发功能
"""
import platform
import logging
import subprocess
from typing import Optional

logger = logging.getLogger('wifi_analyzer.mitm')


class TrafficForwarder:
    """流量转发控制器"""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if TrafficForwarder._initialized:
            return
        TrafficForwarder._initialized = True

        self._is_forwarding = False
        self._original_state: Optional[bool] = None

    @property
    def is_forwarding(self) -> bool:
        """是否正在转发"""
        return self._is_forwarding

    def enable(self) -> bool:
        """
        开启IP转发

        :return: 是否成功
        """
        if self._is_forwarding:
            logger.warning("IP forwarding already enabled")
            return True

        try:
            if platform.system() == 'Windows':
                success = self._enable_windows()
            else:
                success = self._enable_linux()

            if success:
                self._is_forwarding = True
                logger.info("IP forwarding enabled")

            return success

        except Exception as e:
            logger.error(f"Failed to enable IP forwarding: {e}")
            return False

    def disable(self) -> bool:
        """
        关闭IP转发

        :return: 是否成功
        """
        if not self._is_forwarding:
            return True

        try:
            if platform.system() == 'Windows':
                success = self._disable_windows()
            else:
                success = self._disable_linux()

            if success:
                self._is_forwarding = False
                logger.info("IP forwarding disabled")

            return success

        except Exception as e:
            logger.error(f"Failed to disable IP forwarding: {e}")
            return False

    def _enable_windows(self) -> bool:
        """Windows开启IP转发"""
        try:
            import winreg
            import subprocess

            # 打开注册表键
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                0,
                winreg.KEY_ALL_ACCESS
            )

            # 保存原始值
            try:
                self._original_state = bool(winreg.QueryValueEx(key, "IPEnableRouter")[0])
            except:
                self._original_state = False

            # 设置新值
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)

            # 验证设置
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                0,
                winreg.KEY_READ
            )
            value = winreg.QueryValueEx(key, "IPEnableRouter")[0]
            winreg.CloseKey(key)

            if value != 1:
                logger.error("Failed to verify IP forwarding setting")
                return False

            # 尝试刷新网络配置（让设置立即生效）
            try:
                subprocess.run(
                    ['netsh', 'interface', 'ipv4', 'set', 'interface', 'forwarding=enabled'],
                    capture_output=True, timeout=5
                )
            except:
                pass

            logger.info(f"Windows IP forwarding enabled (was: {self._original_state})")
            logger.info("Note: If traffic doesn't flow, try restarting the Remote Access service:")
            logger.info("  net stop RemoteAccess && net start RemoteAccess")

            return True

        except PermissionError:
            logger.error("Permission denied - need administrator privileges")
            return False
        except Exception as e:
            logger.error(f"Windows IP forwarding error: {e}")
            return False

    def _disable_windows(self) -> bool:
        """Windows关闭IP转发"""
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                0,
                winreg.KEY_ALL_ACCESS
            )

            # 恢复原始值
            original = self._original_state if self._original_state is not None else 0
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, int(original))
            winreg.CloseKey(key)

            logger.info(f"Windows IP forwarding disabled (restored to: {original})")
            return True

        except Exception as e:
            logger.error(f"Failed to disable Windows IP forwarding: {e}")
            return False

    def _enable_linux(self) -> bool:
        """Linux开启IP转发"""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            return True
        except PermissionError:
            logger.error("Permission denied - need root privileges")
            return False
        except Exception as e:
            logger.error(f"Linux IP forwarding error: {e}")
            return False

    def _disable_linux(self) -> bool:
        """Linux关闭IP转发"""
        try:
            original = 0 if self._original_state is None else int(self._original_state)
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write(str(original))
            return True
        except Exception as e:
            logger.error(f"Failed to disable Linux IP forwarding: {e}")
            return False

    def check_status(self) -> bool:
        """
        检查IP转发状态

        :return: 是否已开启
        """
        try:
            if platform.system() == 'Windows':
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    0,
                    winreg.KEY_READ
                )
                value = winreg.QueryValueEx(key, "IPEnableRouter")[0]
                winreg.CloseKey(key)
                return bool(value)
            else:
                with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                    return f.read().strip() == '1'
        except:
            return False

    def __del__(self):
        """析构时恢复设置"""
        if self._is_forwarding:
            self.disable()