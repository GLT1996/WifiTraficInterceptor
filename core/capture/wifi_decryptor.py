"""
WiFi流量解密器
"""
import hashlib
import binascii
import logging
import platform
import subprocess
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger('wifi_analyzer.capture')


class WiFiDecryptor:
    """WiFi流量解密器"""

    def __init__(self, ssid: str = "", password: str = ""):
        self.ssid = ssid
        self.password = password
        self.psk: Optional[str] = None
        self.wireshark_key_file: Optional[Path] = None

        if ssid and password:
            self.generate_psk()

    def generate_psk(self) -> str:
        """生成WPA-PSK密钥"""
        if not self.ssid or not self.password:
            logger.error("SSID and password required")
            return ""

        # WPA-PSK = PBKDF2(password, ssid, 4096, 32)
        psk_bytes = hashlib.pbkdf2_hmac(
            'sha1',
            self.password.encode('utf-8'),
            self.ssid.encode('utf-8'),
            4096,
            32
        )
        self.psk = binascii.hexlify(psk_bytes).decode('ascii')
        logger.info(f"Generated PSK for SSID: {self.ssid}")
        return self.psk

    def set_credentials(self, ssid: str, password: str) -> None:
        """设置WiFi凭据"""
        self.ssid = ssid
        self.password = password
        self.generate_psk()

    def configure_wireshark_decryption(self) -> bool:
        """配置Wireshark解密密钥"""
        if not self.psk:
            logger.error("PSK not generated")
            return False

        # 查找Wireshark配置目录
        wireshark_dir = self._find_wireshark_config_dir()
        if not wireshark_dir:
            logger.warning("Wireshark config directory not found")
            return False

        self.wireshark_key_file = wireshark_dir / '80211_keys'

        try:
            wireshark_dir.mkdir(parents=True, exist_ok=True)

            # Wireshark密钥格式: wpa-psk:PSK:SSID
            key_entry = f"wpa-psk:{self.psk}:{self.ssid}\n"

            # 写入密钥文件
            with open(self.wireshark_key_file, 'w') as f:
                f.write(key_entry)

            logger.info(f"Wireshark decryption configured at: {self.wireshark_key_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to configure Wireshark decryption: {e}")
            return False

    def _find_wireshark_config_dir(self) -> Optional[Path]:
        """查找Wireshark配置目录"""
        if platform.system() == 'Windows':
            # Windows: %APPDATA%\Wireshark
            appdata = Path.home() / 'AppData' / 'Roaming'
            return appdata / 'Wireshark'

        elif platform.system() == 'Darwin':  # macOS
            return Path.home() / '.config' / 'wireshark'

        else:  # Linux
            return Path.home() / '.config' / 'wireshark'

    def get_key_file_path(self) -> Optional[Path]:
        """获取密钥文件路径"""
        return self.wireshark_key_file

    def clear_decryption_config(self) -> bool:
        """清除解密配置"""
        if self.wireshark_key_file and self.wireshark_key_file.exists():
            try:
                self.wireshark_key_file.unlink()
                logger.info("Wireshark decryption configuration cleared")
                return True
            except Exception as e:
                logger.error(f"Failed to clear decryption config: {e}")
                return False
        return True

    def is_configured(self) -> bool:
        """检查是否已配置解密"""
        return self.wireshark_key_file and self.wireshark_key_file.exists()

    def get_decryption_status(self) -> Dict[str, any]:
        """获取解密状态"""
        return {
            'ssid': self.ssid,
            'has_password': bool(self.password),
            'has_psk': bool(self.psk),
            'wireshark_configured': self.is_configured(),
            'key_file': str(self.wireshark_key_file) if self.wireshark_key_file else None
        }


def verify_wifi_decryption(ssid: str, password: str) -> bool:
    """验证WiFi解密配置"""
    decryptor = WiFiDecryptor(ssid, password)
    return decryptor.configure_wireshark_decryption()


def test_decryption() -> None:
    """测试解密功能"""
    # 需要实际捕获流量来测试
    # 这里只验证密钥生成
    decryptor = WiFiDecryptor("TestSSID", "TestPassword")
    if decryptor.psk:
        logger.info(f"Test PSK generated: {decryptor.psk}")
        return True
    return False