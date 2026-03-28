"""
全局配置管理
"""
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List

CONFIG_FILE = Path(__file__).parent.parent / 'config.json'


@dataclass
class CaptureConfig:
    """捕获配置"""
    interface: str = ""
    buffer_size: int = 1024
    snap_length: int = 65535
    promiscuous: bool = True
    filter_expression: str = ""


@dataclass
class WiFiConfig:
    """WiFi解密配置"""
    ssid: str = ""
    password: str = ""
    decryption_enabled: bool = False


@dataclass
class DisplayConfig:
    """显示配置"""
    max_packets_display: int = 10000
    auto_scroll: bool = True
    color_by_protocol: bool = True
    time_format: str = "relative"  # relative, absolute, utc


@dataclass
class Settings:
    """全局设置"""
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    wifi: WiFiConfig = field(default_factory=WiFiConfig)
    display: DisplayConfig = field(default_factory=DisplayConfig)

    @classmethod
    def load(cls) -> 'Settings':
        """从文件加载配置"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return cls(
                    capture=CaptureConfig(**data.get('capture', {})),
                    wifi=WiFiConfig(**data.get('wifi', {})),
                    display=DisplayConfig(**data.get('display', {}))
                )
            except Exception:
                pass
        return cls()

    def save(self) -> None:
        """保存配置到文件"""
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)

    def reset(self) -> None:
        """重置为默认配置"""
        self.capture = CaptureConfig()
        self.wifi = WiFiConfig()
        self.display = DisplayConfig()