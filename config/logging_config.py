"""
日志配置
"""
import logging
import sys
from pathlib import Path
from colorlog import ColoredFormatter

LOG_DIR = Path(__file__).parent.parent / 'logs'
LOG_DIR.mkdir(exist_ok=True)


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """设置日志系统"""
    # 创建根日志器
    logger = logging.getLogger('wifi_analyzer')
    logger.setLevel(level)

    # 防止重复添加handler
    if logger.handlers:
        return logger

    # 控制台输出（彩色）
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = ColoredFormatter(
        '%(log_color)s%(asctime)s %(levelname)-8s%(reset)s %(blue)s%(name)s%(reset)s: %(message)s',
        datefmt='%H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 文件输出
    file_handler = logging.FileHandler(
        LOG_DIR / 'wifi_analyzer.log',
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger