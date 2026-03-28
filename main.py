"""
WiFi数据包分析软件 - 主入口
"""
import sys
import ctypes
import platform
import logging

# 检查管理员权限
def is_admin() -> bool:
    """检查是否有管理员权限"""
    if platform.system() == 'Windows':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.getuid() == 0


def main() -> None:
    """主函数"""
    # 设置日志
    from config.logging_config import setup_logging
    logger = setup_logging()

    # 检查权限
    if not is_admin():
        logger.warning("Administrator privileges recommended for packet capture")
        print("\n[WARNING] Running without administrator privileges.")
        print("Packet capture functionality will be limited.")
        # 不再退出，允许继续运行
        # sys.exit(1)

    # 导入PyQt6
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
    except ImportError:
        logger.error("PyQt6 not installed")
        print("[ERROR] PyQt6 is not installed. Please run: pip install PyQt6")
        sys.exit(1)

    # 检查Scapy
    try:
        from scapy.all import sniff, conf
        logger.info("Scapy loaded successfully")
    except ImportError:
        logger.warning("Scapy not installed - capture functionality limited")
        print("[WARNING] Scapy is not installed. Packet capture may not work.")
        print("Please run: pip install scapy")

    # 加载配置
    from config.settings import Settings
    settings = Settings.load()
    logger.info("Configuration loaded")

    # 创建应用
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    # 加载样式表
    try:
        with open('gui/resources/styles.qss', 'r', encoding='utf-8') as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        logger.warning("Stylesheet not found, using default style")

    # 创建主窗口
    from gui.main_window import MainWindow
    window = MainWindow(settings)
    window.show()

    logger.info("Application started")

    # 运行应用
    sys.exit(app.exec())


if __name__ == '__main__':
    import os
    # 添加项目根目录到路径
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)

    main()