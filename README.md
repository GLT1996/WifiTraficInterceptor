# WiFi Traffic Interceptor

WiFi流量拦截分析软件 - 能够捕获局域网内所有连接WiFi设备的网络流量。

## 功能特性

- **网络设备扫描**: 扫描局域网内所有活跃设备，显示IP、MAC地址和厂商信息
- **ARP欺骗(MITM)**: 通过ARP欺骗拦截目标设备的网络流量
- **实时流量捕获**: 捕获并解析TCP、UDP、HTTP、DNS等协议数据包
- **流量分析**: 查看数据包详情、十六进制内容、HTTP明文内容
- **BPF过滤器**: 支持自定义BPF过滤表达式，快速筛选特定流量

## 系统要求

- Windows 10/11
- Python 3.10+ (仅源码运行时需要)
- Npcap (必须安装，用于数据包捕获)

## 安装

### 1. 安装 Npcap

从 https://npcap.com/ 下载并安装Npcap，安装时选择：
- "Install Npcap in WinPcap API-compatible Mode"

### 2. 安装依赖 (源码运行)

```bash
pip install PyQt6 scapy matplotlib pyqtgraph psutil
```

## 运行

### 源码运行

```bash
# 以管理员权限运行
python main.py
```

### 打包为exe可执行文件

```bash
python -m PyInstaller --onefile --windowed --name "WiFiTrafficInterceptor" main.py
```

打包后exe文件位于 `dist/WiFiTrafficInterceptor.exe`

**注意**: exe文件运行时仍需管理员权限，且系统需已安装Npcap。

## 使用说明

1. **选择网卡**: 在界面顶部选择连接WiFi的网卡
2. **扫描网络**: 点击"Scan Network"扫描局域网设备
3. **选择目标**: 在扫描结果中选择要拦截的设备
4. **开始拦截**: 点击"Start Intercept"开始ARP欺骗和流量捕获
5. **查看流量**: 在数据包列表中查看捕获的流量
6. **停止拦截**: 点击"Stop Intercept"停止拦截并恢复网络

## 工作原理

程序使用ARP欺骗技术实现流量拦截：

```
目标设备 <──ARP欺骗──> 本机(攻击者) <──流量转发──> 网关(路由器)
```

1. 向目标设备发送伪造ARP响应，声称本机是网关
2. 向网关发送伪造ARP响应，声称本机是目标设备
3. 目标设备的流量经过本机转发，本机可捕获所有数据包
4. 开启IP转发，确保流量正常传递

## 法律声明

**重要**: 此工具仅限以下合法用途：
- 个人网络安全学习和研究
- 自己网络的安全测试
- 获得明确授权的安全测试

**禁止用于**：
- 未授权的网络攻击
- 窃取他人敏感信息
- 干扰网络正常运行

## 项目结构

```
wifiData/
├── main.py                    # 主程序入口
├── core/
│   ├── mitm/                  # 中间人攻击模块
│   │   ├── network_scanner.py # 网络扫描器
│   │   ├── arp_spoofer.py     # ARP欺骗器
│   │   ├── traffic_forwarder.py # 流量转发控制
│   │   └── mitm_manager.py    # MITM管理器
│   ├── capture/               # 数据包捕获
│   ├── parser/                # 协议解析
│   └── analyzer/              # 流量分析
├── gui/
│   ├── main_window.py         # 主窗口
│   ├── widgets/               # UI组件
│   └── dialogs/               # 对话框
└── dist/
    └── WiFiTrafficInterceptor.exe # 打包后的exe
```