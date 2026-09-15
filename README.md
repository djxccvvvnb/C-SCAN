# C-SCAN
报错是特色:)
跨平台 TCP/UDP 端口扫描器，基于 C 语言实现，兼容 Windows、Linux、macOS。

## 功能特性

- 交互式控制台菜单，双击程序直接运行，无需命令行参数
- 6种扫描模式：TCP Connect、SYN半开、FIN、UDP、XMAS、默认模式
- 跨平台支持：Windows (Winsock2) / Linux & macOS (POSIX socket)
- 自定义或内置端口列表扫描

## 编译方法

### Windows (MinGW-w64 / MSVC)

```bash
# MinGW-w64 (推荐)
gcc main.c -lws2_32 -o C-SCAN.exe

# 或 MSVC
cl main.c ws2_32.lib
```

### Linux / macOS

```bash
gcc main.c -o C-SCAN
```

## 使用说明

1. 双击程序运行（或在终端执行 `./C-SCAN`）
2. 查看版本更新公告后按任意键继续
3. 输入目标IP或域名
4. 选择扫描模式（1-6）
5. 选择端口列表（内置常用端口 / 自定义端口范围）
6. 等待扫描完成

## 扫描模式说明

| 模式 | 名称 | 特点 |
|------|------|------|
| 1 | TCP Connect | 兼容性最强，速度慢，可准确判断端口状态 |
| 2 | SYN半开 | 性能最好，速度快，需要管理员/Root权限 |
| 3 | FIN扫描 | 隐蔽性较好，部分防火墙可绕过，结果无法确定 |
| 4 | UDP扫描 | 探测UDP端口，速度很慢，容易丢包 |
| 5 | XMAS扫描 | 隐蔽扫描，结果无法确定 |
| 6 | 默认模式 | 自动选用TCP Connect扫描 |

## 免责声明

本项目仅用于本地靶场安全学习及授权安全测试，严禁未经授权对公网目标进行扫描。使用者需自行承担所有法律责任，作者不对任何滥用行为负责。
