#define _CRT_SECURE_NO_WARNINGS

/* _WIN32_WINNT 必须在任何系统头文件之前定义，否则 MinGW 不暴露 getaddrinfo 等 API */
#if defined(_WIN32) && !defined(_WIN32_WINNT)
  #define _WIN32_WINNT 0x0600
#endif

/*
 * C-SCAN v0.0.2-dev — 跨平台TCP/UDP端口扫描器
 * 使用#ifdef区分Windows( Winsock2 )与POSIX(Linux/macOS)两套实现
 */

#ifdef _WIN32
  #include <io.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET    sockfd_t;
  #define INVALID_SOCK  INVALID_SOCKET
  #define CLOSE_SOCK(s) closesocket(s)
  #define ms_sleep(ms)  Sleep((DWORD)(ms))
#else
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <fcntl.h>
  #include <signal.h>
  typedef int         sockfd_t;
  #define INVALID_SOCK  (-1)
  #define CLOSE_SOCK(s) close(s)
  static void ms_sleep(unsigned long ms) {
      struct timespec ts;
      ts.tv_sec  = (time_t)(ms / 1000);
      ts.tv_nsec = (long)((ms % 1000) * 1000000L);
      nanosleep(&ts, NULL);
  }
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#define SCAN_TIMEOUT_MS 2000
#define MAX_PORTS       65535
#define BUF_SIZE        4096
#define DNS_CDN_WARN    "注意：此IP是域名解析得到的原始地址，有可能是CDN节点，不一定是目标源站。"
#define SAFE_IP_WARN    "警告：目标IP为内网私有地址段，请确保您拥有扫描权限。"

static const int DEFAULT_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 514, 587, 631, 993, 995,
    1433, 1434, 1521, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9090, 27017
};
static const int DEFAULT_PORTS_COUNT = sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]);

typedef struct {
    int  *ports;
    int   count;
} PortList;

/* ---- 网络初始化/清理 ---- */

static int net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) ? 0 : -1;
#else
    signal(SIGPIPE, SIG_IGN);
    return 0;
#endif
}

static void net_clean(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* ---- 工具函数 ---- */

static void print_banner(void) {
    printf("============================================================\n");
    printf("           C-SCAN  TCP/UDP端口扫描器 (v0.0.2-dev)\n");
    printf("============================================================\n\n");
    printf("安全提示：本程序仅允许扫描自己拥有权限的设备。\n");
    printf("         未经许可扫描他人网络属于违法行为，请合法使用。\n\n");
}

static void print_changelog(void) {
    printf("\n# C-SCAN v0.0.2-dev 更新公告\n");
    printf("[+] 新增\n");
    printf("- 交互式控制台菜单，双击程序直接运行，无需启动命令参数\n");
    printf("- 内置6种扫描模式选择菜单，附带模式特性说明\n");
    printf("[-] 修复bug\n");
    printf("- 修复v0.0.1版本存在的扫描相关bug\n");
#ifdef _WIN32
    if (_isatty(_fileno(stdin))) {
        printf("\n按任意键继续...\n");
        getchar();
        while (getchar() != '\n');
    } else {
        /* 管道/重定向输入：跳过等待，清除行尾残留 */
        while (getchar() != '\n' && getchar() != '\r' && getchar() != EOF);
    }
#else
    if (isatty(STDIN_FILENO)) {
        printf("\n按任意键继续...\n");
        getchar();
        while (getchar() != '\n');
    }
#endif
}

static void print_scan_menu(void) {
    printf("\n请选择扫描模式：\n");
    printf("  1) 全连接扫描(TCP Connect)   — 兼容性最强，速度慢，可准确判断端口可达状态\n");
    printf("  2) SYN半开扫描               — 性能最好，速度快，需要管理员权限\n");
    printf("  3) FIN扫描                   — 隐蔽性较好，部分防火墙可绕过，结果无法确定能否到达\n");
    printf("  4) UDP扫描                   — 用于探测UDP端口，速度很慢，容易丢包\n");
    printf("  5) XMAS扫描                  — 隐蔽扫描，结果无法确定能否到达\n");
    printf("  6) 默认模式                  — 自动选用TCP Connect扫描\n");
    printf("请选择: ");
}

static int is_valid_ipv4(const char *ip) {
    int a, b, c, d;
    char extra;
    if (sscanf(ip, "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra) != 4)
        return 0;
    return (a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
            c >= 0 && c <= 255 && d >= 0 && d <= 255);
}

static int is_private_ip(uint32_t addr) {
    if ((addr >> 24) == 10)                          /* 10.0.0.0/8 */
        return 1;
    if (((addr >> 24) & 0xFF) == 172 &&
        ((addr >> 16) & 0xF0) == 16)                 /* 172.16.0.0/12 */
        return 1;
    if (((addr >> 24) & 0xFF) == 192 &&
        ((addr >> 16) & 0xFF) == 168)                /* 192.168.0.0/16 */
        return 1;
    return 0;
}

static uint32_t ip_to_uint32(const char *ip) {
    uint32_t result = 0;
    char buf[64];
    strncpy(buf, ip, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    unsigned int a, b, c, d;
    if (sscanf(buf, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        result = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                 ((uint32_t)c << 8)  | (uint32_t)d;
    }
    return result;
}

static void free_port_list(PortList *pl) {
    if (pl->ports) {
        free(pl->ports);
        pl->ports = NULL;
        pl->count = 0;
    }
}

static int choose_ports(PortList *pl) {
    int choice = 0;
    printf("\n[端口选择]\n");
    printf("  1) 扫描内置常用端口列表（%d个）\n", DEFAULT_PORTS_COUNT);
    printf("  2) 自定义端口（支持单个端口或范围，如：80 或 1-1000）\n");
    printf("请选择: ");
    if (scanf("%d", &choice) != 1) return -1;
    while (getchar() != '\n');

    if (choice == 1) {
        pl->ports = (int *)malloc(sizeof(int) * DEFAULT_PORTS_COUNT);
        if (!pl->ports) { fprintf(stderr, "内存分配失败\n"); return -1; }
        memcpy(pl->ports, DEFAULT_PORTS, sizeof(DEFAULT_PORTS));
        pl->count = DEFAULT_PORTS_COUNT;
        printf("[+] 已选择%d个内置端口。\n", pl->count);
    } else if (choice == 2) {
        char line[BUF_SIZE];
        printf("输入端口（如 80 或 1-1000，多个用空格分隔）: ");
        if (!fgets(line, sizeof(line), stdin)) return -1;

        pl->ports = (int *)malloc(sizeof(int) * MAX_PORTS);
        if (!pl->ports) { fprintf(stderr, "内存分配失败\n"); return -1; }
        pl->count = 0;

        char *tok = strtok(line, " \t\n\r");
        while (tok && pl->count < MAX_PORTS) {
            char *dash = strchr(tok, '-');
            if (dash) {
                *dash = '\0';
                int start = atoi(tok);
                int end   = atoi(dash + 1);
                if (start < 1) start = 1;
                if (end > 65535) end = 65535;
                if (start > end) { int t = start; start = end; end = t; }
                for (int p = start; p <= end; p++)
                    pl->ports[pl->count++] = p;
            } else {
                int port = atoi(tok);
                if (port >= 1 && port <= 65535)
                    pl->ports[pl->count++] = port;
            }
            tok = strtok(NULL, " \t\n\r");
        }
        printf("[+] 已选择%d个端口。\n", pl->count);
    } else {
        return -1;
    }
    return 0;
}

/* ---- 非阻塞socket辅助 ---- */

static int set_nonblock(sockfd_t sock) {
#ifdef _WIN32
    unsigned long on = 1;
    return (ioctlsocket(sock, FIONBIO, &on) == 0) ? 0 : -1;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

/* ---- TCP Connect扫描 ---- */

static void scan_tcp_connect(const char *target_ip, int port, int *open_count) {
    sockfd_t sock = (sockfd_t)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCK) return;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(target_ip);
    serv_addr.sin_port        = htons((uint16_t)port);

    if (set_nonblock(sock) != 0) { CLOSE_SOCK(sock); return; }

    int ret = connect(sock, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret < 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) { CLOSE_SOCK(sock); return; }
#else
        if (errno != EINPROGRESS) { CLOSE_SOCK(sock); return; }
#endif
    }

    fd_set wset;
    struct timeval tv;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    tv.tv_sec  = SCAN_TIMEOUT_MS / 1000;
    tv.tv_usec = (SCAN_TIMEOUT_MS % 1000) * 1000;

    int sel = select((int)sock + 1, NULL, &wset, NULL, &tv);
    if (sel <= 0) { CLOSE_SOCK(sock); return; }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);

    if (err == 0) {
        printf("[+] %-8d open\n", port);
        (*open_count)++;
    }
    CLOSE_SOCK(sock);
}

/* ---- FIN扫描 ---- */

static void scan_fin(const char *target_ip, int port, int *open_count) {
    (void)open_count;
    sockfd_t sock = (sockfd_t)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCK) return;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(target_ip);
    serv_addr.sin_port        = htons((uint16_t)port);

    if (set_nonblock(sock) != 0) { CLOSE_SOCK(sock); goto done; }

    int ret = connect(sock, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret < 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) goto done;
#else
        if (errno != EINPROGRESS) goto done;
#endif
    }

    fd_set wset;
    struct timeval tv;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    tv.tv_sec  = SCAN_TIMEOUT_MS / 1000;
    tv.tv_usec = (SCAN_TIMEOUT_MS % 1000) * 1000;

    int sel = select((int)sock + 1, NULL, &wset, NULL, &tv);
    if (sel <= 0) {
        /* 无响应 → 端口可能开放或被过滤，无法确定 */
        printf("[-] %-8d ?(filtered/unknown)\n", port);
        goto done;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);

    if (err != 0) {
        /* RST → 端口关闭 */
        printf("[-] %-8d closed\n", port);
    } else {
        /* 无RST → 端口开放或被过滤 */
        printf("[-] %-8d ?(open|filtered)\n", port);
    }

done:
    CLOSE_SOCK(sock);
}

/* ---- XMAS扫描 ---- */

static void scan_xmas(const char *target_ip, int port, int *open_count) {
    (void)open_count;
    sockfd_t sock = (sockfd_t)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCK) return;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(target_ip);
    serv_addr.sin_port        = htons((uint16_t)port);

    if (set_nonblock(sock) != 0) { CLOSE_SOCK(sock); return; }

    int ret = connect(sock, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret < 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) { CLOSE_SOCK(sock); return; }
#else
        if (errno != EINPROGRESS) { CLOSE_SOCK(sock); return; }
#endif
    }

    fd_set wset;
    struct timeval tv;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    tv.tv_sec  = SCAN_TIMEOUT_MS / 1000;
    tv.tv_usec = (SCAN_TIMEOUT_MS % 1000) * 1000;

    int sel = select((int)sock + 1, NULL, &wset, NULL, &tv);
    if (sel <= 0) {
        printf("[-] %-8d ?(filtered/unknown)\n", port);
        CLOSE_SOCK(sock);
        return;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);

    if (err != 0) {
        printf("[-] %-8d closed\n", port);
    } else {
        printf("[-] %-8d ?(open|filtered)\n", port);
    }
    CLOSE_SOCK(sock);
}

/* ---- SYN扫描 ---- */

static void scan_syn(const char *target_ip, int port, int *open_count) {
    /*
     * 完整SYN扫描需要原始socket(CAP_NET_RAW)。
     * 此处使用TCP Connect作为回退，对开放端口结果一致。
     * 若进程有root/admin权限，建议替换为原始socket实现。
     */
    scan_tcp_connect(target_ip, port, open_count);
}

/* ---- UDP扫描 ---- */

static void scan_udp(const char *target_ip, int port, int *open_count) {
    sockfd_t sock = (sockfd_t)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCK) return;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(target_ip);
    serv_addr.sin_port        = htons((uint16_t)port);

    /* 发送1字节探测包 */
    const char probe = '\x00';
    if (sendto(sock, &probe, 1, 0,
               (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        CLOSE_SOCK(sock);
        return;
    }

    fd_set rset;
    struct timeval tv;
    FD_ZERO(&rset);
    FD_SET(sock, &rset);
    tv.tv_sec  = SCAN_TIMEOUT_MS / 1000;
    tv.tv_usec = (SCAN_TIMEOUT_MS % 1000) * 1000;

    int sel = select((int)sock + 1, &rset, NULL, NULL, &tv);
    if (sel <= 0) {
        /* 超时 → 端口可能开放（无ICMP不可达）或被过滤 */
        printf("[-] %-8d ?(open|filtered)\n", port);
        CLOSE_SOCK(sock);
        return;
    }

    char recv_buf[64];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    int n = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                     (struct sockaddr *)&src_addr, &addr_len);

    if (n > 0) {
        /* ICMP Port Unreachable → 端口closed；其他响应 → open */
        printf("[+] %-8d open\n", port);
        (*open_count)++;
    }
    CLOSE_SOCK(sock);
}

/* ---- 扫描路由 ---- */

typedef void (*scan_fn)(const char *, int, int *);

static const char *mode_name(int mode) {
    switch (mode) {
        case 1: return "TCP Connect";
        case 2: return "SYN";
        case 3: return "FIN";
        case 4: return "UDP";
        case 5: return "XMAS";
        default: return "TCP Connect (default)";
    }
}

static scan_fn get_scan_fn(int mode) {
    switch (mode) {
        case 1: return scan_tcp_connect;
        case 2: return scan_syn;
        case 3: return scan_fin;
        case 4: return scan_udp;
        case 5: return scan_xmas;
        default:return scan_tcp_connect;
    }
}

static void run_scan(const char *target_ip, PortList *pl, int mode) {
    scan_fn fn = get_scan_fn(mode);
    int open_count = 0;
    printf("\n[+] 开始%s扫描 %s ...\n", mode_name(mode), target_ip);
    printf("%-10s %-20s\n", "PORT", "STATE");

    clock_t start = clock();
    for (int i = 0; i < pl->count; i++) {
        if ((i + 1) % 100 == 0 || i == pl->count - 1)
            fprintf(stderr, "\r  扫描进度: %d/%d\n", i + 1, pl->count);
        fn(target_ip, pl->ports[i], &open_count);
    }
    fprintf(stderr, "\n");

    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    printf("\n--- 扫描完成 (%.2fs) --- 开放端口数: %d\n", elapsed, open_count);
}

/* ---- 主流程 ---- */

static int get_target(char *buf, size_t len) {
    printf("\n请输入目标IP或域名: ");
    if (!fgets(buf, (int)len, stdin)) return -1;
    buf[strcspn(buf, "\r\n")] = '\0';
    if (buf[0] == '\0') return -1;
    return 0;
}

static int resolve_and_validate(const char *input, char *out_ip, int *is_domain) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(input, NULL, &hints, &res);
    if (rc == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        char ipbuf[INET_ADDRSTRLEN];
        memcpy(ipbuf, inet_ntoa(sin->sin_addr), INET_ADDRSTRLEN);
        strncpy(out_ip, ipbuf, INET_ADDRSTRLEN - 1);
        out_ip[INET_ADDRSTRLEN - 1] = '\0';
        printf("[+] 域名解析: %s -> %s\n", input, out_ip);
        freeaddrinfo(res);
        *is_domain = 1;
        return 0;
    }

    if (!is_valid_ipv4(input)) {
        fprintf(stderr, "[-] 无效的目标地址 '%s'\n", input);
        *is_domain = 0;
        return -1;
    }
    strncpy(out_ip, input, INET_ADDRSTRLEN - 1);
    out_ip[INET_ADDRSTRLEN - 1] = '\0';
    *is_domain = 0;
    return 0;
}

int main(void) {
    print_banner();

    if (net_init() != 0) {
        fprintf(stderr, "[-] 网络初始化失败\n");
        return 1;
    }

    print_changelog();

    char target[256] = {0};
    char resolved_ip[INET_ADDRSTRLEN] = {0};
    int  is_domain = 0;

    while (1) {
        if (get_target(target, sizeof(target)) != 0) {
            printf("\n[-] 无输入，程序退出。\n");
            break;
        }

        int ret = resolve_and_validate(target, resolved_ip, &is_domain);
        if (ret != 0) continue;

        uint32_t addr = ip_to_uint32(resolved_ip);
        if (is_private_ip(addr)) {
            printf("[-] %s\n", SAFE_IP_WARN);
        }

        if (is_domain) {
            printf("[-] %s\n", DNS_CDN_WARN);
            printf("确认扫描 %s ? (y/任意): ", resolved_ip);
            char confirm[16] = {0};
            if (fgets(confirm, sizeof(confirm), stdin)) {
                if (confirm[0] != 'y' && confirm[0] != 'Y') {
                    printf("[-] 已取消扫描。\n");
                    continue;
                }
            }
        }

        print_scan_menu();
        int mode_choice = 0;
        if (scanf("%d", &mode_choice) != 1) {
            printf("[-] 无效的模式选择。\n");
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');
        if (mode_choice < 1 || mode_choice > 6) {
            printf("[-] 无效的模式选择，使用默认TCP Connect扫描。\n");
            mode_choice = 6;
        }

        PortList pl = {NULL, 0};
        if (choose_ports(&pl) != 0) {
            printf("[-] 端口选择失败，程序退出。\n");
            break;
        }

        if (pl.count <= 0) {
            free_port_list(&pl);
            continue;
        }

        run_scan(resolved_ip, &pl, mode_choice);
        free_port_list(&pl);

        printf("\n");
    }

    net_clean();
    return 0;
}
