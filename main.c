#define _WIN32_WINNT 0x0600
/*
 * C-SCAN - Windows TCP端口扫描器
 * 使用Winsock API + 非阻塞socket + select实现超时控制
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define SCAN_TIMEOUT_MS 2000
#define MAX_PORTS 65535
#define BUF_SIZE 4096
#define DNS_CDN_WARN "注意：此IP是域名解析得到的原始地址，有可能是CDN节点，不一定是目标源站。"
#define SAFE_IP_WARN "警告：目标IP为内网私有地址段，请确保您拥有扫描权限。"

static const int DEFAULT_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 514, 587, 631, 993, 995,
    1433, 1434, 1521, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9090, 27017
};
static const int DEFAULT_PORTS_COUNT = sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]);

typedef struct {
    int *ports;
    int count;
} PortList;

/* ---- 工具函数 ---- */

static void print_banner(void) {
    printf("============================================================\n");
    printf("           C-SCAN  TCP端口扫描器 (Windows)\n");
    printf("============================================================\n\n");
    printf("安全提示：本程序仅允许扫描自己拥有权限的设备。\n");
    printf("         未经许可扫描他人网络属于违法行为，请合法使用。\n\n");
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

static void print_ip(const struct sockaddr_in *sin) {
    printf("%s", inet_ntoa(sin->sin_addr));
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

    if (choice == 1) {
        pl->ports = (int *)malloc(sizeof(int) * DEFAULT_PORTS_COUNT);
        if (!pl->ports) { fprintf(stderr, "内存分配失败\n"); return -1; }
        memcpy(pl->ports, DEFAULT_PORTS, sizeof(DEFAULT_PORTS));
        pl->count = DEFAULT_PORTS_COUNT;
        printf("已选择%d个内置端口。\n", pl->count);
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
        printf("已选择%d个端口。\n", pl->count);
    } else {
        return -1;
    }
    return 0;
}

/* ---- 核心扫描逻辑 ---- */

/* 扫描单个端口：每端口新建socket，非阻塞connect + select等待，SO_ERROR判定结果 */
static void scan_one(const char *target_ip, int port, int *open_count) {
    /* 每端口独立socket，避免复用旧连接状态 */
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "创建socket失败: %ld\n", WSAGetLastError());
        return;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(target_ip);
    serv_addr.sin_port        = htons((u_short)port);

    /* 设为非阻塞模式 */
    unsigned long on = 1;
    ioctlsocket(sock, FIONBIO, &on);

    /* 非阻塞connect发起连接 */
    int ret = connect(sock, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret == SOCKET_ERROR) {
        /* WSAEWOULDBLOCK(10035)是预期结果：连接正在后台建立，不能当成失败处理 */
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(sock);
            return;
        }
    }

    /* 用select等待socket可写：连接成功或失败时select都会返回 */
    fd_set wset;
    struct timeval tv;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    tv.tv_sec  = SCAN_TIMEOUT_MS / 1000;
    tv.tv_usec = (SCAN_TIMEOUT_MS % 1000) * 1000;

    int sel = select((int)sock + 1, NULL, &wset, NULL, &tv);
    if (sel <= 0) {
        /* sel==0超时，sel<0出错，均视为closed */
        closesocket(sock);
        return;
    }

    /* 通过getsockopt读取异步连接错误码 */
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);

    if (err == 0) {
        /* 无错误，连接建立成功，端口开放 */
        printf("%-10d %-10s\n", port, "open");
        (*open_count)++;
    }

    closesocket(sock);
}

static void run_scan(const char *target_ip, PortList *pl) {
    int open_count = 0;
    printf("\n开始扫描 %s ...\n", target_ip);
    printf("%-10s %-10s\n", "PORT", "STATE");

    clock_t start = clock();
    for (int i = 0; i < pl->count; i++) {
        if ((i + 1) % 100 == 0 || i == pl->count - 1)
            fprintf(stderr, "\r  扫描进度: %d/%d", i + 1, pl->count);
        scan_one(target_ip, pl->ports[i], &open_count);
    }
    fprintf(stderr, "\n");

    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    printf("\n--- 扫描完成 (%.2fs) ---", elapsed);
    printf(" 开放端口数: %d\n", open_count);
}

/* ---- 主流程 ---- */

static int get_target(char *buf, size_t len) {
    printf("\n请输入目标IP或域名: ");
    if (!fgets(buf, (int)len, stdin)) return -1;
    buf[strcspn(buf, "\r\n")] = '\0';
    if (buf[0] == '\0') return -1;
    return 0;
}

/*
 * 解析目标：
 *  - 先尝试getaddrinfo，成功则为域名，输出解析IP
 *  - 失败则当作IP直输，校验格式后返回
 *  is_domain置1表示输入是域名
 */
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
        printf("域名解析结果: %s -> %s\n", input, out_ip);
        freeaddrinfo(res);
        *is_domain = 1;
        return 0;
    }

    /* getaddrinfo失败，当作IP处理 */
    if (!is_valid_ipv4(input)) {
        fprintf(stderr, "错误: 无效的目标地址 '%s'\n", input);
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

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Winsock初始化失败\n");
        return 1;
    }

    char target[256] = {0};
    char resolved_ip[INET_ADDRSTRLEN] = {0};
    int  is_domain = 0;

    while (1) {
        if (get_target(target, sizeof(target)) != 0) {
            printf("\n无输入，程序退出。\n");
            break;
        }

        int ret = resolve_and_validate(target, resolved_ip, &is_domain);
        if (ret != 0) continue;

        uint32_t addr = ip_to_uint32(resolved_ip);
        if (is_private_ip(addr)) {
            printf("%s\n", SAFE_IP_WARN);
        }

        if (is_domain) {
            printf("%s\n", DNS_CDN_WARN);
            printf("确认扫描 %s ? (y/任意): ", resolved_ip);
            char confirm[16] = {0};
            if (fgets(confirm, sizeof(confirm), stdin)) {
                if (confirm[0] != 'y' && confirm[0] != 'Y') {
                    printf("已取消扫描。\n");
                    continue;
                }
            }
        }

        PortList pl = {NULL, 0};
        if (choose_ports(&pl) != 0) {
            printf("端口选择失败，程序退出。\n");
            break;
        }

        if (pl.count <= 0) {
            free_port_list(&pl);
            continue;
        }

        run_scan(resolved_ip, &pl);
        free_port_list(&pl);

        printf("\n");
    }

    WSACleanup();
    return 0;
}
