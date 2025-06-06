/**
 * DNS 服务器主程序
 * 这是 DNS 服务器应用程序的入口点
 * 负责初始化服务器、设置信号处理器和启动事件循环
 */

#include <stdlib.h>
#include "uv.h"
#include "logging.h"
#include "socket.h"
#include "ipv4_cache.h"
#include "cname_cache.h"
#include "ipv6_cache.h"
#include "config.h"

// 全局事件循环和处理器
uv_loop_t *loop;
uv_signal_t signal_handler;
uv_timer_t timer_handler;

/**
 * SIGINT (Ctrl+C) 信号处理器
 * 清理资源并退出程序
 */
static void sigint_callback(uv_signal_t *handle, int signum)
{
    if (signum == SIGINT)
    {
        // 收到 Ctrl+C
        log_information("Exiting program");

        // 清理资源
        socket_free();
        ipv4_cache_free();
        ipv6_cache_free();
        cname_cache_free();

        exit(0);
    }
}

/**
 * 缓存清理定时器回调
 * 定期删除过期的缓存条目
 */
static void clear_callback(uv_timer_t *handler)
{
    // 每 120 秒清理一次过期缓存
    log_information("Clearing expired cache");
    ipv4_cache_clear();
    ipv6_cache_clear();
    cname_cache_clear();
}

/**
 * 主程序入口点
 * @param argc 命令行参数数量
 * @param argv 命令行参数
 * @return 程序退出码
 */
int main(int argc, char **argv)
{
    // 初始化配置
    dns_config = config_init(argc, argv);
    log_information("Program started");

    // 初始化事件循环和处理器
    loop = uv_default_loop();
    uv_udp_init(loop, &query_socket);
    uv_udp_init(loop, &bind_socket);
    uv_signal_init(loop, &signal_handler);
    uv_timer_init(loop, &timer_handler);

    // 初始化套接字并启动信号处理器
    socket_init();
    uv_signal_start(&signal_handler, sigint_callback, SIGINT);
    uv_timer_start(&timer_handler, clear_callback, 120000, 120000);

    // 初始化缓存
    ipv4_cache_init();
    ipv4_read_file(dns_config.ipv4_config_file);
    ipv6_cache_init();
    cname_cache_init();

    // 启动事件循环
    return uv_run(loop, UV_RUN_DEFAULT);
}
