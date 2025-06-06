#include <stdlib.h>
#include "uv.h"
#include "logging.h"
#include "socket.h"
#include "ipv4_cache.h"
#include "cname_cache.h"
#include "ipv6_cache.h"
#include "config.h"

uv_loop_t *loop;
uv_signal_t signal_handler;
uv_timer_t timer_handler;

static void sigint_callback(uv_signal_t *handle, int signum)
{
    if (signum == SIGINT)
    {
        // Received control-c
        log_information("Exiting program");

        socket_free();
        ipv4_cache_free();
        ipv6_cache_free();
        cname_cache_free();

        exit(0);
    }
}

static void clear_callback(uv_timer_t *handler)
{
    // Clear expired cache every 120 seconds
    log_information("Clearing expired cache");
    ipv4_cache_clear();
    ipv6_cache_clear();
    cname_cache_clear();
}

int main(int argc, char **argv)
{
    dns_config = config_init(argc, argv);
    log_information("Program started");

    loop = uv_default_loop();
    uv_udp_init(loop, &query_socket);
    uv_udp_init(loop, &bind_socket);
    uv_signal_init(loop, &signal_handler);
    uv_timer_init(loop, &timer_handler);

    socket_init();
    uv_signal_start(&signal_handler, sigint_callback, SIGINT);
    uv_timer_start(&timer_handler, clear_callback, 120000, 120000);

    ipv4_cache_init();
    ipv4_read_file(dns_config.ipv4_config_file);
    ipv6_cache_init();
    cname_cache_init();

    return uv_run(loop, UV_RUN_DEFAULT);
}
