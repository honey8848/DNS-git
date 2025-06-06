//
// Created by ricardo on 23-6-26.
//
#include <stddef.h>
#include <stdlib.h>
#include "config.h"

dns_config_t dns_config;

dns_config_t config_init(int argc, char **argv)
{
    dns_config_t config;
    config.logging_level = logging_information_level;
    config.ipv4_config_file = NULL;
    config.ipv6_config_file = NULL;
    config.cname_config_file = NULL;
    config.upstream_name = "10.3.9.44";

    log_debug("Reading command line configuration parameters");
    for (int i = 1; i < argc; i++)
    {
        if (*argv[i] == '-')
        {
            switch (argv[i][1])
            {
                case 'h':
                    config_help_print();
                    exit(0);
                case 's':
                    config.upstream_name = argv[i + 1];
                    log_information("Setting upstream server: %s", config.upstream_name);
                    i++;
                    break;
                case '4':
                    config.ipv4_config_file = argv[i + 1];
                    log_information("Reading IPv4 config file: %s", config.ipv4_config_file);
                    i++;
                    break;
                case '6':
                    config.ipv6_config_file = argv[i + 1];
                    log_information("Reading IPv6 config file: %s", config.ipv6_config_file);
                    i++;
                    break;
                case 'c':
                    config.cname_config_file = argv[i + 1];
                    log_information("Reading CNAME config file: %s", config.cname_config_file);
                    i++;
                    break;
                case 'l':
                {
                    logging_level_t level = *argv[i+1] - 48;
                    if (level > 3)
                    {
                        log_warning("Invalid logging level: %d", level);
                    }
                    else
                    {
                        logging_level = level;
                    }
                }
                default:
                    log_information("Unknown configuration option: %s", argv[i]);
                    break;
            }
        }
        else
        {
            log_information("Unknown configuration option: %s", argv[i]);
        }
    }

    return config;
}

void config_help_print()
{
    log_information("-h Print help information");
    log_information("-s [server_address] Set upstream server address");
    log_information("-4 [file_name] IPv4 configuration file");
    log_information("-6 [file_name] IPv6 configuration file");
    log_information("-c [file_name] CNAME configuration file");
    log_information("-l [0/1/2/3] Set logging level 0-debug 1-info 2-warn 3-error");
}