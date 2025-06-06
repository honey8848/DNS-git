/**
 * IPv6 缓存实现
 * 本文件实现了 IPv6 DNS 记录（AAAA 记录）的缓存系统
 * 提供存储、检索和管理 IPv6 地址映射的功能
 */

//
// Created by ricardo on 23-6-26.
//
#include "ipv6_cache.h"

#include <stdlib.h>
#include "hash_table.h"
#include "logging.h"
#include "utils.h"

// 全局哈希表，用于存储 IPv6 缓存条目
hash_table_t *ipv6_table;

/**
 * 初始化 IPv6 缓存系统
 * 创建一个新的哈希表用于存储 IPv6 记录
 */
void ipv6_cache_init()
{
    ipv6_table = hash_table_new();
    log_information("Initializing IPv6 cache table");
}

/**
 * 添加或更新 IPv6 缓存条目
 * @param name 要缓存的域名
 * @param cache 包含地址和 TTL 的 IPv6 缓存数据
 */
void ipv6_cache_put(string_t *name, ipv6_cache_t *cache)
{
    ipv6_cache_t *old_cache = ipv6_cache_get(name);

    if (old_cache == NULL)
    {
        // 如果条目不存在，创建新的缓存条目
        old_cache = malloc(sizeof(ipv6_cache_t));
        old_cache->ttl = cache->ttl;
        old_cache->timestamp = time(NULL);
        old_cache->node = cache->node;
        old_cache->manual = false;

        hash_table_put(ipv6_table, name, old_cache);
    }
    else
    {
        // 更新现有缓存条目
        old_cache->ttl = cache->ttl;
        old_cache->timestamp = time(NULL);
        old_cache->manual = false;
        free(old_cache->node);
        old_cache->node = cache->node;
    }

    // 记录缓存添加日志
    char *domain_print = string_print(name);
    ipv6_node_t *node = cache->node;
    while (node != NULL)
    {
        string_t *address = inet6address2string(node->address);
        char *address_print = string_print(address);
        log_information("AAAA record cache added %s-%s", domain_print, address_print);
        free(address_print);
        string_free(address);

        node = node->next;
    }
    free(domain_print);
}

/**
 * 获取 IPv6 缓存条目
 * @param name 要查找的域名
 * @return 缓存条目指针，如果未找到则返回 NULL
 */
ipv6_cache_t *ipv6_cache_get(string_t *name)
{
    return hash_table_get(ipv6_table, name);
}

/**
 * 释放 IPv6 缓存使用的所有资源
 */
void ipv6_cache_free()
{
    hash_table_free(ipv6_table);
}

/**
 * 清理过期的 IPv6 缓存条目
 * 删除已超过 TTL 的条目
 */
void ipv6_cache_clear()
{
    time_t now = time(NULL);
    // 分配数组存储过期条目
    string_t **result = malloc(sizeof(string_t *) * ipv6_table->count);
    int count = 0;

    // 扫描哈希表中的所有条目
    for (int i = 0; i < ipv6_table->capacity; i++)
    {
        hash_node_t *node = &ipv6_table->table[i];

        while (node != NULL and node->name != NULL)
        {
            ipv6_cache_t *cache = node->data;

            // 检查条目是否过期
            if (cache->timestamp + cache->ttl < now)
            {
                // 释放 IPv6 节点结构
                ipv6_node_t *p = cache->node;
                while (p != NULL)
                {
                    ipv6_node_t *next_p = p->next;
                    free(p);
                    p = next_p;
                }

                // 添加到待删除列表
                result[count] = node->name;
                count++;
            }

            node = node->next;
        }
    }

    // 删除所有过期条目
    for (int i = 0; i < count; i++)
    {
        hash_table_remove(ipv6_table, result[i]);
    }

    free(result);
}

