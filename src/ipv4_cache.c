/**
 * IPv4 缓存实现
 * 本文件实现了 IPv4 DNS 记录（A 记录）的缓存系统
 * 提供存储、检索和管理 IPv4 地址映射的功能
 */

//
// Created by ricardo on 23-6-23.
//
#include "ipv4_cache.h"

#include <stdlib.h>
#include "hash_table.h"
#include "logging.h"
#include "utils.h"

// 全局哈希表，用于存储 IPv4 缓存条目
hash_table_t *ipv4_table;

/**
 * 初始化 IPv4 缓存系统
 * 创建一个新的哈希表用于存储 IPv4 记录
 */
void ipv4_cache_init()
{
    log_information("Initializing IPv4 cache table");
    ipv4_table = hash_table_new();
}

/**
 * 添加或更新 IPv4 缓存条目
 * @param name 要缓存的域名
 * @param cache 包含地址和 TTL 的 IPv4 缓存数据
 */
void ipv4_cache_put(string_t *name, ipv4_cache_t *cache)
{
    ipv4_cache_t *old_cache = ipv4_cache_get(name);

    if (old_cache == NULL)
    {
        // 如果条目不存在，创建新的缓存条目
        old_cache = malloc(sizeof(ipv4_cache_t));
        old_cache->ttl = cache->ttl;
        old_cache->timestamp = time(NULL);
        old_cache->node = cache->node;
        old_cache->manual = false;

        hash_table_put(ipv4_table, name, old_cache);
    }
    else
    {
        if (old_cache->manual == true)
        {
            // 手动维护的缓存条目不会被更新
            return;
        }

        // 更新现有缓存条目
        old_cache->ttl = cache->ttl;
        old_cache->timestamp = time(NULL);
        old_cache->manual = false;
        free(old_cache->node);
        old_cache->node = cache->node;
    }

    // 记录缓存添加日志
    char *domain_print = string_print(name);
    ipv4_node_t *node = cache->node;
    while (node != NULL)
    {
        string_t *address = inet4address2string(node->address);
        char *address_print = string_print(address);
        log_information("A record cache added %s-%s", domain_print, address_print);
        free(address_print);
        string_free(address);

        node = node->next;
    }
    free(domain_print);
}

/**
 * 获取 IPv4 缓存条目
 * @param name 要查找的域名
 * @return 缓存条目指针，如果未找到则返回 NULL
 */
ipv4_cache_t *ipv4_cache_get(string_t *name)
{
    return hash_table_get(ipv4_table, name);
}

/**
 * 释放 IPv4 缓存使用的所有资源
 */
void ipv4_cache_free()
{
    hash_table_free(ipv4_table);
}

/**
 * 清理过期的 IPv4 缓存条目
 * 删除已超过 TTL 的条目
 */
void ipv4_cache_clear()
{
    time_t now = time(NULL);
    // 分配数组存储过期条目
    string_t **result = malloc(sizeof(string_t *) * ipv4_table->count);
    int count = 0;

    // 扫描哈希表中的所有条目
    for (int i = 0; i < ipv4_table->capacity; i++)
    {
        hash_node_t *node = &ipv4_table->table[i];

        while (node != NULL and node->name != NULL)
        {
            ipv4_cache_t *cache = node->data;

            // 检查条目是否过期且非手动维护
            if (cache->manual == false and cache->timestamp + cache->ttl < now)
            {
                // 释放 IPv4 节点结构
                ipv4_node_t *p = cache->node;
                while (p != NULL)
                {
                    ipv4_node_t *next_p = p->next;
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
        hash_table_remove(ipv4_table, result[i]);
    }

    free(result);
}

/**
 * 从配置文件读取 IPv4 缓存条目
 * @param file_name 配置文件路径
 */
void ipv4_read_file(const char *file_name)
{
    if (file_name == NULL)
    {
        return;
    }

    FILE *file = fopen(file_name, "r");
    if (file == NULL)
    {
        log_warning("Failed to read IPv4 configuration file");
        return;
    }

    // 逐行读取文件
    while (true)
    {
        char buf[1024];
        char *r = fgets(buf, 1024, file);
        if (r == NULL)
        {
            break;
        }

        // 移除行尾的换行符
        string_t *result = string_malloc(buf, strlen(buf) - 1);
        split_array_t *array = string_split(result, ' ');
        if (array->length == 2)
        {
            // 解析 IPv4 地址
            char *address = malloc(array->array[1]->length + 1);
            address[array->array[1]->length] = '\0';
            memcpy(address, array->array[1]->value, array->array[1]->length);

            struct sockaddr_in address_in;
            uv_ip4_addr(address, 0, &address_in);

            // 创建缓存条目
            ipv4_cache_t cache = {
                    .timestamp = -1,
                    .manual = true,
                    .ttl = 1,
            };
            cache.node = malloc(sizeof(ipv4_node_t));
            swap32(&address_in.sin_addr.s_addr);
            cache.node->address = address_in.sin_addr.s_addr;
            cache.node->next = NULL;
            ipv4_cache_put(string_dup(array->array[0]), &cache);

            free(address);
        }
        else
        {
            log_warning("Invalid IPv4 configuration: %s", buf);
        }

        // 清理资源
        for (int i = 0; i < array->length; i++)
        {
            string_free(array->array[i]);
        }
        free(array);
        string_free(result);
    }

    fclose(file);
}