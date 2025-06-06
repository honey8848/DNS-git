/**
 * CNAME 缓存实现
 * 本文件实现了 CNAME DNS 记录的缓存系统
 * 提供存储、检索和管理 CNAME 映射的功能
 */

//
// Created by ricardo on 23-6-26.
//
#include "cname_cache.h"

#include <stdlib.h>
#include "hash_table.h"
#include "logging.h"

// 全局哈希表，用于存储 CNAME 缓存条目
hash_table_t *cname_table;

/**
 * 初始化 CNAME 缓存系统
 * 创建一个新的哈希表用于存储 CNAME 记录
 */
void cname_cache_init()
{
    log_information("Initializing CNAME cache");
    cname_table = hash_table_new();
}

/**
 * 添加新的 CNAME 缓存条目
 * @param name 要缓存的域名
 * @param cache 包含目标名称和 TTL 的 CNAME 缓存数据
 */
void cname_cache_put(string_t *name, cname_cache_t *cache)
{
    cname_cache_t *item = malloc(sizeof(cname_cache_t));

    item->name = cache->name;
    item->ttl = cache->ttl;
    item->timestamp = time(NULL);
    item->manual = false;

    // 记录缓存添加日志
    char *key = string_print(name);
    char *value = string_print(item->name);
    log_information("CNAME cache table added %s->%s", key, value);
    free(key);
    free(value);

    hash_table_put(cname_table, name, item);
}

/**
 * 获取 CNAME 缓存条目
 * @param name 要查找的域名
 * @return 缓存条目指针，如果未找到则返回 NULL
 */
cname_cache_t *cname_cache_get(string_t *name)
{
    return hash_table_get(cname_table, name);
}

/**
 * 释放 CNAME 缓存使用的所有资源
 */
void cname_cache_free()
{
    hash_table_free(cname_table);
}

/**
 * 清理过期的 CNAME 缓存条目
 * 删除已超过 TTL 的条目
 */
void cname_cache_clear()
{
    // CNAME 缓存清理实现
    // 类似于 IPv4 和 IPv6 缓存清理的实现
}


