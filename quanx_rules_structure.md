# Quantumult X规则结构说明

## 规则格式

Quantumult X (简称quanx)的规则采用以下基本格式:

```
规则类型,匹配内容,动作[,参数]
```

例如:
```
domain-suffix,google.com,proxy
```

## 支持的规则类型

根据`quanx_filter.rs`的解析逻辑，支持以下几种规则类型:

### 域名规则

1. **完全匹配**: 
   - `host` 或 `domain` - 精确匹配整个域名
   - 例如: `domain,www.example.com,direct`

2. **后缀匹配**:
   - `host-suffix` 或 `domain-suffix` - 匹配域名后缀
   - 例如: `domain-suffix,example.com,direct`
   - 这种规则会匹配`example.com`、`www.example.com`、`sub.example.com`等

3. **关键词匹配**:
   - `host-keyword` 或 `domain-keyword` - 匹配域名中的关键词
   - 例如: `domain-keyword,google,proxy`

### IP规则

1. **IP CIDR**:
   - `ip-cidr` - IPv4 CIDR规则
   - 例如: `ip-cidr,192.168.0.0/16,direct`

2. **IPv6 CIDR**:
   - `ip6-cidr` 或 `ip-cidr6` - IPv6 CIDR规则
   - 例如: `ip-cidr6,2001:db8::/32,proxy`

3. **GeoIP规则**:
   - `geoip` - 基于IP地理位置的规则
   - 例如: `geoip,CN,direct`
   - 需要配合GeoIP数据库使用

### 最终规则

- `final` - 当所有规则都不匹配时使用的默认规则
- 例如: `final,proxy`

## 动作类型

每条规则指定的动作通常有:

- `direct`: 直接连接，不经过代理
- `proxy`: 通过代理连接
- 其他自定义动作名称(如果在代码中有定义)

## 特殊参数

某些规则支持额外的参数:

- `no-resolve`: 指示不解析域名为IP地址(用于IP规则)
- 例如: `ip-cidr,192.168.0.0/16,direct,no-resolve`

## 在当前项目中的应用

在当前的代理项目中，我们主要使用`domain-suffix`类型的规则，例如:

```
domain-suffix,bilibili.com,direct
domain-suffix,google.com,proxy
```

对于GeoIP规则，我们使用:

```
geoip,CN,direct
geoip,US,proxy
```

## 规则处理流程

当规则加载后，在`RuleSet::load_quanx_filter`方法中:

1. 规则首先按类型分类
2. 然后构建不同类型的匹配器(如Aho-Corasick自动机用于域名匹配)
3. 设置规则优先级，域名规则优先于IP规则

## 推荐的规则组织方式

为了便于维护，建议将规则按以下方式组织:

```
# 直连域名
domain-suffix,baidu.com,direct
domain-suffix,bilibili.com,direct

# 代理域名  
domain-suffix,google.com,proxy
domain-suffix,facebook.com,proxy

# GeoIP规则
geoip,CN,direct
geoip,US,proxy

# 最终规则
final,proxy
``` 