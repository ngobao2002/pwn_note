Pwntools là một thư viện Python được thiết kế chuyên biệt cho việc viết mã khai thác trong các cuộc thi CTF. Nó không chỉ là một công cụ để gửi và nhận dữ liệu, mà là một framework nghiên cứu hoàn chỉnh.
### Các module cốt lõi:
- pwn: Chứa các hàm chính để tương tác với tiến trình (process, remote), đóng gói và giải nén dữ liệu (p32, p64, u32, u64).
- elf: Dùng để phân tích file ELF, dễ dàng lấy địa chỉ của các hàm, các biểu tượng (symbols), và các section như .got.plt, .plt.
- gdb: Cung cấp khả năng đính kèm GDB vào tiến trình một cách tự động (gdb.attach()), cho phép gỡ lỗi script khai thác một cách liền mạch.
- rop: Tự động hóa việc tìm kiếm các gadget và xây dựng các chuỗi ROP (Return-Oriented Programming).
### Template Pwntools
```Python 3
from pwn import *

# Cấu hình chung
elf = context.binary = ELF('./challenge_binary')
libc = ELF('./libc.so.6') # Tải libc nếu cần
context.log_level = 'debug' # Hiển thị chi tiết I/O

# Logic chuyển đổi local/remote
if args.REMOTE:
    p = remote('chall.pwnable.tw', 10101)
else:
    p = process(elf.path)
    # Đính kèm GDB để gỡ lỗi
    gdb.attach(p, gdbscript='''
        b *main+123 # Đặt breakpoint tại địa chỉ quan trọng
        c
    ''')

# --- Viết mã khai thác ở đây ---

p.interactive()
```
### References
https://github.com/damienmaier/pwntools-cheatsheet


