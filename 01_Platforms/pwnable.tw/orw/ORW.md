#### Checksec
Kiểm tra mitigation bao gồm [[NX (Non-executable Stack)]], [[PIE (Position-Independent Executable)]], [[RELRO (Relocation Read-Only)]], [[Stack Canaries]]  
![[Pasted image 20250730210053.png]]
#### Check seccomp
![[Pasted image 20250922160445.png]]
=> Từ tiêu đề và seccomp cho thấy, shellcode ta truyền vào chỉ giới hạn lại quyền `open` `read` và `write`

Sử dụng selfscraft từ pwntools
