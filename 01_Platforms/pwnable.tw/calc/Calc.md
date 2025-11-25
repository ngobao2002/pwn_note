#### Checksec
Kiểm tra mitigation bao gồm [[NX (Non-executable Stack)]], [[PIE (Position-Independent Executable)]], [[RELRO (Relocation Read-Only)]], [[Stack Canaries]]  
![[Pasted image 20250730213459.png]]
Thử thách `calc` là một bước tiến quan trọng so với các bài stack overflow cơ bản. Nó giới thiệu Stack Canary, một cơ chế phòng thủ phổ biến, buộc chúng ta phải suy nghĩ vượt ra ngoài việc chỉ đơn thuần ghi đè lên stack.
=> Sự hiện diện của Canary là rào cản chính. Một cuộc tấn công buffer overflow thông thường sẽ bị phát hiện và chương trình sẽ bị chấm dứt.
#### Main
```Assembly
.text:08049452 ; =============== S U B R O U T I N E =======================================
.text:08049452
.text:08049452 ; Attributes: bp-based frame fuzzy-sp
.text:08049452
.text:08049452 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:08049452                 public main
.text:08049452 main            proc near               ; DATA XREF: _start+17↑o
.text:08049452
.text:08049452 argc            = dword ptr  8
.text:08049452 argv            = dword ptr  0Ch
.text:08049452 envp            = dword ptr  10h
.text:08049452
.text:08049452 ; __unwind {
.text:08049452                 push    ebp
.text:08049453                 mov     ebp, esp
.text:08049455                 and     esp, 0FFFFFFF0h
.text:08049458                 sub     esp, 10h
.text:0804945B                 mov     dword ptr [esp+4], offset timeout
.text:08049463                 mov     dword ptr [esp], 0Eh (14)
.text:0804946A                 call    ssignal
.text:0804946F                 mov     dword ptr [esp], 3Ch (60) ; '<'
.text:08049476                 call    alarm
.text:0804947B                 mov     dword ptr [esp], offset aWelcomeToSecpr ; "=== Welcome to SECPROG calculator ==="
.text:08049482                 call    puts
.text:08049487                 mov     eax, stdout
.text:0804948C                 mov     [esp], eax
.text:0804948F                 call    fflush
.text:08049494                 call    calc
.text:08049499                 mov     dword ptr [esp], offset aMerryChristmas ; "Merry Christmas!"
.text:080494A0                 call    puts
.text:080494A5                 leave
.text:080494A6                 retn
.text:080494A6 ; } // starts at 8049452
.text:080494A6 main            endp
.text:080494A6
.text:080494A6 ; ---------------------------------------------------------------------------
.text:080494A7                 align 10h
```
- *ssignal*: The function ssignal() defines the action to take when the software signal with number signum is raised using the function gsignal(), and returns the previous such action or SIG_DFL.
- Chương trình sẽ gọi signal-handler với 2 args được pass là 14 và timeout. trong `man 7 signal` ta sẽ thấy 14 chính là `SIGALRM` . `SIGALRM` này dùng cho hàm kế tiếp đó chính là `alarm` để ngăn chương trình nếu không có tác động gì thì sẽ tự ngắt kết nối (arg timeout) nếu quá 60 giây (3C).
- Hàm `fflush` trong C được dùng để **xử lý bộ đệm (buffer) của luồng I/O**, đặc biệt quan trọng khi làm việc với `stdout`, `stdin`, `stderr` hoặc file.
```C
#include <stdio.h>

int fflush(FILE *stream);
```
- `stream`: Luồng bạn muốn làm sạch bộ đệm. Có thể là `stdout`, `stdin`, `stderr`, hoặc một `FILE*` đang mở.
- Trả về:
    - `0` nếu thành công
    - `EOF` nếu có lỗi xảy ra
- fflush(stdout):	Ghi toàn bộ nội dung còn trong bộ đệm ra màn hình ngay lập tức.
- fflush(file):	Ghi nội dung bộ đệm của file ra ổ đĩa (rất quan trọng sau khi fwrite)
- fflush(NULL):	Làm sạch tất cả các luồng đầu ra đã mở và flush chúng.
#### calc
```Assembly
.text:08049379 ; =============== S U B R O U T I N E =======================================
.text:08049379
.text:08049379 ; Attributes: bp-based frame
.text:08049379
.text:08049379                 public calc
.text:08049379 calc            proc near               ; CODE XREF: main+42↓p
.text:08049379
.text:08049379 var_5A0         = dword ptr -5A0h
.text:08049379 var_59C         = dword ptr -59Ch
.text:08049379 s               = byte ptr -40Ch
.text:08049379 var_C           = dword ptr -0Ch
.text:08049379
.text:08049379 ; __unwind {
.text:08049379                 push    ebp
.text:0804937A                 mov     ebp, esp
.text:0804937C                 sub     esp, 5B8h
.text:08049382                 mov     eax, large gs:14h
.text:08049388                 mov     [ebp+var_C], eax
.text:0804938B                 xor     eax, eax
.text:0804938D
.text:0804938D loc_804938D:                            ; CODE XREF: calc+AA↓j
.text:0804938D                                         ; calc:loc_8049428↓j
.text:0804938D                 mov     dword ptr [esp+4], 400h ; n
.text:08049395                 lea     eax, [ebp+s]
.text:0804939B                 mov     [esp], eax      ; s
.text:0804939E                 call    _bzero
.text:080493A3                 mov     dword ptr [esp+4], 400h
.text:080493AB                 lea     eax, [ebp+s]
.text:080493B1                 mov     [esp], eax
.text:080493B4                 call    get_expr
.text:080493B9                 test    eax, eax
.text:080493BB                 jnz     short loc_80493CC
.text:080493BD                 nop
.text:080493BE                 mov     eax, [ebp+var_C]
.text:080493C1                 xor     eax, large gs:14h
.text:080493C8                 jz      short locret_8049432
.text:080493CA                 jmp     short loc_804942D
.text:080493CC ; ---------------------------------------------------------------------------
.text:080493CC
.text:080493CC loc_80493CC:                            ; CODE XREF: calc+42↑j
.text:080493CC                 lea     eax, [ebp+var_5A0]
.text:080493D2                 mov     [esp], eax
.text:080493D5                 call    init_pool
.text:080493DA                 lea     eax, [ebp+var_5A0]
.text:080493E0                 mov     [esp+4], eax
.text:080493E4                 lea     eax, [ebp+s]
.text:080493EA                 mov     [esp], eax
.text:080493ED                 call    parse_expr
.text:080493F2                 test    eax, eax
.text:080493F4                 jz      short loc_8049428
.text:080493F6                 mov     eax, [ebp+var_5A0]
.text:080493FC                 sub     eax, 1
.text:080493FF                 mov     eax, [ebp+eax*4+var_59C]
.text:08049406                 mov     [esp+4], eax
.text:0804940A                 mov     dword ptr [esp], offset unk_80BF804
.text:08049411                 call    printf
.text:08049416                 mov     eax, stdout
.text:0804941B                 mov     [esp], eax
.text:0804941E                 call    fflush
.text:08049423                 jmp     loc_804938D
.text:08049428 ; ---------------------------------------------------------------------------
.text:08049428
.text:08049428 loc_8049428:                            ; CODE XREF: calc+7B↑j
.text:08049428                 jmp     loc_804938D
.text:0804942D ; ---------------------------------------------------------------------------
.text:0804942D
.text:0804942D loc_804942D:                            ; CODE XREF: calc+51↑j
.text:0804942D                 call    __stack_chk_fail
.text:08049432 ; ---------------------------------------------------------------------------
.text:08049432
.text:08049432 locret_8049432:                         ; CODE XREF: calc+4F↑j
.text:08049432                 leave
.text:08049433                 retn
.text:08049433 ; } // starts at 8049379
.text:08049433 calc            endp
.text:08049433
.text:08049434
```
Tạo khung stack:
```Assembly
.text:08049379                 push    ebp
.text:0804937A                 mov     ebp, esp
.text:0804937C                 sub     esp, 5B8h
```
Mã giả:
```C
unsigned int calc()
{
  int v1[101]; // [esp+18h] [ebp-5A0h] BYREF
  char s[1024]; // [esp+1ACh] [ebp-40Ch] BYREF
  unsigned int v3; // [esp+5ACh] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(s, 0x400u);
    if ( !get_expr(s, 1024) )
      break;
    init_pool(v1);
    if ( parse_expr(s, v1) )
    {
      printf("%d\n", v1[v1[0]]);
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ v3;
}
```
#### Liên hệ với mã assembly
- Mã giả này là phiên bản cấp cao của mã assembly đã cung cấp. Các lệnh như _bzero, get_expr, init_pool, parse_expr, printf, và fflush trong assembly tương ứng trực tiếp với các hàm gọi trong mã giả.
- v1[101] tương ứng với var_5A0 và var_59C trong assembly, được truy cập để lưu trữ và lấy kết quả.
- s[1024] tương ứng với mảng s (0x400 byte) trong assembly.
- Stack canary (v3 và __readgsdword(0x14u)) khớp với việc sử dụng gs:14h và var_C trong assembly để bảo vệ stack.
Vậy giá trị 101 ở đâu ra ?
Để hiểu tại sao mảng v1 trong mã giả được xác định là v1[101] (101 số nguyên), chúng ta cần xem xét cách các biến var_5A0 và var_59C được sử dụng trong mã assembly và cách chúng được ánh xạ sang mã giả:

1. Kích thước của mảng v1:
	- Trong mã assembly, var_5A0 và var_59C là hai offset liên tiếp trong khung stack: -0x5A0 và -0x59C.
	- Khoảng cách giữa var_5A0 (-0x5A0 = -1440) và var_59C (-0x59C = -1436) là 0x5A0 - 0x59C = 4 byte, tương ứng với một số nguyên (dword, 4 byte trên hệ 32-bit).
	- Tuy nhiên, trong mã giả, v1 được coi là một mảng số nguyên. Để xác định kích thước của mảng này, ta cần xem xét không gian bộ nhớ được phân bổ từ var_5A0 đến khi bắt đầu vùng bộ nhớ của biến tiếp theo (s tại -0x40C).
2. Tính toán kích thước mảng:
	- Vùng bộ nhớ từ var_5A0 (-0x5A0 = -1440) đến s (-0x40C = -1036) là:
$$0x5A0 - 0x40C = 1440 - 1036 = 404 \text{ byte}.$$
	Vì mỗi số nguyên (dword) chiếm 4 byte, số lượng số nguyên có thể chứa trong 404 byte là:-
$$404 \div 4 = 101 \text{ số nguyên}.$$
	- Do đó, vùng bộ nhớ từ var_5A0 đến trước s được diễn giải là một mảng gồm 101 số nguyên, tương ứng với v1[101] trong mã giả.

3. Cách sử dụng var_5A0 và var_59C:
	- Trong mã assembly, var_5A0 được truyền vào hàm init_pool và parse_expr, cho thấy nó là điểm bắt đầu của một cấu trúc dữ liệu (có thể là mảng hoặc ngăn xếp).
	- var_59C được sử dụng để truy cập giá trị kết quả: mov eax, [ebp+eax*4+var_59C], với eax được tính từ var_5A0 (mov eax, [ebp+var_5A0]; sub eax, 1). Điều này cho thấy var_59C là một phần của mảng bắt đầu từ var_5A0, và var_5A0 có thể chứa chỉ số hoặc con trỏ đến phần tử cuối cùng trong mảng.
	- Trong mã giả, v1[v1[0]] tương ứng với việc truy cập giá trị tại chỉ số được lưu trong v1[0]. Điều này xác nhận rằng v1 là một mảng số nguyên, và v1[0] đóng vai trò như một chỉ số hoặc con trỏ.

Tại sao chính xác 101 số nguyên?:
Kích thước 404 byte (từ -0x5A0 đến -0x40C) được chia thành các số nguyên 4 byte, dẫn đến 101 phần tử.
Trong mã giả, người dịch ngược (decompiler) đã suy ra rằng vùng bộ nhớ này được sử dụng như một mảng số nguyên với kích thước 101, dựa trên việc phân bổ bộ nhớ và cách truy cập các phần tử trong mã assembly.

Hàm bzero:
The bzero() function sets the first n bytes of the area starting at s to zero (bytes containing '\0').
#### Luồng hoạt động:
**Khởi tạo frame và canary** (địa chỉ 08049379 - 0804938B):
- Thiết lập stack frame (push ebp, mov ebp esp, sub esp 5B8h) để dành chỗ cho biến:
    - var_5A0 đến var_59C: Một mảng int (pool) khoảng 101 phần tử (dùng để lưu biểu thức đã parse, như stack cho RPN - Reverse Polish Notation).
    - s: Buffer byte 1024 byte để lưu chuỗi biểu thức.
    - var_C: Lưu giá trị canary (từ segment GS) để kiểm tra stack overflow.
- XOR eax để xóa (khởi tạo).
**Vòng lặp chính** (bắt đầu tại loc_804938D, lặp bằng jmp):
- **Xóa buffer** (0804938D - 0804939E): Gọi bzero(s, 400h) để xóa buffer s (1024 byte, tránh dữ liệu cũ).
- **Đọc biểu thức** (080493A3 - 080493B4): Gọi get_expr(s, 400h) để đọc input vào s. Hàm này có lẽ đọc từ stdin (như fgets hoặc tương tự), trả về độ dài hoặc 1 nếu thành công, 0 nếu hết input (EOF) hoặc lỗi.
    - Nếu get_expr trả về 0 (test eax, eax; jnz ...): Thoát vòng lặp, kiểm tra canary, và return (đi đến 080493BE - 08049433).
- **Khởi tạo pool** (080493CC - 080493D5): Gọi init_pool(&v1) để reset mảng pool (có lẽ đặt v1[0] = 1 hoặc tương tự, như chỉ số stack pointer).
- **Phân tích cú pháp** (080493DA - 080493ED): Gọi parse_expr(s, &v1) để parse chuỗi s thành dạng số học trong pool.
    - Nếu parse thất bại (test eax, eax; jz ...): Bỏ qua in kết quả, quay lại vòng lặp (jmp loc_804938D).
    - Nếu thành công: Pool chứa kết quả tính toán (v1[0] là chỉ số hoặc độ dài stack).
### Init pool
```Assembly
08048FF8  push    ebp
08048FF9  mov     ebp, esp
08048FFB  sub     esp, 10h               ; tạo stack frame

08048FFE  mov     eax, [ebp+arg_0]       ; eax = con trỏ pool (tham số hàm)
08049001  mov     dword ptr [eax], 0     ; pool[0] = 0

08049007  mov     [ebp+var_4], 0         ; i = 0

; loop start
0804900E  jmp     short loc_8049022

08049010 loc_8049010:
08049010  mov     eax, [ebp+arg_0]       ; eax = pool
08049013  mov     edx, [ebp+var_4]       ; edx = i
08049016  mov     dword ptr [eax+edx*4+4], 0 ; pool[i+1] = 0
0804901E  add     [ebp+var_4], 1         ; i++

08049022 loc_8049022:
08049022  cmp     [ebp+var_4], 63h       ; so sánh i <= 99 (0x63)
08049026  jle     short loc_8049010      ; nếu đúng thì lặp

08049028  leave
08049029  retn
```
### Parse_expr
```Assembly
.text:0804902A ; =============== S U B R O U T I N E =======================================
.text:0804902A
.text:0804902A ; Attributes: bp-based frame
.text:0804902A
.text:0804902A                 public parse_expr
.text:0804902A parse_expr      proc near               ; CODE XREF: calc+74↓p
.text:0804902A
.text:0804902A var_90          = dword ptr -90h
.text:0804902A var_8C          = dword ptr -8Ch
.text:0804902A var_88          = dword ptr -88h
.text:0804902A var_84          = dword ptr -84h
.text:0804902A var_80          = dword ptr -80h
.text:0804902A var_7C          = dword ptr -7Ch
.text:0804902A s1              = dword ptr -78h
.text:0804902A var_74          = dword ptr -74h
.text:0804902A s               = byte ptr -70h
.text:0804902A var_C           = dword ptr -0Ch
.text:0804902A arg_0           = dword ptr  8
.text:0804902A arg_4           = dword ptr  0Ch
.text:0804902A
.text:0804902A ; __unwind {
.text:0804902A                 push    ebp
.text:0804902B                 mov     ebp, esp
.text:0804902D                 push    ebx
.text:0804902E                 sub     esp, 0A4h
.text:08049034                 mov     eax, [ebp+arg_0]
.text:08049037                 mov     [ebp+var_8C], eax
.text:0804903D                 mov     eax, [ebp+arg_4]
.text:08049040                 mov     [ebp+var_90], eax
.text:08049046                 mov     eax, large gs:14h
.text:0804904C                 mov     [ebp+var_C], eax
.text:0804904F                 xor     eax, eax
.text:08049051                 mov     eax, [ebp+var_8C]
.text:08049057                 mov     [ebp+var_88], eax
.text:0804905D                 mov     [ebp+var_80], 0
.text:08049064                 mov     dword ptr [esp+4], 64h ; 'd' ; n
.text:0804906C                 lea     eax, [ebp+s]
.text:0804906F                 mov     [esp], eax      ; s
.text:08049072                 call    _bzero
.text:08049077                 mov     [ebp+var_84], 0
.text:08049081
.text:08049081 loc_8049081:                            ; CODE XREF: parse_expr+301↓j
.text:08049081                 mov     edx, [ebp+var_84]
.text:08049087                 mov     eax, [ebp+var_8C]
.text:0804908D                 add     eax, edx
.text:0804908F                 movzx   eax, byte ptr [eax]
.text:08049092                 movsx   eax, al
.text:08049095                 sub     eax, 30h ; '0'
.text:08049098                 cmp     eax, 9
.text:0804909B                 jbe     loc_8049324
.text:080490A1                 mov     edx, [ebp+var_84]
.text:080490A7                 mov     eax, [ebp+var_8C]
.text:080490AD                 add     eax, edx
.text:080490AF                 mov     edx, eax
.text:080490B1                 mov     eax, [ebp+var_88]
.text:080490B7                 sub     edx, eax
.text:080490B9                 mov     eax, edx
.text:080490BB                 mov     [ebp+var_7C], eax
.text:080490BE                 mov     eax, [ebp+var_7C]
.text:080490C1                 add     eax, 1
.text:080490C4                 mov     [esp], eax
.text:080490C7                 call    malloc
.text:080490CC                 mov     [ebp+s1], eax
.text:080490CF                 mov     eax, [ebp+var_7C]
.text:080490D2                 mov     [esp+8], eax
.text:080490D6                 mov     eax, [ebp+var_88]
.text:080490DC                 mov     [esp+4], eax
.text:080490E0                 mov     eax, [ebp+s1]
.text:080490E3                 mov     [esp], eax
.text:080490E6                 call    memcpy
.text:080490EB                 mov     edx, [ebp+var_7C]
.text:080490EE                 mov     eax, [ebp+s1]
.text:080490F1                 add     eax, edx
.text:080490F3                 mov     byte ptr [eax], 0
.text:080490F6                 mov     dword ptr [esp+4], offset s2 ; "0"
.text:080490FE                 mov     eax, [ebp+s1]
.text:08049101                 mov     [esp], eax      ; s1
.text:08049104                 call    _strcmp
.text:08049109                 test    eax, eax
.text:0804910B                 jnz     short loc_8049130
.text:0804910D                 mov     dword ptr [esp], offset aPreventDivisio ; "prevent division by zero"
.text:08049114                 call    puts
.text:08049119                 mov     eax, stdout
.text:0804911E                 mov     [esp], eax
.text:08049121                 call    fflush
.text:08049126                 mov     eax, 0
.text:0804912B                 jmp     loc_804935F
.text:08049130 ; ---------------------------------------------------------------------------
.text:08049130
.text:08049130 loc_8049130:                            ; CODE XREF: parse_expr+E1↑j
.text:08049130                 mov     eax, [ebp+s1]
.text:08049133                 mov     [esp], eax
.text:08049136                 call    atoi
.text:0804913B                 mov     [ebp+var_74], eax
.text:0804913E                 cmp     [ebp+var_74], 0
.text:08049142                 jle     short loc_8049164
.text:08049144                 mov     eax, [ebp+var_90]
.text:0804914A                 mov     eax, [eax]
.text:0804914C                 lea     ecx, [eax+1]
.text:0804914F                 mov     edx, [ebp+var_90]
.text:08049155                 mov     [edx], ecx
.text:08049157                 mov     edx, [ebp+var_90]
.text:0804915D                 mov     ecx, [ebp+var_74]
.text:08049160                 mov     [edx+eax*4+4], ecx
.text:08049164
.text:08049164 loc_8049164:                            ; CODE XREF: parse_expr+118↑j
.text:08049164                 mov     edx, [ebp+var_84]
.text:0804916A                 mov     eax, [ebp+var_8C]
.text:08049170                 add     eax, edx
.text:08049172                 movzx   eax, byte ptr [eax]
.text:08049175                 test    al, al
.text:08049177                 jz      short loc_8049198
.text:08049179                 mov     eax, [ebp+var_84]
.text:0804917F                 lea     edx, [eax+1]
.text:08049182                 mov     eax, [ebp+var_8C]
.text:08049188                 add     eax, edx
.text:0804918A                 movzx   eax, byte ptr [eax]
.text:0804918D                 movsx   eax, al
.text:08049190                 sub     eax, 30h ; '0'
.text:08049193                 cmp     eax, 9
.text:08049196                 ja      short loc_80491C0
.text:08049198
.text:08049198 loc_8049198:                            ; CODE XREF: parse_expr+14D↑j
.text:08049198                 mov     eax, [ebp+var_84]
.text:0804919E                 lea     edx, [eax+1]
.text:080491A1                 mov     eax, [ebp+var_8C]
.text:080491A7                 add     eax, edx
.text:080491A9                 mov     [ebp+var_88], eax
.text:080491AF                 lea     edx, [ebp+s]
.text:080491B2                 mov     eax, [ebp+var_80]
.text:080491B5                 add     eax, edx
.text:080491B7                 movzx   eax, byte ptr [eax]
.text:080491BA                 test    al, al
.text:080491BC                 jz      short loc_80491E3
.text:080491BE                 jmp     short loc_8049203
.text:080491C0 ; ---------------------------------------------------------------------------
.text:080491C0
.text:080491C0 loc_80491C0:                            ; CODE XREF: parse_expr+16C↑j
.text:080491C0                 mov     dword ptr [esp], offset aExpressionErro ; "expression error!"
.text:080491C7                 call    puts
.text:080491CC                 mov     eax, stdout
.text:080491D1                 mov     [esp], eax
.text:080491D4                 call    fflush
.text:080491D9                 mov     eax, 0
.text:080491DE                 jmp     loc_804935F
.text:080491E3 ; ---------------------------------------------------------------------------
.text:080491E3
.text:080491E3 loc_80491E3:                            ; CODE XREF: parse_expr+192↑j
.text:080491E3                 mov     edx, [ebp+var_84]
.text:080491E9                 mov     eax, [ebp+var_8C]
.text:080491EF                 add     eax, edx
.text:080491F1                 movzx   eax, byte ptr [eax]
.text:080491F4                 lea     ecx, [ebp+s]
.text:080491F7                 mov     edx, [ebp+var_80]
.text:080491FA                 add     edx, ecx
.text:080491FC                 mov     [edx], al
.text:080491FE                 jmp     loc_804930C
.text:08049203 ; ---------------------------------------------------------------------------
.text:08049203
.text:08049203 loc_8049203:                            ; CODE XREF: parse_expr+194↑j
.text:08049203                 mov     edx, [ebp+var_84]
.text:08049209                 mov     eax, [ebp+var_8C]
.text:0804920F                 add     eax, edx
.text:08049211                 movzx   eax, byte ptr [eax]
.text:08049214                 movsx   eax, al
.text:08049217                 sub     eax, 25h ; '%'  ; switch 11 cases
.text:0804921A                 cmp     eax, 0Ah
.text:0804921D                 ja      def_804922A     ; jumptable 0804922A default case, cases 38-41,44,46
.text:08049223                 mov     eax, ds:jpt_804922A[eax*4]
.text:0804922A                 jmp     eax             ; switch jump
.text:0804922C ; ---------------------------------------------------------------------------
.text:0804922C
.text:0804922C loc_804922C:                            ; CODE XREF: parse_expr+200↑j
.text:0804922C                                         ; DATA XREF: .rodata:jpt_804922A↓o
.text:0804922C                 lea     edx, [ebp+s]    ; jumptable 0804922A cases 43,45
.text:0804922F                 mov     eax, [ebp+var_80]
.text:08049232                 add     eax, edx
.text:08049234                 movzx   eax, byte ptr [eax]
.text:08049237                 movsx   eax, al
.text:0804923A                 mov     [esp+4], eax
.text:0804923E                 mov     eax, [ebp+var_90]
.text:08049244                 mov     [esp], eax
.text:08049247                 call    eval
.text:0804924C                 mov     edx, [ebp+var_84]
.text:08049252                 mov     eax, [ebp+var_8C]
.text:08049258                 add     eax, edx
.text:0804925A                 movzx   eax, byte ptr [eax]
.text:0804925D                 lea     ecx, [ebp+s]
.text:08049260                 mov     edx, [ebp+var_80]
.text:08049263                 add     edx, ecx
.text:08049265                 mov     [edx], al
.text:08049267                 jmp     loc_804930C
.text:0804926C ; ---------------------------------------------------------------------------
.text:0804926C
.text:0804926C loc_804926C:                            ; CODE XREF: parse_expr+200↑j
.text:0804926C                                         ; DATA XREF: .rodata:jpt_804922A↓o
.text:0804926C                 lea     edx, [ebp+s]    ; jumptable 0804922A cases 37,42,47
.text:0804926F                 mov     eax, [ebp+var_80]
.text:08049272                 add     eax, edx
.text:08049274                 movzx   eax, byte ptr [eax]
.text:08049277                 cmp     al, 2Bh ; '+'
.text:08049279                 jz      short loc_804928A
.text:0804927B                 lea     edx, [ebp+s]
.text:0804927E                 mov     eax, [ebp+var_80]
.text:08049281                 add     eax, edx
.text:08049283                 movzx   eax, byte ptr [eax]
.text:08049286                 cmp     al, 2Dh ; '-'
.text:08049288                 jnz     short loc_80492AB
.text:0804928A
.text:0804928A loc_804928A:                            ; CODE XREF: parse_expr+24F↑j
.text:0804928A                 add     [ebp+var_80], 1
.text:0804928E                 mov     edx, [ebp+var_84]
.text:08049294                 mov     eax, [ebp+var_8C]
.text:0804929A                 add     eax, edx
.text:0804929C                 movzx   eax, byte ptr [eax]
.text:0804929F                 lea     ecx, [ebp+s]
.text:080492A2                 mov     edx, [ebp+var_80]
.text:080492A5                 add     edx, ecx
.text:080492A7                 mov     [edx], al
.text:080492A9                 jmp     short loc_804930C
.text:080492AB ; ---------------------------------------------------------------------------
.text:080492AB
.text:080492AB loc_80492AB:                            ; CODE XREF: parse_expr+25E↑j
.text:080492AB                 lea     edx, [ebp+s]
.text:080492AE                 mov     eax, [ebp+var_80]
.text:080492B1                 add     eax, edx
.text:080492B3                 movzx   eax, byte ptr [eax]
.text:080492B6                 movsx   eax, al
.text:080492B9                 mov     [esp+4], eax
.text:080492BD                 mov     eax, [ebp+var_90]
.text:080492C3                 mov     [esp], eax
.text:080492C6                 call    eval
.text:080492CB                 mov     edx, [ebp+var_84]
.text:080492D1                 mov     eax, [ebp+var_8C]
.text:080492D7                 add     eax, edx
.text:080492D9                 movzx   eax, byte ptr [eax]
.text:080492DC                 lea     ecx, [ebp+s]
.text:080492DF                 mov     edx, [ebp+var_80]
.text:080492E2                 add     edx, ecx
.text:080492E4                 mov     [edx], al
.text:080492E6                 jmp     short loc_804930C
.text:080492E8 ; ---------------------------------------------------------------------------
.text:080492E8
.text:080492E8 def_804922A:                            ; CODE XREF: parse_expr+1F3↑j
.text:080492E8                                         ; parse_expr+200↑j
.text:080492E8                                         ; DATA XREF: ...
.text:080492E8                 lea     edx, [ebp+s]    ; jumptable 0804922A default case, cases 38-41,44,46
.text:080492EB                 mov     eax, [ebp+var_80]
.text:080492EE                 add     eax, edx
.text:080492F0                 movzx   eax, byte ptr [eax]
.text:080492F3                 movsx   eax, al
.text:080492F6                 mov     [esp+4], eax
.text:080492FA                 mov     eax, [ebp+var_90]
.text:08049300                 mov     [esp], eax
.text:08049303                 call    eval
.text:08049308                 sub     [ebp+var_80], 1
.text:0804930C
.text:0804930C loc_804930C:                            ; CODE XREF: parse_expr+1D4↑j
.text:0804930C                                         ; parse_expr+23D↑j ...
.text:0804930C                 mov     edx, [ebp+var_84]
.text:08049312                 mov     eax, [ebp+var_8C]
.text:08049318                 add     eax, edx
.text:0804931A                 movzx   eax, byte ptr [eax]
.text:0804931D                 test    al, al
.text:0804931F                 jnz     short loc_8049324
.text:08049321                 nop
.text:08049322                 jmp     short loc_8049354
.text:08049324 ; ---------------------------------------------------------------------------
.text:08049324
.text:08049324 loc_8049324:                            ; CODE XREF: parse_expr+71↑j
.text:08049324                                         ; parse_expr+2F5↑j
.text:08049324                 add     [ebp+var_84], 1
.text:0804932B                 jmp     loc_8049081
.text:08049330 ; ---------------------------------------------------------------------------
.text:08049330
.text:08049330 loc_8049330:                            ; CODE XREF: parse_expr+32E↓j
.text:08049330                 lea     edx, [ebp+s]
.text:08049333                 mov     eax, [ebp+var_80]
.text:08049336                 add     eax, edx
.text:08049338                 movzx   eax, byte ptr [eax]
.text:0804933B                 movsx   eax, al
.text:0804933E                 mov     [esp+4], eax
.text:08049342                 mov     eax, [ebp+var_90]
.text:08049348                 mov     [esp], eax
.text:0804934B                 call    eval
.text:08049350                 sub     [ebp+var_80], 1
.text:08049354
.text:08049354 loc_8049354:                            ; CODE XREF: parse_expr+2F8↑j
.text:08049354                 cmp     [ebp+var_80], 0
.text:08049358                 jns     short loc_8049330
.text:0804935A                 mov     eax, 1
.text:0804935F
.text:0804935F loc_804935F:                            ; CODE XREF: parse_expr+101↑j
.text:0804935F                                         ; parse_expr+1B4↑j
.text:0804935F                 mov     ebx, [ebp+var_C]
.text:08049362                 xor     ebx, large gs:14h
.text:08049369                 jz      short loc_8049370
.text:0804936B                 call    __stack_chk_fail
.text:08049370 ; ---------------------------------------------------------------------------
.text:08049370
.text:08049370 loc_8049370:                            ; CODE XREF: parse_expr+33F↑j
.text:08049370                 add     esp, 0A4h
.text:08049376                 pop     ebx
.text:08049377                 pop     ebp
.text:08049378                 retn
.text:08049378 ; } // starts at 804902A
.text:08049378 parse_expr      endp
.text:08049378
.text:08049379
```
### Phân Tích Hàm parse_expr - Lỗ Hổng Stack Canary Bypass

#### 1. Cấu Trúc Stack Frame

```assembly
var_90 = dword ptr -90h    ; arg_4 (tham số thứ 2)
var_8C = dword ptr -8Ch    ; arg_0 (tham số thứ 1 - chuỗi input)  
var_88 = dword ptr -88h    ; con trỏ hiện tại trong chuỗi
var_84 = dword ptr -84h    ; biến đếm i (vị trí trong chuỗi)
var_80 = dword ptr -80h    ; biến đếm cho stack s_func
var_7C = dword ptr -7Ch    ; độ dài chuỗi số
s1 = dword ptr -78h        ; con trỏ tới chuỗi số đã malloc
var_74 = dword ptr -74h    ; giá trị số nguyên sau khi atoi
s = byte ptr -70h          ; mảng s_func[100] - chứa các toán tử
var_C = dword ptr -0Ch     ; stack canary
```

#### 2. Khởi Tạo và Stack Canary

```assembly
.text:08049046  mov     eax, large gs:14h    ; Lấy stack canary từ TLS
.text:0804904C  mov     [ebp+var_C], eax     ; Lưu canary tại [ebp-0x0C]
.text:0804904F  xor     eax, eax             ; Clear eax

.text:08049064  mov     dword ptr [esp+4], 64h ; n = 100
.text:0804906C  lea     eax, [ebp+s]         ; s = &s_func[0]
.text:08049072  call    _bzero               ; bzero(s_func, 100)
```

**Quan trọng**: Stack canary được đặt tại `[ebp-0x0C]`, ngay trước khi return về caller.

#### 3. Vòng Lặp Chính - Phân Tích Ký Tự

```assembly
loc_8049081:
.text:08049081  mov     edx, [ebp+var_84]    ; edx = i (index hiện tại)
.text:08049087  mov     eax, [ebp+var_8C]    ; eax = chuỗi input
.text:0804908D  add     eax, edx             ; eax = input[i]
.text:0804908F  movzx   eax, byte ptr [eax]  ; lấy byte tại input[i]
.text:08049092  movsx   eax, al             ; sign extend
.text:08049095  sub     eax, 30h             ; eax = input[i] - '0'
.text:08049098  cmp     eax, 9               ; so sánh với 9
.text:0804909B  jbe     loc_8049324          ; nếu <= 9 (là số) thì nhảy
```

**Logic**: Kiểm tra xem ký tự hiện tại có phải là số (0-9) không.

#### 4. Xử Lý Số - Tạo Chuỗi và Chuyển Đổi

Khi gặp ký tự không phải số:

```assembly
; Tính độ dài chuỗi số vừa đọc
.text:080490B1  mov     eax, [ebp+var_88]    ; con trỏ đầu số
.text:080490B7  sub     edx, eax             ; độ dài = vị trí hiện tại - vị trí đầu
.text:080490BB  mov     [ebp+var_7C], eax   ; lưu độ dài

; Malloc memory cho chuỗi số
.text:080490BE  mov     eax, [ebp+var_7C]
.text:080490C1  add     eax, 1               ; +1 cho null terminator
.text:080490C7  call    malloc               ; malloc(length + 1)
.text:080490CC  mov     [ebp+s1], eax       ; s1 = malloc result

; Copy chuỗi số
.text:080490E6  call    memcpy              ; memcpy(s1, start_pos, length)
.text:080490F3  mov     byte ptr [eax], 0   ; null terminate
```

#### 5. Kiểm Tra Division by Zero

```assembly
.text:080490F6  mov     dword ptr [esp+4], offset s2 ; "0"
.text:080490FE  mov     eax, [ebp+s1]
.text:08049104  call    _strcmp              ; strcmp(s1, "0")
.text:08049109  test    eax, eax
.text:0804910B  jnz     short loc_8049130
.text:0804910D  mov     dword ptr [esp], offset aPreventDivisio ; "prevent division by zero"
```

#### 6. Chuyển Đổi và Lưu Trữ Số

```assembly
.text:08049136  call    atoi                ; atoi(s1)
.text:0804913B  mov     [ebp+var_74], eax   ; var_74 = số nguyên

; Nếu số > 0, lưu vào mảng
.text:08049142  jle     short loc_8049164   ; nếu <= 0 thì bỏ qua
.text:08049144  mov     eax, [ebp+var_90]   ; eax = con trỏ tới count
.text:0804914A  mov     eax, [eax]          ; eax = *count
.text:0804914C  lea     ecx, [eax+1]        ; ecx = *count + 1
.text:0804914F  mov     edx, [ebp+var_90]   ; edx = con trỏ tới count
.text:08049155  mov     [edx], ecx          ; *count = *count + 1
.text:08049160  mov     [edx+eax*4+4], ecx  ; array[*count-1] = số
```

**Lỗ hổng ở đây**: `array[*count-1] = số` nhưng không kiểm tra bounds!

#### 7. Switch Statement - Xử Lý Toán Tử

```assembly
.text:08049217  sub     eax, 25h ; '%'       ; eax = char - '%'
.text:0804921A  cmp     eax, 0Ah             ; so sánh với 10
.text:0804921D  ja      def_804922A          ; > 10 thì default case
.text:08049223  mov     eax, ds:jpt_804922A[eax*4] ; jump table
.text:0804922A  jmp     eax                  ; nhảy tới case tương ứng
```

**Jump table xử lý**: `%` (37), `&` (38-41), `*` (42), `+` (43), `,` (44), `-` (45), `.` (46), `/` (47)

#### 8. Case '+' và '-' (Cao Nhất Priority)

```assembly
loc_804922C: ; cases 43(+), 45(-)
.text:08049234  movzx   eax, byte ptr [eax]  ; lấy toán tử từ s_func
.text:08049247  call    eval                 ; gọi eval với toán tử
.text:08049265  mov     [edx], al           ; lưu toán tử mới vào s_func
```

#### 9. Case '%', '*', '/' (Ưu Tiên Trung Bình)

```assembly
loc_804926C: ; cases 37(%), 42(*), 47(/)
; Kiểm tra xem toán tử trước có phải '+' hoặc '-'
.text:08049277  cmp     al, 2Bh ; '+'
.text:08049279  jz      short loc_804928A
.text:08049286  cmp     al, 2Dh ; '-'
.text:08049288  jnz     short loc_80492AB

loc_804928A:
.text:0804928A  add     [ebp+var_80], 1     ; tăng stack pointer
.text:08049307  mov     [edx], al           ; push toán tử mới
```

#### 10. Lỗ Hổng Stack Canary Bypass

### Kịch Bản Tấn Công với "+357"

1. **Khởi tạo**:
    
    - `count = 1` (trong main)
    - Stack canary tại offset 357 từ count
2. **Parsing "+"**:
    
    - Ký tự '+' được thêm vào `s_func`
    - `var_80 = 1` (stack depth)
3. **Parsing "357"**:
    
    ```assembly
    ; Sau atoi: var_74 = 357
    ; Lưu vào array: array[count] = 357, count++
    ; count = 2, array[1] = 357
    ```
    
4. **Kết thúc parsing - eval() được gọi**:
    
    ```assembly
    ; Trong eval: 
    ; count[*count-1] += count[*count] (cho toán tử '+')
    ; Tương đương: count[1] += count[2]
    ; Nhưng count[2] nằm ở offset tiếp theo trong stack!
    ```
    

##### Kịch Bản "+358" - Ghi Đè Canary

1. **Setup tương tự "+357"**
2. **Eval execution**:
    
    ```assembly
    ; count[1] = count[1] + count[2]; Nhưng count[2] trỏ tới vùng nhớ chứa canary!; canary_value = canary_value + 1; Stack smashing detected!
    ```
    

#### 11. Stack Canary Check Cuối Hàm

```assembly
.text:0804935F  mov     ebx, [ebp+var_C]     ; load stored canary
.text:08049362  xor     ebx, large gs:14h    ; XOR với canary hiện tại
.text:08049369  jz      short loc_8049370    ; nếu bằng nhau thì OK
.text:0804936B  call    __stack_chk_fail     ; ngược lại thì stack smashing!
```

#### 12. Tóm Tắt Lỗ Hổng

1. **Buffer overflow**: Không kiểm tra bounds khi ghi vào array
2. **Integer overflow**: Count có thể vượt quá giới hạn array
3. **Stack canary bypass**: Có thể đọc và modify canary value thông qua out-of-bounds access
4. **Information leak**: Có thể leak giá trị trên stack thông qua phép tính toán

**Nguyên nhân gốc**: Hàm không validate input size và không kiểm tra bounds của array trước khi ghi/đọc.
#### References:
https://0xfeebe.medium.com/calc-pwnable-tw-33e705adeee7




