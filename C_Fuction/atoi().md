Hàm `atoi()` trong C được dùng để **chuyển một chuỗi ký tự (string)** thành **số nguyên kiểu `int`**.
``` C
int atoi(const char *str);
```
- **`str`**: là chuỗi chứa các ký tự số, ví dụ `"123"`, `" -45"`, `"0"`, v.v.
- **Giá trị trả về**: số nguyên tương ứng với chuỗi đó.  
    Nếu chuỗi không bắt đầu bằng một phần có thể chuyển thành số, hàm trả về **0**.
#### Lưu ý:
- `atoi()` **không kiểm tra lỗi**. Nếu chuỗi không hợp lệ, nó **trả về 0** — nên bạn không biết là lỗi thật hay chuỗi `"0"`.