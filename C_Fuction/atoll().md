```C
#include <stdlib.h>

long long int atoll(const char *str);
```
### 🔹 Chức năng:
- Hàm `atoll()` đọc **chuỗi số** trong `str` và **chuyển thành số nguyên kiểu `long long int`**.
- Nó **bỏ qua khoảng trắng đầu chuỗi**, **nhận dấu `+` hoặc `-`**, rồi đọc liên tiếp các chữ số cho đến khi gặp ký tự không phải số.
