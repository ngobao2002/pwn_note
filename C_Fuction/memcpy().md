##### Cú pháp:
```C
void *memcpy(void *dest, const void *src, size_t n);
```
- `dest`: con trỏ trỏ tới vùng nhớ đích (nơi dữ liệu sẽ được copy tới).
- `src`: con trỏ trỏ tới vùng nhớ nguồn (nơi lấy dữ liệu để copy).
- `n`: số byte cần sao chép.
Hàm trả về con trỏ `dest`.
#### Cách hoạt động
- `memcpy()` sẽ copy **chính xác `n` byte** từ địa chỉ bắt đầu của `src` sang địa chỉ bắt đầu của `dest`.
- Nó **không quan tâm dữ liệu bên trong là gì** (int, char, struct…), chỉ đơn giản coi đó là mảng byte.
- Tốc độ nhanh hơn vòng lặp `for` vì thường được tối ưu bằng lệnh máy (assembly).
##### Ví dụ:
```C
#include <stdio.h>
#include <string.h>

int main() {
    char src[10] = "ABCDEF";
    char dest[10];
    memcpy(dest, src, 6);  // copy 6 byte (kể cả ký tự '\0')
    printf("dest: %s\n", dest); // In ra "ABCDEF"
    return 0;
}
```
