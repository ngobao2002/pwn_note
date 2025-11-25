
`memset()` **ghi một giá trị byte vào một vùng nhớ**. Dùng rất phổ biến để khởi tạo hoặc xóa buffer.
``` C
void *memset(void *s, int c, size_t n);
```
### Tham số
- `s` — con trỏ tới vùng nhớ đích.
- `c` — giá trị (kiểu `int`) sẽ được _ép về `unsigned char`_ rồi lặp `n` lần.
- `n` — số byte sẽ ghi.