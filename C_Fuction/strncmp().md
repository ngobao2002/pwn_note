```C
int strncmp(const char *s1, const char *s2, size_t n);
```
### Chức năng:
- So sánh **từng ký tự** của hai chuỗi `s1` và `s2`, tối đa `n` ký tự.
- Việc so sánh dừng lại khi:
    - Gặp ký tự khác nhau, hoặc
    - Đã so sánh đủ `n` ký tự, hoặc
    - Một trong hai chuỗi kết thúc (`'\0'`).