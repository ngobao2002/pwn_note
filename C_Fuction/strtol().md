Hàm **`strtol()`** trong C dùng để **chuyển đổi một chuỗi ký tự (`string`) thành một số nguyên kiểu `long int`**, đồng thời cho phép kiểm soát **hệ cơ số (base)** và **vị trí dừng lại trong chuỗi** sau khi đọc xong phần số.

``` C
long int strtol(const char *str, char **endptr, int base);
```

| Tham số  | Mô tả                                                                                                                                                                                                                                                                   |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `str`    | Chuỗi đầu vào cần chuyển đổi, ví dụ `"123abc"`.                                                                                                                                                                                                                         |
| `endptr` | Con trỏ tới con trỏ kiểu `char`. Sau khi hàm thực thi, `*endptr` sẽ trỏ đến **ký tự đầu tiên sau phần số hợp lệ** trong chuỗi. Nếu bạn không cần, có thể truyền `NULL`.                                                                                                 |
| base     | Hệ cơ số của số cần chuyển đổi (2 → nhị phân, 8 → bát phân, 10 → thập phân, 16 → thập lục phân...). Nếu `base = 0`, `strtol` sẽ **tự đoán** dựa trên tiền tố:<br>- `0x` hoặc `0X` → hệ 16 (hexadecimal)<br>- `0` → hệ 8 (octal)<br>- không có tiền tố → hệ 10 (decimal) |










