	
``` C
char *strncpy(char *dest, const char *src, size_t n);
```
- `dest`: bộ đệm đích (buffer) để ghi dữ liệu vào
- `src`: chuỗi nguồn
- `n`: số ký tự tối đa được sao chép
## 📌 Nó hoạt động như thế nào?

- Sao chép **tối đa n ký tự** từ `src` sang `dest`.
- Nếu `src` **ngắn hơn n**, các ký tự còn lại trong `dest` được **padding bằng `\0`** (null byte).
- Nếu `src` **dài hơn hoặc bằng n**, thì **KHÔNG thêm `\0`** vào cuối `dest`.