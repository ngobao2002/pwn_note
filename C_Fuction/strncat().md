``` C
char *strncat(char *dest, const char *src, size_t n);
```
##### **Chức năng**
`strncat()` nối **tối đa n ký tự** từ chuỗi `src` vào **cuối** chuỗi `dest`,  sau đó luôn **thêm ký tự '\0'** để kết thúc chuỗi.
#### ⚠️ Lưu ý quan trọng (rất dễ gây lỗi)
##### **1. dest phải đủ vùng nhớ**
`strncat()` **không kiểm tra kích thước dest**, dễ gây **buffer overflow**.
Bạn phải tự đảm bảo:
``` C
strlen(dest) + n + 1 <= kích_thước_dest
```
##### **2. Hàm vẫn thêm '\0' → copy tối đa n+1 byte**
Nhiều người hiểu nhầm rằng nó copy đúng n byte — _nhưng thực tế nó thêm một byte null nữa._
##### **3. dest phải là chuỗi C hợp lệ**
	Nếu dest chưa có \0 , hàm sẽ chạy quá vùng nhớ.
	