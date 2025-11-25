
**Binning**
Khi **malloc** giải phóng (free) một chunk, nó thường sẽ đưa chunk đó vào **một trong các danh sách bin** (giả sử nó không thể thực hiện hành động như hợp nhất chunk đó với **top chunk**). Sau đó, khi có một lần cấp phát (allocation) tiếp theo, **malloc** sẽ kiểm tra các bin để xem có chunk nào đã được giải phóng mà nó có thể tái sử dụng để phục vụ yêu cầu hay không.
Mục đích của cơ chế này là để **tái sử dụng các chunk đã free trước đó**, từ đó **cải thiện hiệu suất**.


**Glibc**
[Source](https://elixir.bootlin.com/glibc/glibc-2.42.9000/source)

References
http://blog.angelboy.tw/
