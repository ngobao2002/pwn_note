
`/proc/self/maps` là một file đặc biệt trong **Linux procfs** dùng để hiển thị **bản đồ không gian địa chỉ (memory map)** của **tiến trình hiện tại**.
## 📌 Nghĩa đơn giản

- `proc` = virtual filesystem chứa thông tin về tiến trình.
- `self` = alias trỏ đến **tiến trình đang đọc file** (chính nó).
- `maps` = file thể hiện tất cả các vùng nhớ mà tiến trình đang sử dụng.
Khi bạn đọc `/proc/self/maps`, bạn đang xem **memory layout** của chính chương trình đang chạy lệnh đó.

References
https://docs.kernel.org/filesystems/proc.html