Cơ chế này tăng cường bảo vệ cho các bảng địa chỉ động như Global Offset Table (GOT).
- **Partial RELRO (Mặc định):** Section `.got.plt` vẫn có thể ghi được, cho phép kỹ thuật "GOT Overwrite" kinh điển, nơi kẻ tấn công ghi đè một entry trong GOT (ví dụ: `puts@got`) bằng địa chỉ của `system`.
- **Full RELRO:** Toàn bộ GOT được đánh dấu là chỉ đọc (`read-only`) sau khi nạp.
- **Tác động:** Full RELRO làm cho việc ghi đè GOT trở nên bất khả thi, buộc kẻ tấn công phải tìm các mục tiêu ghi đè khác, chẳng hạn như các hook (`__malloc_hook`, `__free_hook`) hoặc các con trỏ hàm khác trong bộ nhớ.