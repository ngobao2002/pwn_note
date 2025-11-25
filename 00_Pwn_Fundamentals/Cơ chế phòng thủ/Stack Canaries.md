Trình biên dịch đặt một giá trị ngẫu nhiên (gọi là "canary") trên stack ngay trước địa chỉ trả về. Trước khi một hàm kết thúc, nó sẽ kiểm tra xem giá trị canary có còn nguyên vẹn hay không.
- **Tác động:** Nếu một buffer overflow tuyến tính xảy ra, nó sẽ ghi đè lên canary. Khi hàm kiểm tra, nó sẽ phát hiện sự thay đổi và chấm dứt chương trình, ngăn chặn việc ghi đè lên địa chỉ trả về.
- **Sự tiến hóa của tấn công:** Kẻ tấn công phải tìm cách bypass canary. Các phương pháp bao gồm:
    1. **Leak canary:** Tìm một lỗ hổng khác (ví dụ: format string) để đọc giá trị của canary và sau đó ghi lại chính xác giá trị đó trong payload.
    2. **Ghi đè có chọn lọc:** Tìm cách ghi đè lên địa chỉ trả về mà không chạm vào canary (khó thực hiện).