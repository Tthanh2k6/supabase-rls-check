# Kiểm tra bảo mật Supabase

todo-ai (demo giả lập)

Có 3 phát hiện cần rà soát. Ưu tiên mức nghiêm trọng và cao. Cảnh báo cấu hình không tự chứng minh việc lộ dữ liệu hoặc quyền ghi.

Nghiêm trọng: 0 / Cao: 2 / Trung bình: 1 / Thấp: 0

Kiểm tra giới hạn trên metadata được cung cấp và/hoặc phép đọc ẩn danh. Không chứng nhận bảo mật. Kết quả rỗng không chứng minh an toàn. Dữ liệu công khai có thể là chủ đích. Không lưu giá trị dòng hoặc khóa.

## Các phát hiện

| Mức độ | Phát hiện / đối tượng | Bằng chứng | Cách sửa |
| --- | --- | --- | --- |
| Cao | Policy có điều kiện luôn đúng — public.profiles | policy_true: read_every_profile | Rà lệnh, role và tổ hợp policy; thay policy cấp quyền quá rộng. |
| Cao | Chưa bật bảo mật cấp dòng — public.todos | rls_disabled | Bật RLS, rà quyền truy cập và policy chủ sở hữu trước khi phát hành. |
| Trung bình | Bucket Storage công khai — storage.todo-attachments | public_bucket | Xác nhận mục đích công khai; chuyển riêng tư nếu nhạy cảm và rà policy storage.objects. |

## Phạm vi và giới hạn

- Chỉ bao phủ đầu vào được cung cấp; phần chưa kiểm tra vẫn chưa rõ.

## Bước tiếp theo

Rà fix.sql trên staging; xuất policy/quyền hiện tại để khôi phục. Khuyến nghị chủ dự án tự kiểm ghi bằng SQL và kiểm tra cách ly hai người dùng. Chạy lại sau khi sửa. Công cụ không thực hiện kiểm ghi.
