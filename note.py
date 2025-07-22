#1. Thư viện  from passlib.context import CryptContext
# Cách dùng 
# pwd_context = CryptContext(schemes = ["bcrypt"] , deprecated = "auto")
## ====> Nó tạo ra một context để xử lý việc mã hóa (hash) và kiểm tra mật khẩu 

## Vai trò chính của pwd_context là : 
# 1. Mã hóa mật khẩu(hash) : Khi người dùng đăng kí hoặc đổi mật khẩu 
# 2. Xác minh mật khẩu : Khi người dùng đăng nhập (so sánh password với bản đã hash)

# Giải thích 
# schemes = ["bcrypt"]
# Cho biết thuật toán dùng để mã hóa mật khẩu bcrypt 

# deprecated="auto"
# Cho biết nếu sau này đổi thuật toán khác (ví dụ từ bcrypt sang argon2), thì passlib sẽ tự động đánh dấu những password cũ là deprecated.

# Giúp hệ thống tự nhận ra mật khẩu nào dùng thuật toán cũ và có thể cập nhật lại sau.


# Dùng thực tế 
# hashed = pwd_context.hash("mypassword")
# Kết quả chuỗi hash (không thể đảo ngược)
#$2b$12$ENePKNdGv6ADGtNkKkTkWe0MxrbgbVugPgbwce/uxIYV2xby.xZmu

#Xác minh mật khẩu (lúc đăng nhập)
# pwd_context.verify("mypassword", hashed)

# So sánh "mypassword" với mật khẩu trong DB trả về True hoặc False 


#🔐 Vì sao phải hash mật khẩu?
# Vì:

# Nếu lưu plain-text thì hacker lấy database là biết mật khẩu của tất cả user luôn.

# Hash là một chiều: không thể đảo ngược lại được (cùng 1 mật khẩu → luôn ra 1 hash khác nhau).


