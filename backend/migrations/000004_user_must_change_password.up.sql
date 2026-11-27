-- 强制改密标记：初始超级管理员与仍使用历史默认口令的存量管理员必须改密后才能访问业务接口。
ALTER TABLE users
    ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0 AFTER status;
