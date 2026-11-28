package main

// isWeakSeedPassword 判断初始超级管理员口令是否为空或仓库中公开的默认值。
func isWeakSeedPassword(p string) bool {
	switch p {
	case "", "Admin@123456", "ChangeMe_Use_A_Strong_Password_1!":
		return true
	}
	return false
}
