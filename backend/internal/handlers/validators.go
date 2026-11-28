package handlers

import (
	"strconv"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

func init() {
	// maxbytes=N：按 UTF-8 字节数限制长度。bcrypt 只接受最长 72 字节的口令，
	// 而 validator 自带的 max 按字符数计算，含中文或 emoji 的口令会绕过校验后在哈希阶段失败。
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		_ = v.RegisterValidation("maxbytes", func(fl validator.FieldLevel) bool {
			limit, err := strconv.Atoi(fl.Param())
			if err != nil {
				limit = 72
			}
			return len(fl.Field().String()) <= limit
		})
	}
}
