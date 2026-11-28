package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// failInternal 返回固定的 500 提示，原始错误只挂到 gin 上下文供日志中间件记录，不进入响应体。
func failInternal(c *gin.Context, msg string, err error) {
	if err != nil {
		_ = c.Error(err)
	}
	Fail(c, http.StatusInternalServerError, msg)
}

// failWrite 处理写库失败：唯一约束冲突返回 409，其余按 failInternal 处理。
func failWrite(c *gin.Context, err error, conflictMsg, internalMsg string) {
	if isUniqueViolation(err) {
		Fail(c, http.StatusConflict, conflictMsg)
		return
	}
	failInternal(c, internalMsg, err)
}

// isUniqueViolation 判断写入是否因唯一约束冲突失败（MySQL 1062 / SQLite UNIQUE）。
// 并发注册或改绑时应用层的「先查后写」无法保证唯一，最终以数据库约束为准。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "Duplicate entry") || strings.Contains(msg, "Error 1062") ||
		strings.Contains(msg, "UNIQUE constraint failed")
}
