package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type PagedResult struct {
	Items interface{} `json:"items"`
	Total int64       `json:"total"`
	Page  int         `json:"page"`
	Size  int         `json:"page_size"`
}

func OK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Code:    0,
		Message: "ok",
		Data:    data,
	})
}

func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, APIResponse{
		Code:    0,
		Message: "created",
		Data:    data,
	})
}

func Fail(c *gin.Context, status int, msg string) {
	c.JSON(status, APIResponse{
		Code:    status,
		Message: msg,
	})
}

func ParsePagination(c *gin.Context) (page, size, offset int) {
	page = 1
	size = 20
	if p, err := strconv.Atoi(c.DefaultQuery("page", "1")); err == nil && p > 0 && p <= 10000 {
		page = p
	}
	if s, err := strconv.Atoi(c.DefaultQuery("page_size", "20")); err == nil && s > 0 && s <= 200 {
		size = s
	}
	offset = (page - 1) * size
	return
}

func CurrentUserID(c *gin.Context) uint64 {
	if v, ok := c.Get("user_id"); ok {
		if id, ok2 := v.(uint64); ok2 {
			return id
		}
	}
	return 0
}

func CurrentUsername(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}
