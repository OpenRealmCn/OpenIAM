package response

import "github.com/gin-gonic/gin"

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func Data(c *gin.Context, status int, data any) {
	c.JSON(status, gin.H{
		"data":      data,
		"requestId": c.GetString("request_id"),
	})
}

func Error(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{
		"error": ErrorBody{
			Code:    code,
			Message: message,
		},
		"requestId": c.GetString("request_id"),
	})
}
