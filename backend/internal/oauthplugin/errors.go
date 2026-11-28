package oauthplugin

// PublicError 表示可以原样展示给终端用户的联合登录错误；其余错误可能包含上游响应、请求地址或数据库细节，
// 调用方应只记录日志并返回通用提示。
type PublicError struct {
	msg string
}

func (e *PublicError) Error() string { return e.msg }

func publicErr(msg string) error { return &PublicError{msg: msg} }
