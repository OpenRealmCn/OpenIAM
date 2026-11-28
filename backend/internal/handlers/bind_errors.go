package handlers

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-playground/validator/v10"
)

// bindFieldLabels 把请求结构体字段名映射为控制台展示用的中文名称。
var bindFieldLabels = map[string]string{
	"Code":         "编码",
	"Name":         "名称",
	"DisplayName":  "显示名称",
	"Description":  "描述",
	"Username":     "用户名",
	"Password":     "密码",
	"NewPassword":  "新密码",
	"Email":        "邮箱",
	"Phone":        "手机号",
	"Title":        "标题",
	"Content":      "内容",
	"Subject":      "主题",
	"Body":         "正文",
	"Channel":      "发送渠道",
	"Type":         "类型",
	"Level":        "级别",
	"Sub":          "主体",
	"Obj":          "资源",
	"Act":          "操作",
	"Dom":          "域",
	"Domain":       "域",
	"DomainCode":   "域编码",
	"Resource":     "资源",
	"Action":       "操作",
	"Permissions":  "权限",
	"PluginType":   "插件类型",
	"Config":       "配置",
	"ProviderName": "身份源标识",
	"ClientID":     "Client ID",
	"ClientSecret": "Client Secret",
	"Settings":     "设置项",
}

// bindError 把 gin 参数绑定错误翻译成用户能看懂的中文提示，不透出结构体名和校验标签。
func bindError(err error) string {
	var ves validator.ValidationErrors
	if errors.As(err, &ves) && len(ves) > 0 {
		fe := ves[0]
		label, ok := bindFieldLabels[fe.Field()]
		if !ok {
			label = fe.Field()
		}
		switch fe.Tag() {
		case "required":
			return fmt.Sprintf("请填写%s", label)
		case "min":
			return fmt.Sprintf("%s至少需要 %s 个字符", label, fe.Param())
		case "max", "maxbytes":
			return fmt.Sprintf("%s过长，请缩短后重试", label)
		case "len":
			return fmt.Sprintf("%s应为 %s 位", label, fe.Param())
		case "email":
			return fmt.Sprintf("%s格式无效", label)
		case "oneof":
			return fmt.Sprintf("%s的取值无效", label)
		default:
			return fmt.Sprintf("%s格式无效", label)
		}
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return "提交的数据类型不正确，请刷新页面后重试"
	}
	return "提交的数据格式不正确，请刷新页面后重试"
}
