package token

import (
	"context"
	"fmt"
	"testing"

	"github.com/gogf/gf/v2/frame/g"
)

func Test_token(t *testing.T) {
	tokenCls := NewBittoken("admin")
	token, err := tokenCls.Generate(context.Background(), "test", g.Map{
		"username": "test",
		"phone":    "13800138000",
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(token)
	res, err := tokenCls.getToken(context.Background(), "test")
	fmt.Println(res, err)
}
