package token

import (
	"context"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/text/gstr"
)

// 初始化参数
func NewBittoken(cacheKey string) *Token {
	ctx := gctx.New()
	return &Token{
		AuthExcludePaths: g.Cfg().MustGet(ctx, "BitToken.Exclude", "/login").Strings(),
		CacheKey:         cacheKey,
		Timeout:          g.Cfg().MustGet(ctx, "BitToken.Timeout", "1000").Int(),
		MaxRefresh:       g.Cfg().MustGet(ctx, "BitToken.Refresh", "1000").Int(),
		EncryptKey:       g.Cfg().MustGet(ctx, "BitToken.EncryptKey").Bytes(),
		MultiLogin:       g.Cfg().MustGet(ctx, "BitToken.MultiLogin").Bool(),
		TokenDelimiter:   "_",
	}
}

func (t *Token) ParsToken(r *ghttp.Request) (res *cacheRes, err error) {
	authHeader := r.Header.Get("Authorization")
	token := ""
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			return nil, gerror.New("token 格式异常")
		} else if parts[1] == "" {
			return nil, gerror.New("token为空")
		}

		token = parts[1]
	} else {
		token = r.Get("token").String()
		if token == "" {
			return nil, gerror.New("token为空")
		}
	}
	res, err = t.ValidToken(r.Context(), token)
	if err != nil {
		return
	}
	return
}

func (m *Token) AuthPath(ctx context.Context, urlPath string) bool {
	// 去除后斜杠
	if strings.HasSuffix(urlPath, "/") {
		urlPath = gstr.SubStr(urlPath, 0, len(urlPath)-1)
	}

	// 排除路径处理，到这里nextFlag为true
	for _, excludePath := range m.AuthExcludePaths {
		tmpPath := excludePath
		// 前缀匹配
		if strings.HasSuffix(tmpPath, "/*") {
			tmpPath = gstr.SubStr(tmpPath, 0, len(tmpPath)-2)
			if gstr.HasPrefix(urlPath, tmpPath) {
				// 前缀匹配不拦截
				return false
			}
		} else {
			// 全路径匹配
			if strings.HasSuffix(tmpPath, "/") {
				tmpPath = gstr.SubStr(tmpPath, 0, len(tmpPath)-1)
			}
			if urlPath == tmpPath {
				// 全路径匹配不拦截
				return false
			}
		}
	}

	return true
}
