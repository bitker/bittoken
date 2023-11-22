package token

import (
	"context"

	"github.com/gogf/gf/v2/crypto/gaes"
	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/encoding/gbase64"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/gogf/gf/v2/util/grand"
)

type Token struct {
	TokenDelimiter string

	AuthExcludePaths []string //排除项
	// 缓存key
	CacheKey string
	// 超时时间 默认10天（毫秒）
	Timeout int
	// 缓存刷新时间 默认为超时时间的一半（毫秒）
	MaxRefresh int
	// Token加密key
	EncryptKey []byte
	// 是否支持多端登录，默认false
	MultiLogin bool
}

type tokenRes struct {
	Uuid  string
	Key   string
	Token string
}

type cacheRes struct {
	Key       string
	Uuid      string
	Data      interface{}
	CreatedAt int64
	RefreshAt int64
}

// 解密返回
type decryptRes struct {
	Key  string
	Uuid string
}

// 生成TOKEN
func (t *Token) Generate(ctx context.Context, userKey string, data interface{}) (token string, err error) {

	if t.MultiLogin {
		// 支持多端重复登录，返回相同token 通过userkey获取数据然后生成相同TOKEN
		res, err := t.getToken(ctx, userKey)
		if err == nil {
			tokenRes, err := t.EncryptToken(ctx, userKey, res.Uuid)
			if err == nil {
				return tokenRes.Token, nil
			}
		}

	}
	res, err := t.EncryptToken(ctx, userKey, "")

	if err != nil {
		return
	}
	//进行缓存
	cacheKey := t.CacheKey + userKey
	userCache := &cacheRes{
		Key:       userKey,
		Uuid:      res.Uuid,
		Data:      data,
		CreatedAt: gtime.Now().TimestampMilli(),
		RefreshAt: gtime.Now().TimestampMilli() + gconv.Int64(t.MaxRefresh),
	}

	token = res.Token
	err = t.setCache(ctx, cacheKey, userCache)

	return
}

// 加密返回token结构体
func (t *Token) EncryptToken(ctx context.Context, userKey string, uuid string) (Res *tokenRes, err error) {
	if userKey == "" {
		return
	}

	if uuid == "" {
		// 重新生成uuid
		newUuid, err := gmd5.Encrypt(grand.Letters(10))
		if err != nil {
			return nil, err
		}
		uuid = newUuid
	}

	tokenStr := userKey + t.TokenDelimiter + uuid

	token, err := gaes.Encrypt([]byte(tokenStr), t.EncryptKey)
	if err != nil {
		return
	}

	return &tokenRes{
		Uuid:  uuid,
		Key:   userKey,
		Token: gbase64.EncodeToString(token),
	}, nil
}

// DecryptToken token解密方法
func (m *Token) DecryptToken(ctx context.Context, token string) (res *decryptRes, err error) {
	if token == "" {
		return
	}

	token64, err := gbase64.Decode([]byte(token))
	if err != nil {
		return
	}
	decryptToken, err := gaes.Decrypt(token64, m.EncryptKey)
	if err != nil {
		return
	}
	tokenArray := gstr.Split(string(decryptToken), m.TokenDelimiter)
	if len(tokenArray) < 2 {
		err = gerror.New("token异常")
		return
	}
	return &decryptRes{Key: tokenArray[0], Uuid: tokenArray[1]}, nil
}

// getToken 通过userKey获取Token
func (t *Token) getToken(ctx context.Context, userKey string) (res *cacheRes, err error) {
	cacheKey := t.CacheKey + userKey

	userCacheResp, err := t.getCache(ctx, cacheKey)
	if err != nil {
		return
	}

	nowTime := gtime.Now().TimestampMilli()
	refreshTime := userCacheResp.RefreshAt

	// 需要进行缓存超时时间刷新
	if gconv.Int64(refreshTime) == 0 || nowTime > gconv.Int64(refreshTime) {
		userCacheResp.CreatedAt = gtime.Now().TimestampMilli()
		userCacheResp.RefreshAt = gtime.Now().TimestampMilli() + gconv.Int64(t.MaxRefresh)
		err = t.setCache(ctx, cacheKey, userCacheResp)
		if err != nil {
			return
		}
	}

	return userCacheResp, nil
}

func (t *Token) setCache(ctx context.Context, cacheKey string, userCache *cacheRes) error {
	cacheValueJson, err := gjson.Encode(userCache)
	if err != nil {
		return err
	}
	_, err = g.Redis().Do(ctx, "SETEX", cacheKey, t.Timeout/1000, cacheValueJson)
	if err != nil {
		return err
	}
	return nil
}
func (t *Token) getCache(ctx context.Context, cacheKey string) (res *cacheRes, err error) {
	userCacheJson, err := g.Redis().Do(ctx, "GET", cacheKey)
	if err != nil {
		return
	}
	if userCacheJson.IsNil() {
		err = gerror.New("login timeout or not login")
		return
	}
	err = gjson.DecodeTo(userCacheJson, &res)
	return
}

// validToken 验证Token
func (t *Token) ValidToken(ctx context.Context, token string) (res *cacheRes, err error) {
	if token == "" {
		err = gerror.New("token is empty")
		return
	}

	decryptToken, err := t.DecryptToken(ctx, token)
	if err != nil {
		return
	}

	userKey := decryptToken.Key
	uuid := decryptToken.Uuid

	userCacheResp, err := t.getToken(ctx, userKey)
	if err != nil {
		return
	}

	if uuid != userCacheResp.Uuid {
		err = gerror.New("token 异常")
		return
	}

	return userCacheResp, nil
}
