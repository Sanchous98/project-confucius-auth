package auth

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"testing"
)

func TestJWT(t *testing.T) {
	secret := "secret-key"
	{
		// valid token
		tokenString, err := NewJWT(jwt.MapClaims{
			"id": "100",
		}, secret)
		assert.Nil(t, err)

		h := JWT(secret)
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetMethod("GET")
		ctx.Request.SetRequestURI("/users/")
		ctx.Request.Header.Set("Authorization", "Bearer "+tokenString)
		h(&ctx)
		token := ctx.UserValue("JWT")
		if assert.NotNil(t, token) {
			assert.Equal(t, "100", token.(*jwt.Token).Claims.(jwt.MapClaims)["id"])
		}
	}

	{
		// invalid token
		h := JWT("secret")
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetMethod("GET")
		ctx.Request.SetRequestURI("/users/")
		ctx.Request.Header.Set("Authorization", "Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
		h(&ctx)
		assert.Equal(t, `Bearer realm="API"`, string(ctx.Response.Header.Peek("WWW-Authenticate")))
		assert.Nil(t, ctx.UserValue("JWT"))
	}

	{
		// invalid token with options
		h := JWT("secret", JWTOptions{
			Realm: "App",
		})
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetMethod("GET")
		ctx.Request.SetRequestURI("/users/")
		ctx.Request.Header.Set("Authorization", "Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
		h(&ctx)
		assert.Equal(t, `Bearer realm="App"`, string(ctx.Response.Header.Peek("WWW-Authenticate")))
		assert.Nil(t, ctx.UserValue("JWT"))
	}
}
