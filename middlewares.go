package auth

import (
	"github.com/Sanchous98/project-confucius-base/stdlib"
	"github.com/dgrijalva/jwt-go"
	"github.com/valyala/fasthttp"
	"strings"
)

const (
	corsAllowHeaders     = "authorization"
	corsAllowMethods     = "HEAD,GET,POST,PUT,DELETE,OPTIONS"
	corsAllowOrigin      = "*"
	corsAllowCredentials = "true"
	defaultRealm         = "API"
)

type AuthenticationFunc func(*fasthttp.RequestCtx) bool
type JWTTokenHandler func(*fasthttp.RequestCtx, *jwt.Token) error
type VerificationKeyHandler func(ctx *fasthttp.RequestCtx) string

func CORS(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Access-Control-Allow-Credentials", corsAllowCredentials)
		ctx.Response.Header.Set("Access-Control-Allow-Headers", corsAllowHeaders)
		ctx.Response.Header.Set("Access-Control-Allow-Methods", corsAllowMethods)
		ctx.Response.Header.Set("Access-Control-Allow-Origin", corsAllowOrigin)

		next(ctx)
	}
}

func NewAuthMiddleware(authFunc AuthenticationFunc) stdlib.Middleware {
	return func(h fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			if authFunc(ctx) {
				h(ctx)
			} else {
				ctx.Response.SetStatusCode(fasthttp.StatusUnauthorized)
			}
		}
	}
}

// JWTOptions represents the options that can be used with the JWT handler.
type JWTOptions struct {
	// auth realm. Defaults to "API".
	Realm string
	// the allowed signing method. This is required and should be the actual method that you use to create JWT token. It defaults to "HS256".
	SigningMethod string
	// a function that handles the parsed JWT token. Defaults to DefaultJWTTokenHandler, which stores the token in the routing context with the key "JWT".
	TokenHandler JWTTokenHandler
	// a function to get a dynamic VerificationKey
	GetVerificationKey VerificationKeyHandler
}

func JWT(verificationKey string, options ...JWTOptions) fasthttp.RequestHandler {
	var opt JWTOptions
	if len(options) > 0 {
		opt = options[0]
	}
	if opt.Realm == "" {
		opt.Realm = defaultRealm
	}
	if opt.SigningMethod == "" {
		opt.SigningMethod = "HS256"
	}
	if opt.TokenHandler == nil {
		opt.TokenHandler = DefaultJWTTokenHandler
	}
	parser := &jwt.Parser{
		ValidMethods: []string{opt.SigningMethod},
	}
	return func(c *fasthttp.RequestCtx) {
		header := string(c.Request.Header.Peek("Authorization"))
		if opt.GetVerificationKey != nil {
			verificationKey = opt.GetVerificationKey(c)
		}
		if strings.HasPrefix(header, "Bearer ") {
			token, err := parser.Parse(header[7:], func(t *jwt.Token) (interface{}, error) {
				return []byte(verificationKey), nil
			})
			if err == nil && token.Valid {
				err = opt.TokenHandler(c, token)
			}
			if err == nil {
				return
			}

		}

		c.Response.Header.Set("WWW-Authenticate", `Bearer realm="`+opt.Realm+`"`)
	}
}

// NewJWT creates a new JWT token and returns it as a signed string that may be sent to the client side.
// The signingMethod parameter is optional. It defaults to the HS256 algorithm.
func NewJWT(claims jwt.Claims, signingKey string, signingMethod ...jwt.SigningMethod) (string, error) {
	var sm jwt.SigningMethod = jwt.SigningMethodHS256
	if len(signingMethod) > 0 {
		sm = signingMethod[0]
	}
	return jwt.NewWithClaims(sm, claims).SignedString([]byte(signingKey))
}

// DefaultJWTTokenHandler stores the parsed JWT token in the routing context with the key named "JWT".
func DefaultJWTTokenHandler(c *fasthttp.RequestCtx, token *jwt.Token) error {
	c.SetUserValue("JWT", token)
	return nil
}
