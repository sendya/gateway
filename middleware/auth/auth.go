package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	v1 "github.com/go-kratos/gateway/api/gateway/middleware/auth/v1"
	"github.com/go-kratos/gateway/middleware"
)

const (

	// bearerWord the bearer key word for authorization
	bearerWord string = "Bearer"

	// bearerFormat authorization token format
	bearerFormat string = "Bearer %s"

	// authorizationKey holds the key used to store the JWT Token in the request tokenHeader.
	authorizationKey string = "Authorization"

	// reason holds the error reason.
	reason string = "UNAUTHORIZED"
)

var (
	ErrMissingJwtToken        = errors.Unauthorized(reason, "JWT token is missing")
	ErrMissingKeyFunc         = errors.Unauthorized(reason, "keyFunc is missing")
	ErrTokenInvalid           = errors.Unauthorized(reason, "Token is invalid")
	ErrTokenExpired           = errors.Unauthorized(reason, "JWT token has expired")
	ErrTokenParseFail         = errors.Unauthorized(reason, "Fail to parse JWT token ")
	ErrUnSupportSigningMethod = errors.Unauthorized(reason, "Wrong signing method")
	ErrWrongContext           = errors.Unauthorized(reason, "Wrong context for middleware")
	ErrNeedTokenProvider      = errors.Unauthorized(reason, "Token provider is missing")
	ErrSignToken              = errors.Unauthorized(reason, "Can not sign token.Is the key correct?")
	ErrGetKey                 = errors.Unauthorized(reason, "Can not get key while signing token")
)

func init() {
	middleware.Register("auth", Middleware)
}

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	options := &v1.Auth{
		AuthorizationKey: "Authorization",
		SecretKey:        "gateway-secret",
		SigningMethod:    "HS256",
	}
	if c.Options != nil {
		if err := anypb.UnmarshalTo(c.Options, options, proto.UnmarshalOptions{Merge: true}); err != nil {
			return nil, err
		}
	}

	signingMethod := jwt.GetSigningMethod(options.SigningMethod)
	if signingMethod == nil {
		return nil, fmt.Errorf("signing method %s is not supported, allowed %+v", options.SigningMethod, jwt.GetAlgorithms())
	}

	keyProvider := func(token *jwt.Token) (interface{}, error) {
		return []byte(options.SecretKey), nil
	}

	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			claims := jwt.RegisteredClaims{}

			auths := strings.SplitN(req.Header.Get(options.AuthorizationKey), " ", 2)
			if len(auths) != 2 || !strings.EqualFold(auths[0], bearerWord) {
				return nil, ErrMissingJwtToken
			}

			tokenInfo, err := jwt.ParseWithClaims(auths[1], &claims, keyProvider)
			if err != nil {
				ve, ok := err.(*jwt.ValidationError)
				if !ok {
					return nil, errors.Unauthorized(reason, err.Error())
				}
				if ve.Errors&jwt.ValidationErrorMalformed != 0 {
					return nil, ErrTokenInvalid
				}
				if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
					return nil, ErrTokenExpired
				}
				return nil, ErrTokenParseFail
			}

			if !tokenInfo.Valid {
				return nil, ErrTokenInvalid
			}
			if tokenInfo.Method != signingMethod {
				return nil, ErrUnSupportSigningMethod
			}

			resp, err := next.RoundTrip(req)
			if err != nil {
				return nil, err
			}

			return resp, nil
		})
	}, nil
}
