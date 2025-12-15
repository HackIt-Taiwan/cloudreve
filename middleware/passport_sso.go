package middleware

import (
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/sso/passport"
	"github.com/gin-gonic/gin"
)

// BlockBuiltinAuthWhenPassportSSOOnly blocks password/passkey/2FA related routes when
// PASSPORT_SSO_ONLY=true, forcing users to authenticate via Passport SSO.
func BlockBuiltinAuthWhenPassportSSOOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := passport.LoadConfigFromEnv()
		if cfg.SSOOnly && cfg.Configured() {
			c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeNoPermissionErr, "Please sign in with Passport SSO", nil))
			c.Abort()
			return
		}
		c.Next()
	}
}
