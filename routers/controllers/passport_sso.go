package controllers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/sso/passport"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
)

const passportRedirectDefault = "/home"

func shortToken(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}
	if len(val) <= 8 {
		return val
	}
	return val[:8] + "..."
}

func PassportSSOStart(c *gin.Context) {
	dep := dependency.FromContext(c)
	l := logging.FromContext(c)
	cfg := passport.LoadConfigFromEnv()
	if !cfg.Configured() {
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeNoPermissionErr, "Passport SSO is not configured", nil))
		return
	}

	c.Header("X-Correlation-ID", logging.CorrelationID(c).String())

	redirectPath := sanitizeRelativeRedirect(c.Query("redirect"))

	state, err := passport.GenerateState()
	if err != nil {
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeEncryptError, "Failed to generate SSO state", err))
		return
	}

	if err := dep.KV().Set(passport.StateKeyPrefix+state, redirectPath, passport.DefaultStateTTLSeconds); err != nil {
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeCacheOperation, "Failed to persist SSO state", err))
		return
	}

	siteURL := dep.SettingProvider().SiteURL(c)
	callbackURL, err := absoluteURL(siteURL, constants.APIPrefix+"/session/sso/passport/callback")
	if err != nil {
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeInternalSetting, "Failed to build callback url", err))
		return
	}

	restartURL, _ := absoluteURL(siteURL, "/session")
	l.Info("Passport SSO start: host=%q redirect=%q site_url=%q callback=%q passport_api=%q client_id=%q state=%q",
		c.Request.Host,
		redirectPath,
		siteURL.String(),
		callbackURL,
		cfg.APIBaseURL,
		cfg.ClientID,
		shortToken(state),
	)

	consentURL, err := passport.RequestConsent(c, cfg, passport.ConsentRequest{
		RedirectURI: callbackURL,
		Fields:      []string{"email", "nickname", "avatar_url", "preferred_language"},
		State:       state,
		RestartURI:  restartURL,
	})
	if err != nil {
		l.Warning("Passport SSO initiation failed: %s", err)
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeNoPermissionErr, "Failed to initiate Passport SSO", err))
		return
	}

	l.Info("Passport SSO start: redirecting to consent_url=%q", consentURL)
	c.Redirect(http.StatusFound, consentURL)
}

func PassportSSOCallback(c *gin.Context) {
	dep := dependency.FromContext(c)
	l := logging.FromContext(c)
	cfg := passport.LoadConfigFromEnv()
	if !cfg.Configured() {
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeNoPermissionErr, "Passport SSO is not configured", nil))
		return
	}

	c.Header("X-Correlation-ID", logging.CorrelationID(c).String())

	code := strings.TrimSpace(c.Query("code"))
	state := strings.TrimSpace(c.Query("state"))
	if code == "" || state == "" {
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeParamErr, "Missing code/state", nil))
		return
	}

	l.Info("Passport SSO callback: host=%q code=%q state=%q", c.Request.Host, shortToken(code), shortToken(state))

	redirRaw, ok := dep.KV().Get(passport.StateKeyPrefix + state)
	_ = dep.KV().Delete("", passport.StateKeyPrefix+state)
	if !ok {
		l.Warning("Passport SSO callback: invalid or expired state=%q", shortToken(state))
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeCredentialInvalid, "Invalid or expired SSO state", nil))
		return
	}

	redirectPath, _ := redirRaw.(string)
	redirectPath = sanitizeRelativeRedirect(redirectPath)
	l.Info("Passport SSO callback: resolved redirect=%q", redirectPath)

	profile, err := passport.ExchangeConsentCode(c, cfg, code)
	if err != nil {
		l.Warning("Passport SSO token exchange failed: %s", err)
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeNoPermissionErr, "SSO login failed", err))
		return
	}

	email := strings.ToLower(strings.TrimSpace(profile.Email))
	if email == "" {
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeNoPermissionErr, "SSO login missing email", nil))
		return
	}

	l.Info("Passport SSO callback: profile email=%q id=%q logto_id=%q", email, strings.TrimSpace(profile.ID), strings.TrimSpace(profile.LogtoID))

	userClient := dep.UserClient()
	u, err := userClient.GetByEmail(c, email)
	if err != nil {
		if ent.IsNotFound(err) {
			args := &inventory.NewUserArgs{
				Email:         email,
				Nick:          strings.TrimSpace(profile.Nickname),
				PlainPassword: "",
				Status:        entuser.StatusActive,
				GroupID:       dep.SettingProvider().DefaultGroup(c),
				Avatar:        strings.TrimSpace(profile.AvatarURL),
				Language:      strings.TrimSpace(profile.PreferredLanguage),
			}

			u, err = userClient.Create(c, args)
			if err != nil {
				c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeDBError, "Failed to create user", err))
				return
			}
			l.Info("Passport SSO callback: user created id=%d email=%q", u.ID, email)
		} else {
			c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeDBError, "Failed to query user", err))
			return
		}
	}

	l.Info("Passport SSO callback: user resolved id=%d email=%q", u.ID, email)

	switch u.Status {
	case entuser.StatusManualBanned, entuser.StatusSysBanned:
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeUserBaned, "This user is banned", nil))
		return
	case entuser.StatusInactive:
		u, err = userClient.SetStatus(c, u, entuser.StatusActive)
		if err != nil {
			c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeDBError, "Failed to activate user", err))
			return
		}
	}

	// Best-effort profile sync on each login.
	if nickname := strings.TrimSpace(profile.Nickname); nickname != "" && nickname != u.Nick {
		if updated, err := userClient.UpdateNickname(c, u, nickname); err == nil {
			u = updated
		}
	}
	if avatar := strings.TrimSpace(profile.AvatarURL); avatar != "" && avatar != u.Avatar {
		if updated, err := userClient.UpdateAvatar(c, u, avatar); err == nil {
			u = updated
		}
	}
	if lang := strings.TrimSpace(profile.PreferredLanguage); lang != "" {
		if u.Settings != nil && u.Settings.Language != lang {
			u.Settings.Language = lang
			_ = userClient.SaveSettings(c, u)
		}
	}

	token, err := dep.TokenAuth().Issue(c, u, nil)
	if err != nil {
		c.JSON(200, serializer.ErrWithDetails(c, serializer.CodeEncryptError, "Failed to issue token", err))
		return
	}

	login := usersvc.BuiltinLoginResponse{
		User:  usersvc.BuildUser(u, dep.HashIDEncoder()),
		Token: *token,
	}

	emitSSOCallbackHTML(c, login, redirectPath)
}

func emitSSOCallbackHTML(c *gin.Context, login usersvc.BuiltinLoginResponse, redirectPath string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("X-Content-Type-Options", "nosniff")

	loginJSON, _ := json.Marshal(login)
	loginB64 := base64.StdEncoding.EncodeToString(loginJSON)
	redirectJSON, _ := json.Marshal(redirectPath)

	html := fmt.Sprintf(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Signing in…</title>
  </head>
  <body>
    <script>
      (function () {
        try {
          const session = JSON.parse(atob(%q));
          const storageKey = "cloudreve_session";
          let state = { sessions: {}, anonymousSettings: {} };
          try {
            const raw = localStorage.getItem(storageKey);
            if (raw) state = JSON.parse(raw) || state;
          } catch (_) {}

          if (!state.sessions) state.sessions = {};
          if (!state.anonymousSettings) state.anonymousSettings = {};

          const existing = state.sessions[session.user.id];
          const existingSettings = existing && existing.settings ? existing.settings : {};
          state.sessions[session.user.id] = Object.assign({}, session, { settings: existingSettings });
          state.current = session.user.id;
          localStorage.setItem(storageKey, JSON.stringify(state));
        } catch (e) {}

        const target = %s;
        try {
          if (typeof target === "string" && target && target.startsWith("/") && !target.startsWith("//") && !target.includes("\\")) {
            window.location.replace(target);
            return;
          }
        } catch (_) {}
        window.location.replace(%q);
      })();
    </script>
  </body>
</html>`, loginB64, string(redirectJSON), passportRedirectDefault)

	c.String(http.StatusOK, html)
}

func sanitizeRelativeRedirect(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return passportRedirectDefault
	}

	// Disallow absolute redirects.
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return passportRedirectDefault
	}

	// Must be relative path.
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return passportRedirectDefault
	}

	if strings.ContainsAny(raw, "\r\n\\") {
		return passportRedirectDefault
	}

	// Avoid redirect loops back into SSO-only session routes.
	if raw == "/session" || raw == "/session/" || strings.HasPrefix(raw, "/session/") {
		return passportRedirectDefault
	}

	return raw
}

func absoluteURL(base *url.URL, path string) (string, error) {
	if base == nil {
		return "", errors.New("site url is not configured")
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(rel).String(), nil
}
