package middleware

import (
	"net/url"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/pkg/sso/passport"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"strings"
)

// FrontendFileHandler 前端静态文件处理
func FrontendFileHandler(dep dependency.Dep) gin.HandlerFunc {
	fs := dep.ServerStaticFS()
	l := dep.Logger()

	ignoreFunc := func(c *gin.Context) {
		c.Next()
	}

	if fs == nil {
		return ignoreFunc
	}

	// 读取index.html
	file, err := fs.Open("/index.html")
	if err != nil {
		l.Warning("Static file \"index.html\" does not exist, it might affect the display of the homepage.")
		return ignoreFunc
	}

	fileContentBytes, err := io.ReadAll(file)
	if err != nil {
		l.Warning("Cannot read static file \"index.html\", it might affect the display of the homepage.")
		return ignoreFunc
	}
	fileContent := string(fileContentBytes)

	fileServer := http.FileServer(fs)
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		passportCfg := passport.LoadConfigFromEnv()

		// Skipping routers handled by backend
		if strings.HasPrefix(path, "/api") ||
			strings.HasPrefix(path, "/dav") ||
			strings.HasPrefix(path, "/f/") ||
			strings.HasPrefix(path, "/s/") ||
			path == "/manifest.json" {
			c.Next()
			return
		}

		// Force Passport SSO for login/register routes (server-side redirect for hard reload).
		if passportCfg.SSOOnly && passportCfg.Configured() && (path == "/session" || path == "/session/" || path == "/session/signup" || path == "/session/signup/") {
			target := constants.APIPrefix + "/session/sso/passport"
			if r := strings.TrimSpace(c.Request.URL.Query().Get("redirect")); r != "" {
				target = target + "?" + (url.Values{"redirect": []string{r}}).Encode()
			}
			c.Redirect(http.StatusFound, target)
			c.Abort()
			return
		}

		// 不存在的路径和index.html均返回index.html
		if (path == "/index.html") || (path == "/") || !fs.Exists("/", path) {
			// 读取、替换站点设置
			settingClient := dep.SettingProvider()
			siteBasic := settingClient.SiteBasic(c)
			pwaOpts := settingClient.PWA(c)
			theme := settingClient.Theme(c)
			finalHTML := util.Replace(map[string]string{
				"{siteName}":               siteBasic.Name,
				"{siteDes}":                siteBasic.Description,
				"{siteScript}":             siteBasic.Script,
				"{pwa_small_icon}":         pwaOpts.SmallIcon,
				"{pwa_medium_icon}":        pwaOpts.MediumIcon,
				"var(--defaultThemeColor)": theme.DefaultTheme,
			}, fileContent)

			if passportCfg.SSOOnly && passportCfg.Configured() {
				finalHTML = injectPassportSSOOnlyScript(finalHTML)
			}

			c.Header("Content-Type", "text/html")
			c.Header("Cache-Control", "public, no-cache")
			c.String(200, finalHTML)
			c.Abort()
			return
		}

		if path == "/sw.js" || strings.HasPrefix(path, "/locales/") {
			c.Header("Cache-Control", "public, no-cache")
		} else if strings.HasPrefix(path, "/assets/") {
			c.Header("Cache-Control", "public, max-age=31536000")
		}

		// 存在的静态文件
		fileServer.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}

func injectPassportSSOOnlyScript(html string) string {
	snippet := `<script>
(function () {
  try {
    var shouldRedirect = function (pathname) {
      return pathname === "/session" || pathname === "/session/" || pathname === "/session/signup" || pathname === "/session/signup/";
    };

    var buildTarget = function () {
      var params = new URLSearchParams(window.location.search || "");
      var redirect = params.get("redirect") || "";
      var target = "/api/v4/session/sso/passport";
      if (redirect) {
        target += "?redirect=" + encodeURIComponent(redirect);
      }
      return target;
    };

    var redirectIfNeeded = function () {
      try {
        if (!shouldRedirect(window.location.pathname)) return;
        window.location.replace(buildTarget());
      } catch (_) {}
    };

    var origPushState = history.pushState;
    history.pushState = function () {
      origPushState.apply(this, arguments);
      redirectIfNeeded();
    };

    var origReplaceState = history.replaceState;
    history.replaceState = function () {
      origReplaceState.apply(this, arguments);
      redirectIfNeeded();
    };

    window.addEventListener("popstate", redirectIfNeeded);
    redirectIfNeeded();
  } catch (_) {}
})();
</script>`

	if strings.Contains(html, "</body>") {
		return strings.Replace(html, "</body>", snippet+"</body>", 1)
	}

	return html + snippet
}
