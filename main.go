package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

var (
	cfg        *Config
	err        error
	r          *gin.Engine
	store      cookie.Store
	keyPair    tls.Certificate
	ssoHandler *SSOHandler
)

func main() {

	if cfg, err = ParseConf(); err != nil {
		log.Fatal("invalid config: ", err)
	}

	gin.SetMode(gin.ReleaseMode)

	r = gin.Default()

	r.LoadHTMLGlob("templates/*")

	store = cookie.NewStore([]byte(cfg.SessionSecret))

	store.Options(sessions.Options{
		MaxAge:   cfg.MaxSessionAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	r.Use(sessions.Sessions("session", store))

	if ssoHandler, err = NewSSOHandler(cfg); err != nil {
		log.Fatal("failed to initiate the SSO handler instance: ", err)
	}

	r.GET("/", ssoHandler.Home)
	r.GET("/login", ssoHandler.LoginPage)
	r.GET("/auth/saml/login", ssoHandler.SAMLLogin)
	r.POST("/auth/saml/acs", ssoHandler.SAMLCallback)
	r.GET("/auth/saml/metadata", ssoHandler.SAMLMetadata)
	r.GET("/logout", ssoHandler.Logout)
	r.GET("/debug", ssoHandler.Debug)
	r.POST("/auth/saml/slo", ssoHandler.SAMLLogoutCallback)

	server := &http.Server{
		Addr:    strings.TrimPrefix(cfg.BaseURL, cfg.Scheme+"://"),
		Handler: r,
	}

	if cfg.Scheme == "https" {

		if keyPair, err = tls.LoadX509KeyPair("server.crt", "server.key"); err != nil {
			log.Fatalf("failed to load key pair: %v", err)
		}

		server.TLSConfig = &tls.Config{
			Certificates:       []tls.Certificate{keyPair},
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		log.Println("Server starting on " + cfg.BaseURL)

		if err = server.ListenAndServeTLS("", ""); err != nil {
			panic(fmt.Sprintf("Failed to start server: %v", err))
		}
	}

	log.Println("Server starting on " + cfg.BaseURL)

	server.ListenAndServe()

}
