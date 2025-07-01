package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/beevik/etree"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

type SSOHandler struct {
	samlSP *saml2.SAMLServiceProvider
	cfg    *Config
}

type UserInfo struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	AuthMethod    string                 `json:"auth_method"`
	SessionExpiry time.Time              `json:"session_expiry"`
	RawClaims     map[string]interface{} `json:"raw_claims"`
}

func NewSSOHandler(cfg *Config) (*SSOHandler, error) {
	var (
		err         error
		httpC       *http.Client
		keyPair     tls.Certificate
		idpCert     *x509.Certificate
		metadataXML []byte
		samlSP      *saml2.SAMLServiceProvider
	)

	httpC = &http.Client{}

	if keyPair, err = tls.LoadX509KeyPair("server.crt", "server.key"); err != nil {
		return nil, fmt.Errorf("failed to load key pair: %v", err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	if cfg.Scheme == "https" {
		tlsConfig := &tls.Config{
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
		httpC = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}

	// Shared certStore and metadata loading
	if metadataXML, err = fetchMetadataXML(httpC, cfg.SAMLMetadataURL); err != nil {
		return nil, fmt.Errorf("failed to fetch SAML metadata: %v", err)
	}

	if idpCert, err = extractCertificateFromMetadata(metadataXML); err != nil {
		return nil, fmt.Errorf("failed to extract certificate from metadata: %v", err)
	}

	certStore = dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	}

	samlSP = &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      fmt.Sprintf("%s/realms/%s/protocol/saml", cfg.KeycloakURL, cfg.Realm),
		IdentityProviderSLOURL:      fmt.Sprintf("%s/realms/%s/protocol/saml", cfg.KeycloakURL, cfg.Realm),
		IdentityProviderIssuer:      fmt.Sprintf("%s/realms/%s", cfg.KeycloakURL, cfg.Realm),
		ServiceProviderIssuer:       cfg.SAMLEntityID,
		AssertionConsumerServiceURL: cfg.BaseURL + "/auth/saml/acs",
		AudienceURI:                 cfg.SAMLEntityID,
		IDPCertificateStore:         &certStore,
		SignAuthnRequests:           true,
		SPKeyStore:                  dsig.TLSCertKeyStore(keyPair),
		SPSigningKeyStore:           dsig.TLSCertKeyStore(keyPair),
		AllowMissingAttributes:      false,
		NameIdFormat:                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		ServiceProviderSLOURL:       fmt.Sprintf("%s/auth/saml/slo", cfg.BaseURL),
	}

	return &SSOHandler{
		samlSP: samlSP,
		cfg:    cfg,
	}, nil
}

func (h *SSOHandler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"keycloakURL": h.cfg.KeycloakURL,
		"realm":       h.cfg.Realm,
	})
}

func (h *SSOHandler) SAMLLogin(c *gin.Context) {
	var (
		authURL    string
		err        error
		session    = sessions.Default(c)
		relayState = generateRandomString(32)
	)

	if authURL, err = h.samlSP.BuildAuthURL(relayState); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to build SAML auth URL",
			"debug": err.Error(),
		})
		return
	}

	session.Set("saml_request_relay", relayState)

	if err = session.Save(); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to save SAML request ID",
			"debug": err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, authURL)
}

func (h *SSOHandler) SAMLCallback(c *gin.Context) {

	var (
		session       = sessions.Default(c)
		storedRelay   = session.Get("saml_request_relay")
		err           error
		samlResponse  string
		res           *types.Response
		relayState    = c.PostForm("RelayState")
		assertionInfo *saml2.AssertionInfo
		userInfoJSON  []byte
	)

	if c.PostForm("SAMLResponse") == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "No SAML response received",
		})
		return
	}

	samlResponse = c.PostForm("SAMLResponse")

	if res, err = h.samlSP.ValidateEncodedResponse(samlResponse); err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Invalid SAML response",
			"debug": err.Error(),
		})
		return
	}

	if storedRelay == nil {
		return
	}

	if storedRelay.(string) != relayState {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Invalid SAML Relay State",
			"debug": "Possible attack",
		})
		return
	}

	if res.Destination != "" && res.Destination != h.samlSP.AssertionConsumerServiceURL {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Invalid SAML destination",
			"debug": fmt.Sprintf("Expected: %s, Got: %s",
				h.samlSP.AssertionConsumerServiceURL,
				res.Destination),
		})
		return
	}

	if res.Issuer == nil || res.Issuer.Value != h.samlSP.IdentityProviderIssuer {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Invalid SAML issuer",
			"debug": fmt.Sprintf("Expected: %s, Got: %s",
				h.samlSP.IdentityProviderIssuer,
				safeGetIssuer(res.Issuer)),
		})
		return
	}

	if res.Status == nil || res.Status.StatusCode == nil ||
		res.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		status := "unknown"
		if res.Status != nil && res.Status.StatusCode != nil {
			status = res.Status.StatusCode.Value
		}
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "SAML response not successful",
			"debug": fmt.Sprintf("Status: %s", status),
		})
		return
	}

	if assertionInfo, err = h.samlSP.RetrieveAssertionInfo(samlResponse); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to process SAML assertion",
			"debug": err.Error(),
		})
		return
	}

	if assertionInfo.SessionNotOnOrAfter.Before(time.Now().Local()) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "SAML assertion has expired",
		})
		return
	}

	session.Set("saml_session_index", assertionInfo.SessionIndex)
	session.Set("saml_name_id", assertionInfo.NameID)

	session.Delete("saml_request_relay")

	userInfo := &UserInfo{
		ID:            assertionInfo.NameID,
		Email:         getSAMLAttribute(assertionInfo, "email"),
		AuthMethod:    "SAML",
		SessionExpiry: time.Now().Local().Add(time.Second * time.Duration(h.cfg.MaxSessionAge)),
		RawClaims:     convertSAMLAttributes(assertionInfo),
	}

	if userInfoJSON, err = json.Marshal(userInfo); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to marshal user info",
			"debug": err.Error(),
		})
		return
	}

	session.Set("user_info", string(userInfoJSON))

	if err := session.Save(); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to save user session",
			"debug": err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/")
}

func (h *SSOHandler) SAMLMetadata(c *gin.Context) {
	var (
		metadata *types.EntityDescriptor
		err      error
		xmlData  []byte
	)

	if metadata, err = h.samlSP.Metadata(); err != nil {
		c.String(http.StatusInternalServerError, "Failed to generate metadata: %v", err)
		return
	}

	if xmlData, err = xml.MarshalIndent(metadata, "", "  "); err != nil {
		c.String(http.StatusInternalServerError, "Failed to marshal metadata: %v", err)
		return
	}

	c.Header("Content-Type", "application/xml")
	c.Data(http.StatusOK, "application/xml", xmlData)
}

func (h *SSOHandler) Logout(c *gin.Context) {
	var (
		session  = sessions.Default(c)
		userInfo *UserInfo
	)

	if session.Get("user_info"); session.Get("user_info") != nil {
		if _, ok := session.Get("user_info").(string); ok {
			json.Unmarshal([]byte(session.Get("user_info").(string)), &userInfo)
		}
	}

	if userInfo != nil {
		switch userInfo.AuthMethod {

		case "SAML":
			h.initiateSAMLLogout(c)
			return
		}
	}

	c.Redirect(http.StatusFound, "/")
}

func (h *SSOHandler) Home(c *gin.Context) {
	var (
		userInfo     *UserInfo
		session      = sessions.Default(c)
		userInfoData = session.Get("user_info")
		remainingM   float64
		err          error
	)

	if userInfoData != nil {
		if err = json.Unmarshal([]byte(userInfoData.(string)), &userInfo); err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Failed to parse user session data",
				"debug": err.Error(),
			})
			return
		}
	}

	if userInfo != nil {

		remainingM = time.Until(userInfo.SessionExpiry).Minutes()

		if remainingM <= 0 {

			if userInfo.AuthMethod == "SAML" {
				h.initiateSAMLLogout(c)
				return
			}

			session.Clear()

			if err = session.Save(); err != nil {
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{
					"error": "Failed to clear session",
					"debug": err.Error(),
				})
				return
			}
			c.Redirect(http.StatusFound, "/")
			return
		}
	}

	c.HTML(http.StatusOK, "home.html", gin.H{
		"user":             userInfo,
		"isLoggedIn":       userInfo != nil,
		"currentTime":      time.Now().Local(),
		"remainingMinutes": remainingM,
	})
}

func (h *SSOHandler) initiateSAMLLogout(c *gin.Context) {

	var (
		session              = sessions.Default(c)
		sIndex               = session.Get("saml_session_index")
		sNameID              = session.Get("saml_name_id")
		sessionIndex, nameID string
		relayState           = generateRandomString(32)
		doc                  *etree.Document
		err                  error
		logoutURL            string
	)

	if sIndex == nil || sNameID == nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Missing SAML session data for logout",
		})
		return
	}

	sessionIndex, _ = sIndex.(string)
	nameID, _ = sNameID.(string)

	if doc, err = h.samlSP.BuildLogoutRequestDocument(nameID, sessionIndex); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to build SAML logout request",
			"debug": err.Error(),
		})
		return
	}

	if logoutURL, err = h.samlSP.BuildLogoutURLRedirect(relayState, doc); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to build SAML logout URL",
			"debug": err.Error(),
		})
		return
	}

	session.Set("saml_logout_req", relayState)
	session.Delete("user_info")
	session.Delete("saml_session_index")
	session.Delete("saml_name_id")

	if err := session.Save(); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to update session",
			"debug": err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, logoutURL)
}

func (h *SSOHandler) SAMLLogoutCallback(c *gin.Context) {

	var (
		session    = sessions.Default(c)
		relayState = c.PostForm("RelayState")
		samlResp   = c.PostForm("SAMLResponse")
	)

	if session.Get("saml_logout_req") == nil {
		return
	}

	if _, err = h.samlSP.ValidateEncodedLogoutResponsePOST(samlResp); err != nil {
		return
	}

	if relayState == session.Get("saml_logout_req").(string) {

		session.Clear()

		if err = session.Save(); err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Failed to save SAML request ID",
				"debug": err.Error(),
			})
			return
		}

		c.Redirect(http.StatusFound, "/")
	}

}

func (h *SSOHandler) Debug(c *gin.Context) {

	var (
		session      = sessions.Default(c)
		userInfoData = session.Get("user_info")
		userInfo     *UserInfo
	)

	if userInfoData != nil {
		if userInfoStr, ok := userInfoData.(string); ok {
			json.Unmarshal([]byte(userInfoStr), &userInfo)
		}
	}

	debugInfo := map[string]interface{}{
		"session_data": userInfo,
		"current_time": time.Now().Local(),
		"environment": map[string]string{
			"KEYCLOAK_URL":         h.cfg.KeycloakURL,
			"REALM":                h.cfg.Realm,
			"SAML_ENTITY_ID":       h.cfg.SAMLEntityID,
			"SAML_METADATA_URL":    h.cfg.SAMLMetadataURL,
			"INSECURE_SKIP_VERIFY": "",
		},
	}

	c.HTML(http.StatusOK, "debug.html", gin.H{
		"debug": debugInfo,
	})
}
