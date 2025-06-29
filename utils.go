package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
)

type EntityDescriptor struct {
	XMLName          xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	IDPSSODescriptor struct {
		XMLName       xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
		KeyDescriptor []struct {
			XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
			Use     string   `xml:"use,attr"`
			KeyInfo struct {
				XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
				X509Data struct {
					XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
					X509Certificate string   `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
				}
			}
		}
	}
}

func fetchMetadataXML(client *http.Client, url string) ([]byte, error) {
	var (
		resp *http.Response
		err  error
	)

	if resp, err = client.Get(url); err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad HTTP response: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func extractCertificateFromMetadata(metadataXML []byte) (*x509.Certificate, error) {

	var (
		ed       EntityDescriptor
		err      error
		certData string
		block    *pem.Block
		cert     *x509.Certificate
	)

	if err = xml.Unmarshal(metadataXML, &ed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %v", err)
	}

	for _, kd := range ed.IDPSSODescriptor.KeyDescriptor {

		if kd.Use == "signing" || kd.Use == "" {

			certData = fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", strings.TrimSpace(kd.KeyInfo.X509Data.X509Certificate))

			if block, _ = pem.Decode([]byte(certData)); block == nil {
				return nil, fmt.Errorf("failed to decode PEM block")
			}

			if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %v", err)
			}

			return cert, nil
		}
	}

	return nil, fmt.Errorf("no signing certificate found in metadata")
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate random string: %v", err))
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func getSAMLAttribute(assertionInfo *saml2.AssertionInfo, name string) string {
	for _, attr := range assertionInfo.Values {

		if strings.EqualFold(attr.Name, name) || strings.EqualFold(attr.FriendlyName, name) {
			if len(attr.Values) > 0 {
				return attr.Values[0].Value
			}
		}
	}
	return ""
}

func safeGetIssuer(issuer *types.Issuer) string {
	if issuer == nil {
		return ""
	}
	return issuer.Value
}

func convertSAMLAttributes(assertionInfo *saml2.AssertionInfo) map[string]interface{} {
	attrs := make(map[string]interface{})

	attrs["name_id"] = assertionInfo.NameID
	attrs["session_index"] = assertionInfo.SessionIndex

	for _, attr := range assertionInfo.Values {
		values := make([]string, len(attr.Values))
		for i, val := range attr.Values {
			values[i] = val.Value
		}
		attrs[attr.Name] = values
	}

	return attrs
}
