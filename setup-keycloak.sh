#!/bin/bash

echo "Waiting for Keycloak to be ready..."
sleep 10

# Get admin token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "Failed to get admin token, trying HTTP..."
    ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=admin" \
      -d "password=admin" \
      -d "grant_type=password" \
      -d "client_id=admin-cli" | jq -r '.access_token')
fi

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "Failed to get admin token"
    exit 1
fi

echo "Got admin token, configuring Keycloak..."

# Create realm
curl -s -X POST http://localhost:8080/admin/realms \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "demo-realm",
    "enabled": true,
    "displayName": "Demo Realm"
  }'

# Configure realm SSO session settings (10 minutes)
curl -s -X PUT http://localhost:8080/admin/realms/demo-realm \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ssoSessionIdleTimeout": 600,
    "ssoSessionMaxLifespan": 600,
    "ssoSessionIdleTimeoutRememberMe": 0,
    "ssoSessionMaxLifespanRememberMe": 0
  }'

# Get SAML client ID 
SAML_CLIENT_ID=$(curl -s -X GET http://localhost:8080/admin/realms/demo-realm/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" | jq -r '.[] | select(.clientId == "http://localhost:8081/saml/metadata") | .id')

# Create SAML client 
if [ -z "$SAML_CLIENT_ID" ]; then
  curl -s -X POST http://localhost:8080/admin/realms/demo-realm/clients \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "clientId": "http://localhost:8081/saml/metadata",
      "enabled": true,
      "protocol": "saml",
      "redirectUris": ["http://localhost:8081/auth/saml/acs"],
      "baseUrl": "http://localhost:8081",
      "attributes": {
        "saml.assertion.signature": "true",
        "saml.force.post.binding": "true",
        "saml.multivalued.roles": "false",
        "saml.encrypt": "false",
        "saml.server.signature": "true",
        "saml.server.signature.keyinfo.ext": "false",
        "exclude.session.state.from.auth.response": "false",
        "saml.signature.algorithm": "RSA_SHA256",
        "saml.client.signature": "false",
        "tls.client.certificate.bound.access.tokens": "false",
        "saml.authnstatement": "true",
        "display.on.consent.screen": "false",
        "saml.onetimeuse.condition": "false"
      }
    }'
    
  SAML_CLIENT_ID=$(curl -s -X GET http://localhost:8080/admin/realms/demo-realm/clients \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" | jq -r '.[] | select(.clientId == "http://localhost:8081/saml/metadata") | .id')
fi

# Update client with proper logout settings
curl -s -X PUT http://localhost:8080/admin/realms/demo-realm/clients/$SAML_CLIENT_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "http://localhost:8081/saml/metadata",
    "enabled": true,
    "protocol": "saml",
    "redirectUris": ["http://localhost:8081/auth/saml/acs"],
    "baseUrl": "http://localhost:8081",
    "adminUrl": "http://localhost:8081",
    "attributes": {
      "saml.assertion.signature": "true",
      "saml.force.post.binding": "true",
      "saml.multivalued.roles": "false",
      "saml.encrypt": "false",
      "saml.server.signature": "true",
      "saml.server.signature.keyinfo.ext": "false",
      "exclude.session.state.from.auth.response": "false",
      "saml.signature.algorithm": "RSA_SHA256",
      "saml.client.signature": "false",
      "tls.client.certificate.bound.access.tokens": "false",
      "saml.authnstatement": "true",
      "display.on.consent.screen": "false",
      "saml.onetimeuse.condition": "false",
      "saml_single_logout_service_url_post": "http://localhost:8081/auth/saml/slo",
      "saml.force.post.binding": "true",
      "saml.server.signature": "true",
      "saml.client.signature": "false"
    }
  }'

# Add protocol mappers
curl -s -X POST http://localhost:8080/admin/realms/demo-realm/clients/$SAML_CLIENT_ID/protocol-mappers/models \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "X500 givenName",
    "protocol": "saml",
    "protocolMapper": "saml-user-property-mapper",
    "consentRequired": false,
    "config": {
      "user.attribute": "givenName",
      "friendly.name": "givenName",
      "attribute.name": "givenName",
      "attribute.nameformat": "Basic"
    }
  }'

curl -s -X POST http://localhost:8080/admin/realms/demo-realm/clients/$SAML_CLIENT_ID/protocol-mappers/models \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "X500 surname",
    "protocol": "saml",
    "protocolMapper": "saml-user-property-mapper",
    "consentRequired": false,
    "config": {
      "user.attribute": "surname",
      "friendly.name": "surname",
      "attribute.name": "surname",
      "attribute.nameformat": "Basic"
    }
  }'

curl -s -X POST http://localhost:8080/admin/realms/demo-realm/clients/$SAML_CLIENT_ID/protocol-mappers/models \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "X500 email",
    "protocol": "saml",
    "protocolMapper": "saml-user-property-mapper",
    "consentRequired": false,
    "config": {
      "user.attribute": "email",
      "friendly.name": "email",
      "attribute.name": "email",
      "attribute.nameformat": "Basic"
    }
  }'

# Create test user
curl -s -X POST http://localhost:8080/admin/realms/demo-realm/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "enabled": true,
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User",
    "credentials": [{
      "type": "password",
      "value": "password",
      "temporary": false
    }]
  }'

echo "Keycloak configuration completed!"
echo "Test user created: testuser / password"
echo "SAML SP Client: http://localhost:8081/saml/metadata"
