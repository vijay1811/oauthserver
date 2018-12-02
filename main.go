package main

import (
	"encoding/json"

	"github.com/gorilla/mux"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/pkg/errors"

	//	"github.com/stretchr/testify/assert"
	"log"
	"net/http"
	"time"
)

var accessTokenLifespan = time.Hour

var authCodeLifespan = time.Minute

var fositeStore = &storage.MemoryStore{
	Clients: map[string]fosite.Client{
		"my-client": &fosite.DefaultClient{
			ID:            "my-client",
			Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{"id_token", "code", "token", "token code", "id_token code", "token id_token", "token code id_token"},
			GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
			Scopes:        []string{"fosite", "offline", "openid"},
			Audience:      []string{"https://www.ory.sh/api"},
		},
		"public-client": &fosite.DefaultClient{
			ID:            "public-client",
			Secret:        []byte{},
			Public:        true,
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{"id_token", "code", "code id_token"},
			GrantTypes:    []string{"refresh_token", "authorization_code"},
			Scopes:        []string{"fosite", "offline", "openid"},
			Audience:      []string{"https://www.ory.sh/api"},
		},
	},
	Users: map[string]storage.MemoryUserRelation{
		"peter": {
			Username: "peter",
			Password: "secret",
		},
	},
	AuthorizeCodes:         map[string]storage.StoreAuthorizeCode{},
	PKCES:                  map[string]fosite.Requester{},
	Implicit:               map[string]fosite.Requester{},
	AccessTokens:           map[string]fosite.Requester{},
	RefreshTokens:          map[string]fosite.Requester{},
	IDSessions:             map[string]fosite.Requester{},
	AccessTokenRequestIDs:  map[string]string{},
	RefreshTokenRequestIDs: map[string]string{},
}

var hmacStrategy = &oauth2.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
	AccessTokenLifespan:   accessTokenLifespan,
	AuthorizeCodeLifespan: authCodeLifespan,
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

func tokenRevocationHandler(oauth2 fosite.OAuth2Provider, session fosite.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := fosite.NewContext()
		err := oauth2.NewRevocationRequest(ctx, req)
		if err != nil {
			log.Printf("Revoke request failed because %+v", err)
		}
		oauth2.WriteRevocationResponse(rw, err)
	}
}

func tokenIntrospectionHandler(oauth2 fosite.OAuth2Provider, session fosite.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := fosite.NewContext()
		ar, err := oauth2.NewIntrospectionRequest(ctx, req, session)
		if err != nil {
			log.Printf("Introspection request failed because: %+v", err)
			oauth2.WriteIntrospectionError(rw, err)
			return
		}

		oauth2.WriteIntrospectionResponse(rw, ar)
	}
}

func tokenInfoHandler(oauth2 fosite.OAuth2Provider, session fosite.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := fosite.NewContext()
		_, resp, err := oauth2.IntrospectToken(ctx, fosite.AccessTokenFromRequest(req), fosite.AccessToken, session)
		if err != nil {
			log.Printf("Info request failed because: %+v", err)
			http.Error(rw, errors.Cause(err).(*fosite.RFC6749Error).Description, errors.Cause(err).(*fosite.RFC6749Error).Code)
			return
		}

		log.Printf("Introspecting caused: %+v", resp)

		if err := json.NewEncoder(rw).Encode(resp); err != nil {
			panic(err)
		}
	}
}

func authEndpointHandler(oauth2 fosite.OAuth2Provider, session fosite.Session) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := fosite.NewContext()

		ar, err := oauth2.NewAuthorizeRequest(ctx, req)
		if err != nil {
			log.Printf("Access request failed because: %+v", err)
			log.Printf("Request: %+v", ar)
			oauth2.WriteAuthorizeError(rw, ar, err)
			return
		}

		if ar.GetRequestedScopes().Has("fosite") {
			ar.GrantScope("fosite")
		}

		if ar.GetRequestedScopes().Has("offline") {
			ar.GrantScope("offline")
		}

		if ar.GetRequestedScopes().Has("openid") {
			ar.GrantScope("openid")
		}

		for _, a := range ar.GetRequestedAudience() {
			ar.GrantAudience(a)
		}

		// Normally, this would be the place where you would check if the user is logged in and gives his consent.
		// For this test, let's assume that the user exists, is logged in, and gives his consent...

		response, err := oauth2.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			log.Printf("Access request failed because: %+v", err)
			log.Printf("Request: %+v", ar)
			oauth2.WriteAuthorizeError(rw, ar, err)
			return
		}

		oauth2.WriteAuthorizeResponse(rw, ar, response)
	}
}

func authCallbackHandler() func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		// if q.Get("code") == "" && q.Get("error") == "" {
		// 	assert.NotEmpty(t, q.Get("code"))
		// 	assert.NotEmpty(t, q.Get("error"))
		// }

		if q.Get("code") != "" {
			rw.Write([]byte("code: ok"))
		}
		if q.Get("error") != "" {
			rw.WriteHeader(http.StatusNotAcceptable)
			rw.Write([]byte("error: " + q.Get("error")))
		}

	}
}

func tokenEndpointHandler(provider fosite.OAuth2Provider) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		req.ParseMultipartForm(1 << 20)
		ctx := fosite.NewContext()

		accessRequest, err := provider.NewAccessRequest(ctx, req, &oauth2.JWTSession{})
		if err != nil {
			log.Printf("Access @@@ request failed because: %+v", err)
			log.Printf("Request: %+v", accessRequest)
			provider.WriteAccessError(rw, accessRequest, err)
			return
		}

		if accessRequest.GetRequestedScopes().Has("fosite") {
			accessRequest.GrantScope("fosite")
		}

		response, err := provider.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			log.Printf("Access request failed because: %+v", err)
			log.Printf("Request: %+v", accessRequest)
			provider.WriteAccessError(rw, accessRequest, err)
			return
		}

		provider.WriteAccessResponse(rw, accessRequest, response)
	}
}

func main() {
	f := compose.Compose(new(compose.Config), fositeStore, hmacStrategy, nil,
		compose.OAuth2ResourceOwnerPasswordCredentialsFactory,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory)
	session := &fosite.DefaultSession{}
	router := mux.NewRouter()
	router.HandleFunc("/auth", authEndpointHandler(f, session))
	router.HandleFunc("/token", tokenEndpointHandler(f))
	router.HandleFunc("/callback", authCallbackHandler())
	router.HandleFunc("/info", tokenInfoHandler(f, session))
	router.HandleFunc("/introspect", tokenIntrospectionHandler(f, session))
	router.HandleFunc("/revoke", tokenRevocationHandler(f, session))

	http.ListenAndServe(":3846", router)
}

// http://localhost:3846/callback?code=BXt9alHo0roWlxwr24eUK_9WGMItCj4iScbdMTVJZyI.WH1Yp5F9j1t7GjpHyTIY_m-DW6aIzecvWjcbUOuSxL4&scope=fosite&state=12345678901234567890
