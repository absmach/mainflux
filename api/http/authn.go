// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"net/http"
	"strings"

	apiutil "github.com/absmach/supermq/api/http/util"
	smqauthn "github.com/absmach/supermq/pkg/authn"
	"github.com/go-chi/chi/v5"
)

type sessionKeyType string

const (
	SessionKey = sessionKeyType("session")
	patPrefix  = "pat_"
)

func AuthenticateMiddleware(authn smqauthn.Authentication, domainCheck bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := apiutil.ExtractBearerToken(r)
			if token == "" {
				EncodeError(r.Context(), apiutil.ErrBearerToken, w)
				return
			}
			var resp smqauthn.Session
			var err error
			if strings.HasPrefix(token, patPrefix) {
				resp, err = authn.AuthenticatePAT(r.Context(), token)
				if err != nil {
					EncodeError(r.Context(), err, w)
					return
				}
			} else {
				resp, err = authn.Authenticate(r.Context(), token)
				if err != nil {
					EncodeError(r.Context(), err, w)
					return
				}
			}

			if domainCheck {
				domain := chi.URLParam(r, "domainID")
				if domain == "" {
					EncodeError(r.Context(), apiutil.ErrMissingDomainID, w)
					return
				}
				resp.DomainID = domain
				resp.DomainUserID = auth.EncodeDomainUserID(domain, resp.UserID)
			}

			ctx := context.WithValue(r.Context(), SessionKey, resp)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
