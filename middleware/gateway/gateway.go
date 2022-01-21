package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type MiddlewareHandler struct {
	ctx    context.Context
	Client *http.Client
	Name   string
	Config Config
}

type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type PayloadAuth struct {
	Id    string   `json:"id"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

func (h *MiddlewareHandler) decodeToken(token string) (*PayloadAuth, error) {
	tokenParse, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error in parsing")
		}
		return h.Config.JwtSecretKey, nil
	})
	if claims, ok := tokenParse.Claims.(jwt.MapClaims); ok && tokenParse.Valid {
		roleClaims := claims["role"].([]interface{})
		roles := make([]string, len(roleClaims))
		for i, v := range roleClaims {
			roles[i] = v.(string)
		}
		data := PayloadAuth{
			Id:    claims["sub"].(string),
			Email: claims["email"].(string),
			Roles: roles,
		}
		return &data, nil
	} else {
		return nil, errors.New("failed to decode")
	}
}

func (h *MiddlewareHandler) getHeaderToken(r *http.Request) (string, error) {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer ")
	index := 1
	if len(splitToken) > index {
		return splitToken[index], nil
	}
	return "", errors.New("Invalid Token")
}

func (h *MiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	token, err := h.getHeaderToken(r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Code:    http.StatusForbidden,
			Message: err.Error(),
		})
		return
	}

	authData, err := h.decodeToken(token)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Code:    http.StatusForbidden,
			Message: "Invalid Token",
		})
		return
	}

	req, err := http.NewRequestWithContext(h.ctx, r.Method, fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.URL.Host, r.URL.Path), r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Code:    http.StatusInternalServerError,
			Message: "Internal Server Error",
		})
		return
	}

	for key, value := range r.Header {
		req.Header[key] = value
	}

	req.Header.Set("X-USER-ID", authData.Id)
	req.Header.Set("X-USER-ROLE", strings.Join(authData.Roles, ","))

	req.URL.RawQuery = r.URL.RawQuery

	resp, err := h.Client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Code:    http.StatusInternalServerError,
			Message: "Internal Server Error",
		})
	} else {
		for key, value := range resp.Header {
			w.Header()[key] = value
		}
		w.WriteHeader(resp.StatusCode)

		_, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Println("failed to write response:", err.Error())
		}
	}
}

type Config struct {
	JwtSecretKey  string
	ClientTimeout time.Duration
}

func New(ctx context.Context, name string, cfg Config) (http.Handler, error) {
	handler := MiddlewareHandler{
		ctx: ctx,
		Client: &http.Client{
			Timeout: cfg.ClientTimeout,
		},
		Name:   name,
		Config: cfg,
	}
	mux := http.NewServeMux()
	mux.Handle("/", &handler)
	return mux, nil
}
