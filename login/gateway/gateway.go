package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"log"
	"net/http"
	"time"
)

type Config struct {
	JwtSecretKey  string
	JwtIss        string
	JwtExpired    time.Duration
	ClientTimeout time.Duration
}

type LoginHandler struct {
	ctx    context.Context
	Client *http.Client
	Name   string
	Config Config
}

type Response struct {
	Data PayloadAuth `json:"data"`
}

type PayloadAuth struct {
	Id    string   `json:"id"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	Token string   `json:"token"`
}

type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *LoginHandler) generateToken(payload *PayloadAuth) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": payload.Email,
		"role":  payload.Roles,
		"sub":   payload.Id,
		"iss":   h.Config.JwtIss,
		"exp":   time.Now().Add(h.Config.JwtExpired).Unix(),
	})
	tokenString, err := token.SignedString([]byte(h.Config.JwtSecretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var data PayloadAuth

	req, err := http.NewRequestWithContext(h.ctx, r.Method, fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.URL.Host, r.URL.Path), r.Body)
	if err != nil {
		log.Println("failed to call backend:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	req.Host = r.Host
	req.URL.Opaque = r.URL.RequestURI()
	for key, value := range r.Header {
		req.Header[key] = value
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		log.Println("failed to write response:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		if resp.StatusCode == http.StatusOK {
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					log.Println("failed defer:", err.Error())
					return
				}
			}(resp.Body)

			err = json.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				log.Println("failed decode:", err.Error())
				return
			}

			for key, value := range resp.Header {
				w.Header()[key] = value
			}

			token, err := h.generateToken(&data)
			if err != nil {
				log.Println(err)
				return
			}

			data.Token = token

			w.Header().Del("Content-Length")
			w.WriteHeader(resp.StatusCode)

			responseObj := Response{
				Data: data,
			}

			err = json.NewEncoder(w).Encode(&responseObj)
			if err != nil {
				log.Println("failed to write response:", err.Error())
			}
		} else {
			for key, value := range resp.Header {
				w.Header()[key] = value
			}
			w.Header().Del("Content-Length")
			w.WriteHeader(resp.StatusCode)
			_, err := io.Copy(w, resp.Body)
			if err != nil {
				log.Println("failed decode:", err.Error())
				return
			}
		}
	}
}

func New(ctx context.Context, name string, cfg Config) (http.Handler, error) {
	handler := LoginHandler{
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
