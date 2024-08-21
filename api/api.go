package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/sytallax/prettylog"
)

var (
	prettyhandler = prettylog.NewHandler(&slog.HandlerOptions{
		Level:       slog.LevelInfo,
		AddSource:   false,
		ReplaceAttr: nil,
	})
	logger = slog.New(prettyhandler)
)

type SpotifyConnector struct {
	ClientID     string
	ClientSecret string
	codeVerifier string
	oauthCode    string
	accessToken  string
}

type accessToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Scope        string
	ExpiresAt    time.Time
	RefreshToken string `json:"refresh_token"`
}

func NewSpotifyConnector() (*SpotifyConnector, error) {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}

	spotifyClientID := os.Getenv("SPOTIFY_CLIENT_ID")
	spotifyClientSecret := os.Getenv("SPOTIFY_CLIENT_SECRET")

	return &SpotifyConnector{
		ClientID:     spotifyClientID,
		ClientSecret: spotifyClientSecret,
	}, nil
}

func (c *SpotifyConnector) RedirectToAuthCodeFlow() (string, error) {
	if c.ClientID == "" {
		return "", errors.New("connector client id is blank")
	}

	codeVerifier, codeChallenge, err := generateCodeVerifierAndChallenge(128)
	if err != nil {
		return "", err
	}
	c.codeVerifier = codeVerifier

	base, err := url.Parse("https://accounts.spotify.com/authorize")
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Add("client_id", c.ClientID)
	params.Add("response_type", "code")
	params.Set("redirect_uri", "http://127.0.0.1:6838/callback")
	params.Add("scope", "user-read-private user-read-email")
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", codeChallenge)

	base.RawQuery = params.Encode() + "&redirect_uri=http://127.0.0.1:6838/callback"
	return base.String(), nil
}

func (s *SpotifyConnector) SetOauthCode(c echo.Context) error {
	switch c.QueryParam("error") {
	case "access_denied":
		return c.String(http.StatusUnauthorized, "OAuth was declined.")
	case "":
		break
	default:
		return c.String(http.StatusInternalServerError, "An unknown error occurred.")
	}
	s.oauthCode = c.QueryParam("code")
	logger.Info("Connector has recieved a code", "code", s.oauthCode)
	return c.String(http.StatusOK, "You have been authorized.")
}

func (c *SpotifyConnector) GetAccessToken() error {
	params := map[string]string{
		"client_id":     c.ClientID,
		"grant_type":    "authorization_code",
		"code":          c.oauthCode,
		"code_verifier": c.codeVerifier,
		"redirect_uri":  "http://127.0.0.1:6838/callback",
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		"https://accounts.spotify.com/api/token",
		bytes.NewBuffer(paramsJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func generateCodeVerifierAndChallenge(size int64) (string, string, error) {
	alphabet := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]byte, size)
	for i := range b {
		randI, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", "", err
		}
		b[i] = alphabet[randI.Int64()]
	}
	bAsSha := sha256.Sum256(b)
	shaAsB64 := base64.URLEncoding.EncodeToString(bAsSha[:])
	return string(b), shaAsB64, nil
}
