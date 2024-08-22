package main

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sytallax/eercandy/api"
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

func main() {
	connector, err := api.NewSpotifyConnector()
	if err != nil {
		logger.Error("could not create spotify connector", "error", err.Error())
	}

	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	e.GET("/login", func(c echo.Context) error {
		authURL, err := connector.RedirectToAuthCodeFlow()
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, authURL)
	})
	e.GET("/callback", connector.GetAccessToken)
	e.GET("/me", func(c echo.Context) error {
		user, err := connector.FetchCurrentUser()
		if err != nil {
			logger.Error("Could not fetch current user", "error", err.Error())
			return c.String(http.StatusInternalServerError, "Could not fetch current user. Error: "+err.Error())
		}
		return c.String(http.StatusOK, "Account for "+user.DisplayName+": Email is "+user.Email+" and URL is "+user.URL)
	})

	e.Logger.Fatal(e.Start(":6838"))
}
