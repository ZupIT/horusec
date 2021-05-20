// nolint
package main

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"

	"github.com/ZupIT/horusec/examples/go/example1/api/routes"
)

func main() {

	echoInstance := echo.New()
	echoInstance.HideBanner = true

	echoInstance.Use(middleware.Logger())
	echoInstance.Use(middleware.Recover())
	echoInstance.Use(middleware.RequestID())

	// health routes
	echoInstance.GET("/healthcheck", routes.Healthcheck)

	echoInstance.Logger.Fatal(echoInstance.Start(":8888"))

}
