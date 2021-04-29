// nolint
package routes

import (
	"net/http"

	"github.com/labstack/echo"
)

// Healthcheck is the heathcheck function.
func Healthcheck(c echo.Context) error {
	return c.String(http.StatusOK, "WORKING!\n")
}
