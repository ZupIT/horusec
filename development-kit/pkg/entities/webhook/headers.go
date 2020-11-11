package webhook

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type HeaderType []Headers

type Headers struct {
	Key    string `json:"key"`
	Value string `json:"value"`
}
func (h HeaderType) Value() (driver.Value, error) {
	return json.Marshal(h)
}
func (h *HeaderType) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("[]byte assertion failed")
	}

	return json.Unmarshal(b, h)
}
