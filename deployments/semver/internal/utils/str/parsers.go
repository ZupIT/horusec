package str

import "strconv"

func ParseUIntOrDefault(s string) uint {
	value, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return uint(value)
}
