package gocloak

// StringP returns a pointer of a string variable
func StringP(value string) *string {
	return &value
}

// PString returns a string value from a pointer
func PString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// BoolP returns a pointer of a boolean variable
func BoolP(value bool) *bool {
	return &value
}

// PBool returns a boolean value from a pointer
func PBool(value *bool) bool {
	return *value
}

// IntP returns a pointer of an integer variable
func IntP(value int) *int {
	return &value
}

// Int32P returns a pointer of an int32 variable
func Int32P(value int32) *int32 {
	return &value
}

// Int64P returns a pointer of an int64 variable
func Int64P(value int64) *int64 {
	return &value
}

// PInt returns an integer value from a pointer
func PInt(value *int) int {
	return *value
}

// PInt32 returns an int32 value from a pointer
func PInt32(value *int32) int32 {
	return *value
}

// PInt64 returns an int64 value from a pointer
func PInt64(value *int64) int64 {
	return *value
}

// Float32P returns a pointer of a float32 variable
func Float32P(value float32) *float32 {
	return &value
}

// Float64P returns a pointer of a float64 variable
func Float64P(value float64) *float64 {
	return &value
}

// PFloat32 returns an flaot32 value from a pointer
func PFloat32(value *float32) float32 {
	return *value
}

// PFloat64 returns an flaot64 value from a pointer
func PFloat64(value *float64) float64 {
	return *value
}

// NilOrEmpty returns true if string is empty or has a nil value
func NilOrEmpty(value *string) bool {
	return value == nil || len(*value) == 0
}

// DecisionStrategyP returns a pointer for a DecisionStrategy value
func DecisionStrategyP(value DecisionStrategy) *DecisionStrategy {
	return &value
}

// LogicP returns a pointer for a LogicP value
func LogicP(value Logic) *Logic {
	return &value
}

// PStringSlice converts a pointer to []string or returns ampty slice if nill value
func PStringSlice(value *[]string) []string {
	if value == nil {
		return []string{}
	}
	return *value
}

// NilOrEmptySlice returns true if list is empty or has a nil value
func NilOrEmptySlice(value *[]string) bool {
	return value == nil || len(*value) == 0
}
