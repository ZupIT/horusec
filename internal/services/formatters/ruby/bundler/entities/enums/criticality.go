package enums

type CriticalityType string

const (
	High   CriticalityType = "High"
	Medium CriticalityType = "Medium"
	Low    CriticalityType = "Low"
)

func (c CriticalityType) ToString() string {
	return string(c)
}

func GetCriticalityTypeByString(criticalityType string) CriticalityType {
	switch criticalityType {
	case High.ToString():
		return High
	case Medium.ToString():
		return Medium
	case Low.ToString():
		return Low
	}
	return Low
}
