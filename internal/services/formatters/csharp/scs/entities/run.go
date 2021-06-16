package entities

type Run struct {
	Results []*Result `json:"results"`
	Tool    Tool      `json:"tool"`
}
