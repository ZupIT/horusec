package commitauthor

type CommitAuthor struct {
	Author     string `json:"author"`
	Email      string `json:"email"`
	CommitHash string `json:"commitHash"`
	Message    string `json:"message"`
	Date       string `json:"date"`
}
