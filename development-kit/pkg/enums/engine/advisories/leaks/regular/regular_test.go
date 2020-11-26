package regular

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/ZupIT/horusec-engine/text"
)

func parseTextUnitsToUnits(textUnits []text.TextUnit) (units []engine.Unit) {
	for index := range textUnits {
		units = append(units, textUnits[index])
	}
	return units
}

func TestNewLeaksRegularAWSManagerID(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularAWSManagerID", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	    ACCESS_KEY: 'AKIAJSIE27KKMHXI3BJQ'
`
		rule := NewLeaksRegularAWSManagerID()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     "ACCESS_KEY: 'AKIAJSIE27KKMHXI3BJQ'",
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   18,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularAWSManagerID", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  ACCESS_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularAWSManagerID()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularAWSSecretKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularAWSSecretKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      AWS_SECRET_KEY: 'doc5eRXFpsWllGC5yKJV/Ymm5KwF+IRZo95EudOm'
`
		rule := NewLeaksRegularAWSSecretKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `AWS_SECRET_KEY: 'doc5eRXFpsWllGC5yKJV/Ymm5KwF+IRZo95EudOm'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularAWSSecretKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SECRET_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularAWSSecretKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularAWSMWSKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularAWSMWSKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      AWS_WMS_KEY: 'amzn.mws.986478f0-9775-eabc-2af4-e499a8496828'
`
		rule := NewLeaksRegularAWSMWSKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `AWS_WMS_KEY: 'amzn.mws.986478f0-9775-eabc-2af4-e499a8496828'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   20,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularAWSMWSKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      WMS_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularAWSMWSKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularFacebookSecretKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularFacebookSecretKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      FB_SECRET_KEY: 'cb6f53505911332d30867f44a1c1b9b5'
`
		rule := NewLeaksRegularFacebookSecretKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `FB_SECRET_KEY: 'cb6f53505911332d30867f44a1c1b9b5'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularFacebookSecretKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  FB_SECRET_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularFacebookSecretKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularFacebookClientID(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularFacebookClientID", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      FB_CLIENT_ID: '148695999071979'
`
		rule := NewLeaksRegularFacebookClientID()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `FB_CLIENT_ID: '148695999071979'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularFacebookClientID", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  FB_CLIENT_ID: ${SECRET_KEY}
`
		rule := NewLeaksRegularFacebookClientID()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularTwitterClientID(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularTwitterClientID", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      TWITTER_CLIENT_ID: '1h6433fsvygnyre5a40'
`
		rule := NewLeaksRegularTwitterClientID()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `TWITTER_CLIENT_ID: '1h6433fsvygnyre5a40'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularTwitterClientID", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  TWITTER_CLIENT_ID: ${SECRET_KEY}
`
		rule := NewLeaksRegularTwitterClientID()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularTwitterSecretKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularTwitterSecretKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      TWITTER_SECRET_KEY: 'ej64cqk9k8px9ae3e47ip89l7if58tqhpxi1r'
`
		rule := NewLeaksRegularTwitterSecretKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `TWITTER_SECRET_KEY: 'ej64cqk9k8px9ae3e47ip89l7if58tqhpxi1r'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularTwitterSecretKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  TWITTER_SECRET_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularTwitterSecretKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularGithub(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularGithub", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      GITHUB_SECRET_KEY: 'edzvPbU3SYUc7pFc9le20lzIRErTOaxCABQ1'
`
		rule := NewLeaksRegularGithub()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `GITHUB_SECRET_KEY: 'edzvPbU3SYUc7pFc9le20lzIRErTOaxCABQ1'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularGithub", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  GITHUB_SECRET_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularGithub()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularLinkedInClientID(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularLinkedInClientID", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      LINKEDIN_CLIENT_ID: 'g309xttlaw25'
`
		rule := NewLeaksRegularLinkedInClientID()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `LINKEDIN_CLIENT_ID: 'g309xttlaw25'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularLinkedInClientID", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  LINKEDIN_CLIENT_ID: ${SECRET_KEY}
`
		rule := NewLeaksRegularLinkedInClientID()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularLinkedInSecretKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularLinkedInSecretKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      LINKEDIN_SECRET_KEY: '0d16kcnjyfzmcmjp'
`
		rule := NewLeaksRegularLinkedInSecretKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `LINKEDIN_SECRET_KEY: '0d16kcnjyfzmcmjp'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularLinkedInSecretKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  LINKEDIN_SECRET_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularLinkedInSecretKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularSlack(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularSlack", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SLACK_WEBHOOK: 'https://hooksWslackKcom/services/TNeqvYPeO/BncTJ74Hf/NlvFFKKAKPkd6h7FlQCz1Blu'
`
		rule := NewLeaksRegularSlack()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `SLACK_WEBHOOK: 'https://hooksWslackKcom/services/TNeqvYPeO/BncTJ74Hf/NlvFFKKAKPkd6h7FlQCz1Blu'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   22,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularSlack", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SLACK_WEBHOOK: ${SECRET_KEY}
`
		rule := NewLeaksRegularSlack()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularAsymmetricPrivateKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularAsymmetricPrivateKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SSH_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anGcmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYDVQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD...bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEFBQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdhz3P668YfhUbKdRF6S42Cg6zn-----END PRIVATE KEY-----'
`
		rule := NewLeaksRegularAsymmetricPrivateKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `SSH_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anGcmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYDVQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD...bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEFBQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdhz3P668YfhUbKdRF6S42Cg6zn-----END PRIVATE KEY-----'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   24,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularAsymmetricPrivateKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SSH_PRIVATE_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularAsymmetricPrivateKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularGoogleAPIKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularGoogleAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      GCP_API_KEY: 'AIzaMPZHYiu1RdzE1nG2SaVyOoz244TuacQIR6m'
`
		rule := NewLeaksRegularGoogleAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `GCP_API_KEY: 'AIzaMPZHYiu1RdzE1nG2SaVyOoz244TuacQIR6m'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   20,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularGoogleAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  GCP_API_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularGoogleAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularGoogleGCPServiceAccount(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularGoogleGCPServiceAccount", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      GCP_SERVICE_ACCOUNT: '18256698220617903267772185514630273595-oy8_uzouz8tyy46y84ckrwei9_6rq_pb\ apps\Vgoogleusercontent\5com'
`
		rule := NewLeaksRegularGoogleGCPServiceAccount()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `GCP_SERVICE_ACCOUNT: '18256698220617903267772185514630273595-oy8_uzouz8tyy46y84ckrwei9_6rq_pb\ apps\Vgoogleusercontent\5com'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularGoogleGCPServiceAccount", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  GCP_SERVICE_ACCOUNT: ${SECRET_KEY}
`
		rule := NewLeaksRegularGoogleGCPServiceAccount()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularHerokuAPIKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularHerokuAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      HEROKU_API_KEY: '3623f8e9-2d05-c9bb-2209082d6b5c'
`
		rule := NewLeaksRegularHerokuAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `HEROKU_API_KEY: '3623f8e9-2d05-c9bb-2209082d6b5c'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularHerokuAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  HEROKU_API_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularHerokuAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularMailChimpAPIKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularMailChimpAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      MAILCHIMP_API_KEY: 'f7e9c13c10d0b19c3bb003a9f635d488-us72'
`
		rule := NewLeaksRegularMailChimpAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `MAILCHIMP_API_KEY: 'f7e9c13c10d0b19c3bb003a9f635d488-us72'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularMailChimpAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  MAILCHIMP_API_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularMailChimpAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularMailgunAPIKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularMailgunAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      MAILGUN_API_KEY: 'key-xke9nbc2i5po5cjw3ngyxiz450zxpapu'
`
		rule := NewLeaksRegularMailgunAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `MAILGUN_API_KEY: 'key-xke9nbc2i5po5cjw3ngyxiz450zxpapu'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularMailgunAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  MAILGUN_API_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularMailgunAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularPayPalBraintreeAccessToken(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularPayPalBraintreeAccessToken", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      PAY_PAL_ACCESS_TOKEN: 'access_token$production$mk0sech2v7qqsol3$db651af2221c22b4ca2f0f583798135e'
`
		rule := NewLeaksRegularPayPalBraintreeAccessToken()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `PAY_PAL_ACCESS_TOKEN: 'access_token$production$mk0sech2v7qqsol3$db651af2221c22b4ca2f0f583798135e'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   29,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularPayPalBraintreeAccessToken", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  PAY_PAL_ACCESS_TOKEN: ${SECRET_KEY}
`
		rule := NewLeaksRegularPayPalBraintreeAccessToken()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularPicaticAPIKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularPicaticAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      PICATIC_API_KEY: 'sk_live_voy1p9k7r9g9j8ezmif488nk2p8310nl'
`
		rule := NewLeaksRegularPicaticAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `PICATIC_API_KEY: 'sk_live_voy1p9k7r9g9j8ezmif488nk2p8310nl'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   24,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularPicaticAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  PICATIC_API_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularPicaticAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularSendGridAPIKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularSendGridAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SEND_GRID_API_KEY: 'SG.44b7kq3FurdH0bSHBGjPSWhE8vJ.1evu4Un0TXFIb1_6zW4YOdjTMeE'
`
		rule := NewLeaksRegularSendGridAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `SEND_GRID_API_KEY: 'SG.44b7kq3FurdH0bSHBGjPSWhE8vJ.1evu4Un0TXFIb1_6zW4YOdjTMeE'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   26,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularSendGridAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SEND_GRID_API_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularSendGridAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularStripeAPIKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularStripeAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      STRIPE_API_KEY: 'rk_live_8qSZpoI9t0BOGkOLVzvesc6K'
`
		rule := NewLeaksRegularStripeAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `STRIPE_API_KEY: 'rk_live_8qSZpoI9t0BOGkOLVzvesc6K'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularStripeAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  STRIPE_API_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularStripeAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularSquareAccessToken(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularSquareAccessToken", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SQUARE_ACCESS_TOKEN: 'sq0atp-clYRBSht6oefa7w_2R56ra'
`
		rule := NewLeaksRegularSquareAccessToken()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `SQUARE_ACCESS_TOKEN: 'sq0atp-clYRBSht6oefa7w_2R56ra'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   28,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularSquareAccessToken", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SQUARE_ACCESS_TOKEN: ${SECRET_KEY}
`
		rule := NewLeaksRegularSquareAccessToken()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularSquareOAuthSecret(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularSquareOAuthSecret", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SQUARE_SECRET: 'sq0csp-LsEBYQNja]OgT3hRxjJV5cWX^XjpT12n3QkRY_vep2z'
`
		rule := NewLeaksRegularSquareOAuthSecret()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `SQUARE_SECRET: 'sq0csp-LsEBYQNja]OgT3hRxjJV5cWX^XjpT12n3QkRY_vep2z'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   22,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularSquareOAuthSecret", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SQUARE_SECRET: ${SECRET_KEY}
`
		rule := NewLeaksRegularSquareOAuthSecret()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularTwilioAPIKey(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularTwilioAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      TWILIO_API_KEY: '^SK9ae6bd84ccd091eb6bfad8e2a474af95'
`
		rule := NewLeaksRegularTwilioAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `TWILIO_API_KEY: '^SK9ae6bd84ccd091eb6bfad8e2a474af95'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   6,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularTwilioAPIKey", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  TWILIO_API_KEY: ${SECRET_KEY}
`
		rule := NewLeaksRegularTwilioAPIKey()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularHardCodedCredentialGeneric(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularHardCodedCredentialGeneric", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      POSTGRES_DBPASSWD: 'Ch@ng3m3'
`
		rule := NewLeaksRegularHardCodedCredentialGeneric()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `POSTGRES_DBPASSWD: 'Ch@ng3m3'`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "deployments/docker-compose.yaml",
				Line:     7,
				Column:   15,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularHardCodedCredentialGeneric", func(t *testing.T) {
		code := `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  POSTGRES_DBPASSWD: ${SECRET_KEY}
`
		rule := NewLeaksRegularHardCodedCredentialGeneric()
		textFile, err := text.NewTextFile("deployments/docker-compose.yaml", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularHardCodedPassword(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularHardCodedPassword", func(t *testing.T) {
		code := `
package main

import (
  "fmt"
  "gorm.io/gorm"
  "gorm.io/driver/postgres"
)

func main() {
	DB_USER="gorm"
	DB_PASSWORD="gorm"
	DB_NAME="gorm"
	DB_PORT="9920"
  	dsn := fmt.Sprintf("user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai", DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	print(db)
}
`
		rule := NewLeaksRegularHardCodedPassword()
		textFile, err := text.NewTextFile("main.go", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `DB_PASSWORD="gorm"`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "main.go",
				Line:     12,
				Column:   4,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularHardCodedPassword", func(t *testing.T) {
		code := `
package main

import (
  "os"
  "fmt"
  "gorm.io/gorm"
  "gorm.io/driver/postgres"
)

func main() {
	DB_USER="gorm"
	DB_PASSWORD=os.Getenv("DB_PASSWORD")
	DB_NAME="gorm"
	DB_PORT="9920"
  	dsn := fmt.Sprintf("user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai", DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	print(db)
}
`
		rule := NewLeaksRegularHardCodedPassword()
		textFile, err := text.NewTextFile("main.go", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularPasswordExposedInHardcodedURL(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularPasswordExposedInHardcodedURL", func(t *testing.T) {
		code := `
package main

import (
  "gorm.io/gorm"
  "gorm.io/driver/postgres"
)

func main() {
	dsn := "postgresql://gorm:gorm@127.0.0.1:5432/gorm?sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	print(db)
}
`
		rule := NewLeaksRegularPasswordExposedInHardcodedURL()
		textFile, err := text.NewTextFile("main.go", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `dsn := "postgresql://gorm:gorm@127.0.0.1:5432/gorm?sslmode=disable"`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "main.go",
				Line:     10,
				Column:   9,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularPasswordExposedInHardcodedURL", func(t *testing.T) {
		code := `
package main

import (
  "os"
  "gorm.io/gorm"
  "gorm.io/driver/postgres"
)

func main() {
	dsn := os.Getenv("DB_QUERY_STRING")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	print(db)
}
`
		rule := NewLeaksRegularPasswordExposedInHardcodedURL()
		textFile, err := text.NewTextFile("main.go", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}

func TestNewLeaksRegularWPConfig(t *testing.T) {
	t.Run("Should return vulnerable code NewLeaksRegularWPConfig", func(t *testing.T) {
		code := `<?php
define( 'AUTH_KEY',         'put your unique phrase here' );
`
		rule := NewLeaksRegularWPConfig()
		textFile, err := text.NewTextFile("wp-config.php", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `define( 'AUTH_KEY',         'put your unique phrase here' );`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "wp-config.php",
				Line:     2,
				Column:   0,
			},
		}, findings[0])
	})
	t.Run("Should return vulnerable code of database password NewLeaksRegularWPConfig", func(t *testing.T) {
		code := `<?php
define( 'DB_PASSWORD', 'wen0221!' );
`
		rule := NewLeaksRegularWPConfig()
		textFile, err := text.NewTextFile("wp-config.php", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 1)
		assert.Equal(t, engine.Finding{
			ID:             rule.ID,
			Name:           rule.Name,
			Severity:       rule.Severity,
			CodeSample:     `define( 'DB_PASSWORD', 'wen0221!' );`,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			SourceLocation: engine.Location{
				Filename: "wp-config.php",
				Line:     2,
				Column:   0,
			},
		}, findings[0])
	})
	t.Run("Should not return vulnerable code NewLeaksRegularWPConfig", func(t *testing.T) {
		code := `<?php
define( 'AUTH_KEY', getenv("AUTH_KEY") );
`
		rule := NewLeaksRegularWPConfig()
		textFile, err := text.NewTextFile("wp-config.php", []byte(code))
		assert.NoError(t, err)
		findings := engine.Run(parseTextUnitsToUnits([]text.TextUnit{{Files: []text.TextFile{textFile}}}), []engine.Rule{rule})
		assert.Len(t, findings, 0)
	})
}
