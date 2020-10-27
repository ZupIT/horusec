package jwx

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	jwt "github.com/dgrijalva/jwt-go/v4"
	"github.com/pkg/errors"
)

// SignClaims signs the given claims using a given key and a method
func SignClaims(claims jwt.Claims, key interface{}, method jwt.SigningMethod) (string, error) {
	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(key)
}

// DecodeAccessTokenHeader decodes the header of the accessToken
func DecodeAccessTokenHeader(token string) (*DecodedAccessTokenHeader, error) {
	const errMessage = "could not decode access token header"
	token = strings.Replace(token, "Bearer ", "", 1)
	headerString := strings.Split(token, ".")
	decodedData, err := base64.RawStdEncoding.DecodeString(headerString[0])
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	result := &DecodedAccessTokenHeader{}
	err = json.Unmarshal(decodedData, result)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	return result, nil
}

func decodePublicKey(e, n *string) (*rsa.PublicKey, error) {
	const errMessage = "could not decode public key"

	decN, err := base64.RawURLEncoding.DecodeString(*n)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	nInt := big.NewInt(0)
	nInt.SetBytes(decN)

	decE, err := base64.RawURLEncoding.DecodeString(*e)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE), 8)
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}

	eReader := bytes.NewReader(eBytes)
	var eInt uint64
	err = binary.Read(eReader, binary.BigEndian, &eInt)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	pKey := rsa.PublicKey{N: nInt, E: int(eInt)}
	return &pKey, nil
}

// DecodeAccessToken currently only supports RSA - sorry for that
func DecodeAccessToken(accessToken string, e, n *string, expectedAudience string) (*jwt.Token, *jwt.MapClaims, error) {
	const errMessage = "could not decode accessToken"

	rsaPublicKey, err := decodePublicKey(e, n)
	if err != nil {
		return nil, nil, errors.Wrap(err, errMessage)
	}

	claims := &jwt.MapClaims{}

	audValidation := jwt.WithoutAudienceValidation()
	if expectedAudience != "" {
		audValidation = jwt.WithAudience(expectedAudience)
	}

	token2, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}, audValidation)

	if err != nil {
		return nil, nil, errors.Wrap(err, errMessage)
	}

	return token2, claims, nil
}

// DecodeAccessTokenCustomClaims currently only supports RSA - sorry for that
func DecodeAccessTokenCustomClaims(accessToken string, e, n *string, customClaims jwt.Claims, expectedAudience string) (*jwt.Token, error) {
	const errMessage = "could not decode accessToken with custom claims"

	rsaPublicKey, err := decodePublicKey(e, n)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	audValidation := jwt.WithoutAudienceValidation()
	if expectedAudience != "" {
		audValidation = jwt.WithAudience(expectedAudience)
	}

	token2, err := jwt.ParseWithClaims(accessToken, customClaims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}, audValidation)

	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	return token2, nil
}
