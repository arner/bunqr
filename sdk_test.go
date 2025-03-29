package bunqr

import (
	"net/http"
	"os"
	"testing"

	"github.com/arner/bunqr/client"
)

func TestCreateSessionOAuth(t *testing.T) {
	file, _ := os.Open("client/testdata/create-session-oauth.json")
	defer file.Close()
	rsp := &http.Response{
		StatusCode: 200,
		Body:       file,
	}
	res, err := client.ParseSlice[[]client.SessionServerCreate](rsp)
	if err != nil {
		t.Error(err.Error())
	}

	val, err := parseCreateSessionResponse(res.Response)
	if err != nil {
		t.Error(err.Error())
	}

	assertEqual(t, val.APIKeyID, 654321, "APIKeyID")
	assertEqual(t, val.UserID, 123456, "UserID")
	assertEqual(t, val.Nickname, "AliceN", "Nickname")
	assertEqual(t, val.AccessToken, "thetoken", "AccessToken")
}

func TestCreateSessionAPIKey(t *testing.T) {
	file, _ := os.Open("client/testdata/create-session-apikey.json")
	defer file.Close()
	rsp := &http.Response{
		StatusCode: 200,
		Body:       file,
	}
	res, err := client.ParseSlice[[]client.SessionServerCreate](rsp)
	if err != nil {
		t.Error(err.Error())
	}

	val, err := parseCreateSessionResponse(res.Response)
	if err != nil {
		t.Error(err.Error())
	}
	assertEqual(t, val.APIKeyID, 25064842, "APIKeyID")
	assertEqual(t, val.UserID, 1725995, "UserID")
	assertEqual(t, val.Nickname, "Elliot", "Nickname")
	assertEqual(t, val.AccessToken, "thetoken", "AccessToken")
}

func assertEqual[V comparable](t *testing.T, got, expected V, field string) {
	t.Helper()

	if expected != got {
		t.Errorf(`assert.Equal %s
		got     : %v,
		expected: %v`, field, got, expected)
	}
}
