package client

import (
	"bytes"
	"context"
	"crypto/rsa"
	"io"
	"math/big"
	"net/http"
	"os"
	"testing"
)

const keyN = "28097090660837336068280341880627720538196625946575012884511037220767410427394539019889749395163714087117766983190154149426328394820893731281471610398289160147104343878455149597607182618481037932339798498724495751043947046859304053859014171389777621733455347546778628398940408158324387466102415880524831346840422611576698823595703958958226146532821857122666706933553428242152123225032723797145921862530630475645637232029622083219656134255264047517644860020726552072586538240426476409180985979203447228378834831860328036201076248950676422083667161671780396337276117993328265415337014660012882028777068144156037901471487"
const pub = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3pJjgdZqHPOyOqW6WBoO\nA3u6wsOhmHkfuamtX4APTwBC0gfquqMCzFc7f+j3r4CN25Vau1Gmnz33c36S2NLD\nVJggY8tLClB10O31wJzHkCNxUOIRTAvfhEP4kjpQYFb1yuO/tudx6JyC4V1x0ON3\nfLAYWGpkiOuGuc3JO59uzuLR4t+5CJ/mFBKBMZXMgrwann2Hy8YmKWjQADZaAOZ4\nV2+yaXN97C9T5XrU+BD4qiwLsTtF2yihroAeEON0k3ypVWxp+DpBTk45r5jRJ+N2\nXIVATHhDE0Y1xny+Ns2TRu4ez9yah7J+S3STZmp9KV2wH7rr1MHX6O90zQBoLYhO\n/wIDAQAB\n-----END PUBLIC KEY-----\n"

func TestParseServerKey(t *testing.T) {
	key, err := parseServerKey([]byte(pub))
	if err != nil {
		t.Fatal(err.Error())
	}
	if key.E != 65537 {
		t.Error("key exponent does not match")
	}
	if key.N.String() != keyN {
		t.Error("key modulus does not match")
	}
}

func TestVerifyServerSignature(t *testing.T) {
	// server key
	kn, _ := big.NewInt(0).SetString(keyN, 10)
	pub := rsa.PublicKey{
		N: kn,
		E: 65537,
	}
	c, err := New("", WithServerKey(pub))
	if err != nil {
		t.Fatal(err.Error())
	}

	sig := "PFPlNFQkmB50le/nuqdbpvsB98PHyTRpgVP3tx4IrgvRTW4X7l+0oEzrsTO3SKZ5dckCPjdm6sSyH31S13LfB1eQ2uVASbzmoE5C+PQJFXznrnfkkV9QfEnL4dSZLvD/p+9pd+D5hC4hpQ7a5RMIlKleHbdBGgkqf3CW6M+BmW7oMQU9pIY2w+13l+8vJ/xpYdCk4Bl7TdALvamEwbBPL43beaClEuvtXSxjtlmpZs2NsJmV27lM9Kj7k7NVa+/C4Ng+DxZH//1frfx5Ve6m2AW+w1wcSgyBNyAlQAjJrGTzzHR2sIzRpC1H0uarMdqKys3nmM6DWEcTjKYPb4c8Uw=="
	body := []byte(`{"Response":[{"Id":{"id":1839935170}}]}`)

	res := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewBuffer(body)),
	}
	res.Header.Set(HXBunqServerSignature, sig)
	err = c.validateSignature(context.TODO(), res)
	if err != nil {
		t.Error(err.Error())
	}

	sig = "d3Jvbmcgc2lnbmF0dXJlCg=="
	body = []byte(`{"Response":[{"Id":{"id":1839935170}}]}`)

	res = &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewBuffer(body)),
	}
	res.Header.Set(HXBunqServerSignature, sig)
	err = c.validateSignature(context.TODO(), res)
	if err == nil {
		t.Error("expected error with wrong signature")
	}

	res = &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewBuffer(body)),
	}
	err = c.validateSignature(context.TODO(), res)
	if err == nil {
		t.Error("expected error with missing header")
	}

	res = &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewBuffer([]byte{})),
	}
	err = c.validateSignature(context.TODO(), res)
	if err != nil {
		t.Error("expected no error with empty body")
	}
}

func TestCreateInstallation(t *testing.T) {
	file, _ := os.Open("testdata/create-installation.json")
	defer file.Close()
	rsp := &http.Response{
		StatusCode: 200,
		Body:       file,
	}
	res, err := ParseSlice[[]InstallationCreate](rsp)
	if err != nil {
		t.Error(err.Error())
	}
	assertEqual(t, res.Response[0].Id.Id, 10000000, "id")
	assertEqual(t, res.Response[1].Token.Id, 20000000, "token id")
	assertEqual(t, res.Response[1].Token.Token, "mytoken", "token")
	assertEqual(t, res.Response[2].ServerPublicKey.ServerPublicKey,
		"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwBiy0NPYZzLVxiTvhXkt\ntTevJGlYEnm6TKcvkwvTWcNrdUIMKjcFncr9eR0kuS+Or4pGFf40iJIpQ1tSGJOg\natFq9lOkH3KPA0/HIuERXsaIrjPKdLg6uksXFvmrJaiknQpkA1sDrvZJrhuiz4gq\n7few3LwH2m331CXS0EGQA931PMyXOS1utCxc+Bdioh6tJF974+gNrs2aWlFbIwX8\nnegKaU1kE08bzYGxuBWbv8LW9yyn0ITEN111Bg4GLfDNTYyorVO2AGjhczCVVvvh\n99u92Alql0z0JEyVxeioyF9vZVwwdCJXrmNvCpWoR56gW316UAoAHE9LDBN1JgtD\nfwIDAQAB\n-----END PUBLIC KEY-----\n",
		"token")
}

func TestCreateDevice(t *testing.T) {
	file, _ := os.Open("testdata/create-device.json")
	defer file.Close()
	rsp := &http.Response{
		StatusCode: 200,
		Body:       file,
	}
	res, err := ParseSlice[[]DeviceServerCreate](rsp)
	if err != nil {
		t.Error(err.Error())
	}
	assertEqual(t, res.Response[0].Id.Id, 74539435, "id")
}

func TestParseMonetaryAccounts(t *testing.T) {
	file, _ := os.Open("testdata/list-all-monetary-accounts-for-user.json")
	defer file.Close()
	rsp := &http.Response{
		StatusCode: 200,
		Body:       file,
	}
	res, err := ParseSlice[[]MonetaryAccount](rsp)
	if err != nil {
		t.Error(err.Error())
	}
	assertEqual(t, len(res.Response), 1, "len res")
	acc := res.Response[0].MonetaryAccountBank
	assertEqual(t, acc.Id, 1895767, "accountID")
	assertEqual(t, len(acc.Alias), 3, "aliases")
	assertEqual(t, acc.Alias[2].Value, "NL52BUNQ2117660061", "iban")
	assertEqual(t, acc.Avatar.Image[0].AttachmentPublicUuid, "8e18f165-f7a7-40e7-b809-74149cdb27fe", "image attachment id")
	assertEqual(t, acc.Avatar.Image[0].Urls[0].Url, "https://bunq-triage-model-storage-public.s3.eu-central-1.amazonaws.com/bunq_file/File/content/921ece497cd00f4e0cef3f0f63a962c31cf3f8e35311d127d5a7b23be3d074d5.png", "image url")
	assertEqual(t, acc.Balance.Value, "-9.99", "balance")
}

func TestParseMonetaryAccount(t *testing.T) {
	file, _ := os.Open("testdata/read-monetary-account-bank.json")
	defer file.Close()
	rsp := &http.Response{
		StatusCode: 200,
		Body:       file,
	}
	res, err := ParseSingle[MonetaryAccount](rsp)
	if err != nil {
		t.Error(err.Error())
	}
	acc := res.Response.MonetaryAccountBank
	assertEqual(t, acc.Id, 1234567, "accountID")
	assertEqual(t, len(acc.Alias), 2, "aliases")
	assertEqual(t, acc.Alias[0].Value, "NLxxBUNQxxxxxx", "iban")
	assertEqual(t, acc.Balance.Value, "123.45", "balance")
}

func TestParseError(t *testing.T) {
	file, _ := os.Open("testdata/error.json")
	defer file.Close()
	rsp := &http.Response{
		StatusCode: 200,
		Body:       file,
	}
	res, err := ParseSlice[[]MonetaryAccount](rsp)
	if err != nil {
		t.Error(err.Error())
	}
	if len(res.Errors) == 0 {
		t.Fatal("expected error")
	}
	assertEqual(t, res.Errors[0].ErrorDescription, "Insufficient authentication.", "err")
}

func assertEqual[V comparable](t *testing.T, got, expected V, field string) {
	t.Helper()

	if expected != got {
		t.Errorf(`assert.Equal %s
		got     : %v,
		expected: %v`, field, got, expected)
	}
}
