# bunqr

This is a go SDK for the Bunq API. The basics are there but is not a finished product - use at your own risk. There are no dependencies.

It contains a package for the OAuth2 authentication flow, based on the go http library, that can also be used independently.

The `SDK.Client` struct exposes all API endpoints of the Bunq API. **Some of them will not work out of the box!** See below for how to fix. It's because the code is generated from the API spec. Is this the best approach? In hindsight, probably not. But fixes are usually not difficult to make.

## Try it out

Review the Bunq [API documentation](https://doc.bunq.com/).

1. In the Bunq app, go to settings -> OAuth (under Developers). Fill in the callback URL (for the example it's `http://localhost:8080/callback`) and copy the client id and secret to your PC.
2.  ```
    export BUNQ_CLIENT_ID=<client id>
    export BUNQ_CLIENT_SECRET=<secret>
    ```
3. `cd example`
4. Generate a private key: `openssl genrsa -out private_key.pem 2048`. 
5. `go run .`
6. Open http://localhost:8080 in your browser.


## Using the SDK

Take a look at the [example](https://github.com/arner/bunqr/blob/main/example/main.go) for the example code. This code is not suitable for production as it is, but it gives a good idea of what you need to implement. You can use it with an API key or OAuth2 (recommended).

## Fixing the API

The code in the `client` package that calls the APIs is generated based on a tweaked version of the official [OpenAPI definition](https://github.com/bunq/doc/blob/develop/swagger.json). The definition is notoriously bad. That means there's a fair chance that if you try a function, it doesn't work right away and you have to fix the definition first to match the request and response, and regenerate the code.

Open `client/schema_fixed.json` and make your changes. It can help to store the response body as a json in `client/testdata` and write a test. Don't commit personal information.

Run `go mod tidy` once to download the oapi-codegen tool. Then execute:

```bash
cd client
go generate ./...

sed -i.bak -e 's/\*string/string/g' api.gen.go
sed -i.bak -e 's/\*int/int/g' api.gen.go
sed -i.bak -e 's/\*bool/bool/g' api.gen.go
sed -i.bak -e 's/\*\[\]/\[\]/g' api.gen.go
sed -i.bak -e 's/\*Amount/Amount/g' api.gen.go
sed -i.bak -e 's/CounterpartyAlias   \*/CounterpartyAlias   /g' api.gen.go
rm api.gen.go.bak
```

## Contribute

PRs with tests are welcome.
