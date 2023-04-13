# Golang

- [https://www.redteam.cafe/red-team/golang/red-team-how-to-embed-golang-tools-in-c](https://www.redteam.cafe/red-team/golang/red-team-how-to-embed-golang-tools-in-c)




## Obfuscate Go Tooling



### garble

Example with [chisel](https://github.com/jpillora/chisel):

```
$ go install mvdan.cc/garble@latest
$ go install github.com/jpillora/chisel@latest
$ git clone https://github.com/jpillora/chisel chisel-src && cd chisel-src
$ env CGO_ENABLE=1 GOOS=windows GOARCH=amd64 garble -literals -tiny build -trimpath
```

Example with [rsockstun](https://github.com/llkat/rsockstun):

```
$ git clone https://github.com/llkat/rsockstun rsockstun-src && cd rsockstun-src
$ go mod init rsockstun && go mod tidy
$ env CGO_ENABLE=1 GOOS=windows GOARCH=amd64 garble -literals -tiny build -trimpath
```
