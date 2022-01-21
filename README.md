#Krakend Custom Plugin

### How To Build?
1. build login plugin `go build -buildmode=plugin -o ./build/login.so ./login/plugin`
2. build middleware plugin `go build -buildmode=plugin -o ./build/middleware.so ./middleware/plugin`

### Reference
- https://www.krakend.io/docs/extending/writing-plugins/