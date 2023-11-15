module github.com/brocaar/chirpstack-application-server

go 1.16

require (
	github.com/NickBall/go-aes-key-wrap v0.0.0-20170929221519-1c3aa3e4dfc5
	github.com/aws/aws-sdk-go v1.47.7
	github.com/brocaar/chirpstack-api/go/v3 v3.12.5
	github.com/brocaar/lorawan v0.0.0-20230609081225-559f55342122
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/eclipse/paho.mqtt.golang v1.4.3
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gofrs/uuid v4.4.0+incompatible
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/golang-migrate/migrate/v4 v4.16.2
	github.com/golang/protobuf v1.5.3
	github.com/goreleaser/goreleaser v0.106.0
	github.com/goreleaser/nfpm v0.11.0
	github.com/gorilla/mux v1.8.1
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.16.0
	github.com/jmoiron/sqlx v1.3.5
	github.com/lib/pq v1.10.9
	github.com/mmcloughlin/geohash v0.10.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.17.0
	github.com/robertkrimen/otto v0.2.1
	github.com/segmentio/kafka-go v0.4.44
	github.com/sirupsen/logrus v1.9.3
	github.com/smartystreets/goconvey v1.6.4
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.17.0
	github.com/streadway/amqp v1.1.0
	github.com/stretchr/testify v1.8.4
	github.com/tmc/grpc-websocket-proxy v0.0.0-20220101234140-673ab2c3ae75
	golang.org/x/crypto v0.15.0
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616
	golang.org/x/net v0.18.0
	golang.org/x/oauth2 v0.14.0
	golang.org/x/tools v0.15.0
	google.golang.org/grpc v1.59.0
)

require (
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20190430165422-3e4dfb77656c // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/klauspost/compress v1.17.2 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pierrec/lz4/v4 v4.1.18 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/smartystreets/assertions v1.0.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20231108232855-2478ac86f678 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231106174013-bbf56f31fb17 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)

replace github.com/brocaar/chirpstack-api/go/v3 => ../chirpstack-api/go
