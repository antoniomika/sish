module github.com/antoniomika/sish

go 1.16

require (
	github.com/ScaleFT/sshkeys v0.0.0-20200327173127-6142f742bca5
	github.com/caddyserver/certmagic v0.14.1
	github.com/fsnotify/fsnotify v1.4.9
	github.com/gin-gonic/gin v1.7.3
	github.com/go-playground/validator/v10 v10.8.0 // indirect
	github.com/gorilla/websocket v1.4.2
	github.com/jpillora/ipfilter v1.2.2
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/miekg/dns v1.1.43 // indirect
	github.com/mikesmitty/edkey v0.0.0-20170222072505-3356ea4e686a
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/phuslu/iploc v1.0.20210730 // indirect
	github.com/pires/go-proxyproto v0.6.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cast v1.4.0 // indirect
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/ugorji/go v1.2.6 // indirect
	github.com/vulcand/oxy v1.3.0
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.18.1 // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace github.com/vulcand/oxy => github.com/antoniomika/oxy v1.1.1-0.20210804032133-5924ea01c950
