package snowflake

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	sf "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"
)

const transportName = "snowflake"

type Transport struct{}

// Name returns the name of the snowflake transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new snowflakeClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := &snowflakeClientFactory{transport: t}
	return cf, nil
}

// ServerFactory is not implemented for snowflake
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	return nil, errors.New("ServerFactory not implemented for the snowflake transport")
}

type snowflakeClientFactory struct {
	transport base.Transport
}

func (cf *snowflakeClientFactory) Transport() base.Transport {
	return cf.transport
}

func (cf *snowflakeClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	config := sf.ClientConfig{}
	if arg, ok := args.Get("ampcache"); ok {
		config.AmpCacheURL = arg
	}
	if arg, ok := args.Get("sqsqueue"); ok {
		config.SQSQueueURL = arg
	}
	if arg, ok := args.Get("sqscreds"); ok {
		config.SQSCredsStr = arg
	}
	if arg, ok := args.Get("fronts"); ok {
		if arg != "" {
			config.FrontDomains = strings.Split(strings.TrimSpace(arg), ",")
		}
	} else if arg, ok := args.Get("front"); ok {
		config.FrontDomains = strings.Split(strings.TrimSpace(arg), ",")
	}
	if arg, ok := args.Get("ice"); ok {
		config.ICEAddresses = strings.Split(strings.TrimSpace(arg), ",")
	}
	if arg, ok := args.Get("max"); ok {
		max, err := strconv.Atoi(arg)
		if err != nil {
			return nil, fmt.Errorf("Invalid SOCKS arg: max=%s", arg)
		}
		config.Max = max
	}
	if arg, ok := args.Get("url"); ok {
		config.BrokerURL = arg
	}
	if arg, ok := args.Get("utls-nosni"); ok {
		switch strings.ToLower(arg) {
		case "true", "yes":
			config.UTLSRemoveSNI = true
		}
	}
	if arg, ok := args.Get("utls-imitate"); ok {
		config.UTLSClientID = arg
	}
	if arg, ok := args.Get("fingerprint"); ok {
		config.BridgeFingerprint = arg
	}
	return config, nil
}

func (cf *snowflakeClientFactory) Dial(network, address string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	config, ok := args.(sf.ClientConfig)
	if !ok {
		return nil, errors.New("invalid type for args")
	}
	transport, err := sf.NewSnowflakeClient(config)
	if err != nil {
		return nil, err
	}
	return transport.Dial()
}
