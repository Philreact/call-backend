package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

const (
	discoveryTimeout = 8 * time.Second
	leaseSeconds     = 7200
	stateMaxAge      = 3 * time.Hour
)

type portList []uint16

func (ports *portList) String() string {
	values := make([]string, len(*ports))
	for index, port := range *ports {
		values[index] = strconv.Itoa(int(port))
	}
	return strings.Join(values, ",")
}

func (ports *portList) Set(value string) error {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || parsed == 0 {
		return fmt.Errorf("invalid UDP port %q", value)
	}
	*ports = append(*ports, uint16(parsed))
	return nil
}

type state struct {
	Version    int      `json:"version"`
	PublicHost string   `json:"publicHost"`
	Ports      []uint16 `json:"ports"`
	Mode       string   `json:"mode"`
	UpdatedAt  int64    `json:"updatedAt"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var ports portList
	stateFile := flag.String("state-file", "/data/network/reachability.json", "shared reachability state file")
	publicHost := flag.String("public-host", "", "explicit literal public IP")
	useUPnP := flag.Bool("upnp", true, "use UPnP when no public IPv4 is attached")
	health := flag.Bool("health", false, "validate the current state file and exit")
	flag.Var(&ports, "port", "UDP port to expose; repeat for each service")
	flag.Parse()

	if *health {
		if err := checkState(*stateFile, time.Now()); err != nil {
			return fmt.Errorf("network helper unhealthy: %w", err)
		}
		return nil
	}
	ports = normalizedPorts(ports)
	if len(ports) == 0 {
		return errors.New("at least one --port is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer os.Remove(*stateFile)

	if strings.TrimSpace(*publicHost) != "" {
		host, err := parsePublicHost(*publicHost)
		if err != nil {
			return fmt.Errorf("invalid --public-host: %w", err)
		}
		return serveDirect(ctx, *stateFile, host, ports, "configured")
	}
	if host, ok := attachedPublicHost(true); ok {
		return serveDirect(ctx, *stateFile, host, ports, "direct")
	}
	if *useUPnP {
		mapping, err := openMappings(ctx, ports)
		if err == nil {
			defer mapping.close()
			fmt.Fprintf(os.Stderr, "UPnP mapped UDP ports %s; public host %s\n", ports.String(), mapping.publicIP)
			if err = writeState(*stateFile, mapping.publicIP, ports, "upnp"); err != nil {
				return fmt.Errorf("write reachability state: %w", err)
			}
			if err = mapping.maintain(ctx, func(host netip.Addr) error {
				return writeState(*stateFile, host, ports, "upnp")
			}); err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("UPnP mapping lost: %w", err)
			}
			return nil
		}
		fmt.Fprintf(os.Stderr, "UPnP unavailable: %v\n", err)
	}
	if host, ok := attachedPublicHost(false); ok {
		return serveDirect(ctx, *stateFile, host, ports, "direct")
	}
	return errors.New("no reachable public address: set QAPP_BACKEND_PUBLIC_HOST or enable UPnP")
}

func serveDirect(ctx context.Context, path string, host netip.Addr, ports portList, mode string) error {
	if err := writeState(path, host, ports, mode); err != nil {
		return fmt.Errorf("write reachability state: %w", err)
	}
	fmt.Fprintf(os.Stderr, "backend public host %s (%s); UDP ports %s\n", host, mode, ports.String())
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if mode == "direct" {
				current, ok := attachedPublicHost(host.Is4())
				if !ok {
					return errors.New("direct public address is no longer attached")
				}
				host = current
			}
			if err := writeState(path, host, ports, mode); err != nil {
				return fmt.Errorf("refresh reachability state: %w", err)
			}
		}
	}
}

func normalizedPorts(input portList) portList {
	seen := make(map[uint16]struct{}, len(input))
	result := make(portList, 0, len(input))
	for _, port := range input {
		if _, exists := seen[port]; !exists {
			seen[port] = struct{}{}
			result = append(result, port)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func writeState(path string, host netip.Addr, ports portList, mode string) error {
	if !host.IsValid() || !isPublicInternetAddress(host) {
		return errors.New("resolved host is not a public internet address")
	}
	document, err := json.Marshal(state{1, host.Unmap().String(), ports, mode, time.Now().UnixMilli()})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err = os.WriteFile(temporary, append(document, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func checkState(path string, now time.Time) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var value state
	if err = json.Unmarshal(raw, &value); err != nil {
		return err
	}
	host, err := netip.ParseAddr(value.PublicHost)
	if err != nil || value.Version != 1 || !isPublicInternetAddress(host) || len(value.Ports) == 0 {
		return errors.New("invalid reachability state")
	}
	updated := time.UnixMilli(value.UpdatedAt)
	if updated.After(now.Add(time.Minute)) || now.Sub(updated) > stateMaxAge {
		return errors.New("stale reachability state")
	}
	return nil
}

func parsePublicHost(value string) (netip.Addr, error) {
	host, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !isPublicInternetAddress(host) {
		return netip.Addr{}, errors.New("must be a literal public IP address")
	}
	return host.Unmap(), nil
}

func attachedPublicHost(ipv4Only bool) (netip.Addr, bool) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, false
	}
	var candidates []netip.Addr
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := networkInterface.Addrs()
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil {
				continue
			}
			address := prefix.Addr().Unmap()
			if isPublicInternetAddress(address) && (!ipv4Only || address.Is4()) {
				candidates = append(candidates, address)
			}
		}
	}
	if len(candidates) == 0 {
		return netip.Addr{}, false
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].String() < candidates[j].String() })
	return candidates[0], true
}

func isPublicInternetAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.Is4() {
		value := address.As4()
		if value[0] == 0 || value[0] >= 224 || (value[0] == 100 && value[1] >= 64 && value[1] <= 127) || (value[0] == 192 && value[1] == 0) || (value[0] == 198 && (value[1] == 18 || value[1] == 19)) || (value[0] == 198 && value[1] == 51 && value[2] == 100) || (value[0] == 203 && value[1] == 0 && value[2] == 113) {
			return false
		}
	}
	return !netip.MustParsePrefix("2001:db8::/32").Contains(address)
}

type gatewayClient interface {
	LocalAddr() net.IP
	GetExternalIPAddressCtx(context.Context) (string, error)
	AddPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMappingCtx(context.Context, string, uint16, string) error
}

type mappings struct {
	client   gatewayClient
	ports    portList
	localIP  string
	publicIP netip.Addr
}

func openMappings(ctx context.Context, ports portList) (*mappings, error) {
	discoveryContext, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	clients, discoveryErrors, discoveryErr := discoverClients(discoveryContext)
	var failures []string
	for _, err := range discoveryErrors {
		failures = append(failures, err.Error())
	}
	if discoveryErr != nil {
		failures = append(failures, discoveryErr.Error())
	}
	for _, client := range clients {
		mapping, err := mapWithClient(ctx, client, ports)
		if err == nil {
			return mapping, nil
		}
		failures = append(failures, err.Error())
	}
	if len(failures) == 0 {
		return nil, errors.New("no UPnP Internet Gateway Device found")
	}
	return nil, errors.New(strings.Join(failures, "; "))
}

func mapWithClient(ctx context.Context, client gatewayClient, ports portList) (*mappings, error) {
	external, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("read router external IP: %w", err)
	}
	publicIP, err := netip.ParseAddr(strings.TrimSpace(external))
	if err != nil || !isPublicInternetAddress(publicIP) {
		return nil, fmt.Errorf("router reported non-public external IP %q", external)
	}
	localIP := client.LocalAddr().String()
	if parsed := net.ParseIP(localIP); parsed == nil || parsed.IsUnspecified() {
		return nil, errors.New("UPnP gateway did not provide a usable local address")
	}
	mapping := &mappings{client: client, ports: ports, localIP: localIP, publicIP: publicIP.Unmap()}
	if err = mapping.add(ctx); err != nil {
		mapping.close()
		return nil, err
	}
	return mapping, nil
}

func (mapping *mappings) add(ctx context.Context) error {
	for _, port := range mapping.ports {
		requestContext, cancel := context.WithTimeout(ctx, discoveryTimeout)
		err := mapping.client.AddPortMappingCtx(requestContext, "", port, "UDP", port, mapping.localIP, true, "Qortal private transport", leaseSeconds)
		cancel()
		if err != nil {
			return fmt.Errorf("map UDP %d: %w", port, err)
		}
	}
	return nil
}

func (mapping *mappings) maintain(ctx context.Context, update func(netip.Addr) error) error {
	ticker := time.NewTicker(time.Duration(leaseSeconds/2) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := mapping.add(ctx); err != nil {
				return err
			}
			external, err := mapping.client.GetExternalIPAddressCtx(ctx)
			address, parseErr := netip.ParseAddr(strings.TrimSpace(external))
			if err != nil || parseErr != nil || !isPublicInternetAddress(address) {
				return errors.New("router no longer reports a public address")
			}
			mapping.publicIP = address.Unmap()
			if err = update(mapping.publicIP); err != nil {
				return err
			}
		}
	}
}

func (mapping *mappings) close() {
	for _, port := range mapping.ports {
		ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
		_ = mapping.client.DeletePortMappingCtx(ctx, "", port, "UDP")
		cancel()
	}
}

func discoverClients(ctx context.Context) ([]gatewayClient, []error, error) {
	var clients []gatewayClient
	var discoveryErrors []error
	var fatalErrors []error
	ip2, errs, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	for _, client := range ip2 {
		clients = append(clients, client)
	}
	discoveryErrors = append(discoveryErrors, errs...)
	if err != nil {
		fatalErrors = append(fatalErrors, err)
	}
	ip1, errs, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	for _, client := range ip1 {
		clients = append(clients, client)
	}
	discoveryErrors = append(discoveryErrors, errs...)
	if err != nil {
		fatalErrors = append(fatalErrors, err)
	}
	ppp1, errs, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx)
	for _, client := range ppp1 {
		clients = append(clients, client)
	}
	discoveryErrors = append(discoveryErrors, errs...)
	if err != nil {
		fatalErrors = append(fatalErrors, err)
	}
	return clients, discoveryErrors, errors.Join(fatalErrors...)
}
