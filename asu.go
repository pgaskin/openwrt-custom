package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"time"
)

var (
	dir      = "img"
	server   = "https://sysupgrade.openwrt.org"
	version  = "22.03.4"
	packages = []string{
		"luci", "-luci-theme-bootstrap", "luci-theme-openwrt",
		"luci-mod-admin-full", "luci-app-firewall",
		"-libustream-wolfssl", "libustream-openssl",
		"kmod-macvlan",
		"6rd", "6in4",
		"ppp", "luci-proto-ppp", "ppp-mod-pppoe",
		"kmod-wireguard", "wireguard-tools", "luci-app-wireguard", "luci-proto-wireguard",
		"kmod-usb-net-rndis", "kmod-usb-net-cdc-ncm",
		"relayd", "luci-proto-relay",
		"gre", "luci-proto-gre",
		"ipip", "luci-proto-ipip",
		"vxlan", "luci-proto-vxlan",
		"-wpad-basic-wolfssl", "wpad-openssl",
		"ddns-scripts", "luci-app-ddns",
		"qosify",
		"usteer",
		"umdns",
		"tcpdump", "iperf3", "ss", "knot-host", "knot-dig", "curl", "tc-full", "ip-full", "iw-full",
		"nano", "htop", "ncdu", "xxd", "strace", "htop", "jq", "netcat", "nmap", "mtr",
		"conntrack", "iputils-ping", "iputils-arping", "socat", "ip-bridge",
		"muninlite",
		"prometheus-node-exporter-lua", "prometheus-node-exporter-lua-wifi", "prometheus-node-exporter-lua-wifi_stations",
		"prometheus-node-exporter-lua-openwrt", "prometheus-node-exporter-lua-uci_dhcp_host",
	}
	devices = [][2]string{
		{"ipq40xx/mikrotik", "mikrotik_hap-ac2"},
		{"ath79/generic", "tplink_archer-c7-v4"},
		{"ath79/generic", "tplink_archer-c7-v5"},
		{"mediatek/mt7622", "linksys_e8450-ubi"},
	}
	extraPackages = map[[2]string][]string{
		{"ath79/generic", "tplink_archer-c7-v4"}: {
			"-ath10k-firmware-qca988x-ct", "ath10k-firmware-qca988x",
			"-kmod-ath10k-ct", "kmod-ath10k",
		},
		{"ath79/generic", "tplink_archer-c7-v5"}: {
			"-ath10k-firmware-qca988x-ct", "ath10k-firmware-qca988x",
			"-kmod-ath10k-ct", "kmod-ath10k",
		},
	}
	snapshotTargets = map[string]bool{
		"ipq40xx/mikrotik": true,
	}
	snapshotReleaseTargets = map[string]bool{
	}
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "openwrt_defconfig_packages" {
		// this can be added to the end of an official defconfig
		for _, x := range packages {
			if x[0] != '-' {
				fmt.Println("CONFIG_PACKAGE_" + x + "=y")
			}
		}
		for _, x := range packages {
			if x[0] == '-' {
				fmt.Println("# CONFIG_PACKAGE_" + x[1:] + " is not set")
			}
		}
		return
	}

	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	if err := os.Mkdir(dir, 0777); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	if err := os.Chdir(dir); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	var w1, w2 int
	for _, dev := range devices {
		if x := len(dev[0]); x > w1 {
			w1 = x
		}
		if x := len(dev[1]); x > w2 {
			w2 = x
		}
	}

	for _, dev := range devices {
		fmt.Printf("%*s  %*s  waiting\n", -w1, dev[0], -w2, dev[1])
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	dch := []chan any{}
	for _, dev := range devices {
		var vr string
		if snapshotTargets[dev[0]] {
			vr = "SNAPSHOT"
		} else if snapshotReleaseTargets[dev[0]] {
			vr = version[:strings.LastIndex(version, ".")] + "-SNAPSHOT"
		} else {
			vr = version
		}
		dch = append(dch, asu(ctx, vr, dev[0], dev[1], append(append([]string{}, packages...), extraPackages[dev]...)...))
	}

	sci := make([]int, len(dch))
	sch := make([]reflect.SelectCase, len(dch))
	for i, ch := range dch {
		sci[i] = i
		sch[i].Dir = reflect.SelectRecv
		sch[i].Chan = reflect.ValueOf(ch)
	}

	dst := make([]string, len(dch))
	var errored bool
	for len(sch) != 0 {
		i, status, ok := reflect.Select(sch)
		if !ok {
			sci = append(sci[:i], sci[i+1:]...)
			sch = append(sch[:i], sch[i+1:]...)
			continue
		}
		i = sci[i]

		select {
		case <-ctx.Done():
			continue
		default:
		}

		var err error
		switch status := status.Interface().(type) {
		case string:
			dst[i] = status
		case error:
			dst[i] = "error: " + status.Error()
			err = status
		default:
			panic("invalid type")
		}

		fmt.Printf("\x1B[%dA", len(devices))
		for j, dev := range devices {
			fmt.Printf("\x1B[2K%*s  %*s  %s\n", -w1, dev[0], -w2, dev[1], dst[j])
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			cancel()
			errored = true
		}
	}

	if errored {
		os.Exit(1)
	}
}

func asu(ctx context.Context, version, target, profile string, packages ...string) chan any {
	ch := make(chan any)
	go asu1(ctx, ch, version, target, profile, packages...)
	return ch
}

func asu1(ctx context.Context, ch chan any, version, target, profile string, packages ...string) {
	defer close(ch)

	var hash string
	var res *BuildResponse
	for res == nil {
		select {
		case <-ctx.Done():
			ch <- ctx.Err()
			return
		default:
		}

		var obj any
		var err error
		if hash == "" {
			ch <- "submitting request"
			obj, err = asu1req(ctx, version, target, profile, packages...)
		} else {
			obj, err = asu1status(ctx, hash)
		}
		if err != nil {
			ch <- fmt.Errorf("asu request: %w", err)
			return
		}
		switch obj := obj.(type) {
		case *BuildStatus:
			if obj.RequestHash != "" {
				hash = obj.RequestHash
			}
			switch v := obj.Value().(type) {
			case string:
				ch <- v
			case error:
				ch <- fmt.Errorf("build failed: %w", v)
				return
			default:
				panic("invalid type")
			}
			time.Sleep(time.Second)
		case *BuildResponse:
			res = obj
		default:
			panic("invalid type")
		}
	}

	if _, err := os.Stat(res.ImagePrefix + ".json"); err == nil {
		ch <- fmt.Errorf("save result: output file already exists")
		return
	}
	if err := os.WriteFile(res.ImagePrefix+".json", res.Orig, 0666); err != nil {
		ch <- fmt.Errorf("save result: %w", err)
		return
	}
	if !res.BuildAt.IsZero() {
		_ = os.Chtimes(res.ImagePrefix+".json", time.Now(), res.BuildAt)
	}

	for i, x := range res.Images {
		select {
		case <-ctx.Done():
			ch <- ctx.Err()
			return
		default:
		}

		ch <- fmt.Sprintf("downloading [%d/%d] %s", i+1, len(res.Images), x.Name)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/store/"+res.BinDir+"/"+x.Name, nil)
		if err != nil {
			ch <- fmt.Errorf("download %s: %w", x.Name, err)
			return
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			ch <- fmt.Errorf("download %s: %w", x.Name, err)
			return
		}
		defer resp.Body.Close()

		f, err := os.CreateTemp(".", ".auc-*")
		if err != nil {
			ch <- fmt.Errorf("download %s: %w", x.Name, err)
			return
		}
		defer os.Remove(f.Name())

		c := &countReader{
			R: resp.Body,
			F: func(n int) {
				if resp.ContentLength != 0 {
					ch <- fmt.Sprintf("downloading [%d/%d] %s (%.1f/%.1f MiB) %.0f%%", i+1, len(res.Images), x.Name, float64(n)/1048576, float64(resp.ContentLength)/1048576, float64(n)/float64(resp.ContentLength)*100)
				} else {
					ch <- fmt.Sprintf("downloading %d/%d %s (%.1f/... MiB)", i+1, len(res.Images), x.Name, float64(n)/1048576)
				}
			},
		}
		c.F(0)

		h := sha256.New()
		if _, err := io.CopyBuffer(io.MultiWriter(f, h), c, make([]byte, 102400)); err != nil {
			ch <- fmt.Errorf("download %s: %w", x.Name, err)
			return
		}
		resp.Body.Close()

		if sha := hex.EncodeToString(h.Sum(nil)); sha != x.SHA256 {
			ch <- fmt.Errorf("download %s: expected sha256:%s, got sha256:%s", x.Name, x.SHA256, sha)
			return
		}

		if err := f.Sync(); err != nil {
			ch <- fmt.Errorf("download %s: %w", x.Name, err)
			return
		}

		if err := f.Close(); err != nil {
			ch <- fmt.Errorf("download %s: %w", x.Name, err)
			return
		}

		if _, err := os.Stat(x.Name); err == nil {
			ch <- fmt.Errorf("download %s: output file already exists", x.Name)
			return
		}

		if err := os.Rename(f.Name(), x.Name); err != nil {
			ch <- fmt.Errorf("download %s: %w", x.Name, err)
			return
		}

		if v := resp.Header.Get("Last-Modified"); v != "" {
			if t, err := time.Parse(http.TimeFormat, v); err == nil && !t.IsZero() {
				_ = os.Chtimes(x.Name, time.Now(), t)
			}
		}
	}

	ch <- "done: " + res.ImagePrefix
}

type BuildRequest struct {
	Version  string   `json:"version"`
	Profile  string   `json:"profile"`
	Target   string   `json:"target"`
	Packages []string `json:"packages"`
}

type BuildStatus struct {
	Detail      string `json:"detail"`
	EnqueuedAt  string `json:"enqueued_at"`
	RequestHash string `json:"request_hash"`
	Status      int    `json:"status"`
	Type        string `json:"type"`
}

func (s BuildStatus) String() string {
	return s.Detail
}

func (s BuildStatus) Value() any {
	if s.Status != 200 && s.Status != 202 {
		return fmt.Errorf("%v (status %d)", s.Detail, s.Status)
	}
	return s.Detail
}

type BuildResponse struct {
	ArchPackages       string    `json:"arch_packages"`
	BinDir             string    `json:"bin_dir"`
	BuildAt            time.Time `json:"build_at"`
	BuildCmd           []string  `json:"build_cmd"`
	DefaultPackages    []string  `json:"default_packages"`
	Detail             string    `json:"detail"`
	DevicePackages     []string  `json:"device_packages"`
	EnqueuedAt         time.Time `json:"enqueued_at"`
	ID                 string    `json:"id"`
	ImagePrefix        string    `json:"image_prefix"`
	ImagebuilderStatus string    `json:"imagebuilder_status"`
	Images             []struct {
		Filesystem     string `json:"filesystem"`
		Name           string `json:"name"`
		SHA256         string `json:"sha256"`
		SHA256Unsigned string `json:"sha256_unsigned"`
		Type           string `json:"type"`
	} `json:"images"`
	Manifest         map[string]string `json:"manifest"`
	MetadataVersion  int               `json:"metadata_version"`
	RequestHash      string            `json:"request_hash"`
	SourceDateEpoch  int               `json:"source_date_epoch"`
	Status           int               `json:"status"`
	Stderr           string            `json:"stderr"`
	Stdout           string            `json:"stdout"`
	SupportedDevices []string          `json:"supported_devices"`
	Target           string            `json:"target"`
	Titles           []struct {
		Model  string `json:"model"`
		Vendor string `json:"vendor"`
	} `json:"titles"`
	VersionCode   string          `json:"version_code"`
	VersionNumber string          `json:"version_number"`
	Orig          json.RawMessage `json:"-"`
}

func asu1req(ctx context.Context, version, target, profile string, packages ...string) (any, error) {
	buf, err := json.Marshal(BuildRequest{
		Version:  version,
		Profile:  profile,
		Target:   target,
		Packages: packages,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/build", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return asu1resp(resp.StatusCode, resp.Body)
}

func asu1status(ctx context.Context, hash string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/api/v1/build/"+url.PathEscape(hash), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return asu1resp(resp.StatusCode, resp.Body)
}

func asu1resp(status int, body io.Reader) (any, error) {
	buf, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	if status == http.StatusOK {
		var obj BuildResponse
		if err := json.Unmarshal(buf, &obj); err != nil {
			return "", err
		}
		obj.Orig = json.RawMessage(buf)
		return &obj, nil
	} else {
		var obj BuildStatus
		if err := json.Unmarshal(buf, &obj); err != nil {
			return "", err
		}
		return &obj, nil
	}
}

type countReader struct {
	R io.Reader
	N int
	F func(int)
}

func (c *countReader) Read(p []byte) (n int, err error) {
	n, err = c.R.Read(p)
	if c.N += n; c.F != nil {
		c.F(c.N)
	}
	return n, err
}
