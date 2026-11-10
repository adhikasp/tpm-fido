package sitesignatures

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"sync"
)

// from https://github.com/danstiner/rust-u2f/blob/master/u2f-core/src/known_app_ids.rs
// and https://github.com/github/SoftU2F/blob/master/SoftU2FTool/KnownFacets.swift
var builtin = map[[32]byte]string{
	hashURL("https://api-9dcf9b83.duosecurity.com"):             "duosecurity.com",
	hashURL("https://dashboard.stripe.com"):                     "dashboard.stripe.com",
	hashURL("https://demo.yubico.com"):                          "demo.yubico.com",
	hashURL("https://github.com/u2f/trusted_facets"):            "github.com",
	hashURL("https://gitlab.com"):                               "gitlab.com",
	hashURL("https://id.fedoraproject.org/u2f-origins.json"):    "id.fedoraproject.org",
	hashURL("https://keepersecurity.com"):                       "keepersecurity.com",
	hashURL("https://lastpass.com"):                             "lastpass.com",
	hashURL("https://mdp.github.io"):                            "mdp.github.io",
	hashURL("https://personal.vanguard.com"):                    "vanguard.com",
	hashURL("https://u2f.aws.amazon.com/app-id.json"):           "aws.amazon.com",
	hashURL("https://u2f.bin.coffee"):                           "u2f.bin.coffee",
	hashURL("https://vault.bitwarden.com/app-id.json"):          "vault.bitwarden.com",
	hashURL("https://www.dropbox.com/u2f-app-id.json"):          "dropbox.com",
	hashURL("https://www.fastmail.com"):                         "www.fastmail.com",
	hashURL("https://www.gstatic.com/securitykey/origins.json"): "google.com",

	hashURL("bin.coffee"):          "bin.coffee",
	hashURL("coinbase.com"):        "coinbase.com",
	hashURL("demo.yubico.com"):     "demo.yubico.com",
	hashURL("github.com"):          "github.com",
	hashURL("webauthn.bin.coffee"): "webauthn.bin.coffee",
	hashURL("webauthn.io"):         "webauthn.io",
}

var (
	mu     sync.RWMutex
	extra  = map[[32]byte]string{}
	loaded bool
)

func hashURL(url string) [32]byte {
	return sha256.Sum256([]byte(url))
}

// The application parameter a token sees is a SHA-256 of either the origin
// ("https://github.com", legacy U2F API) or the bare relying-party id
// ("github.com", WebAuthn over CTAP1). Register both shapes for every name so
// either kind of request resolves.
func Register(name string) {
	name = strings.TrimSpace(name)
	if name == "" || strings.HasPrefix(name, "#") {
		return
	}

	display := name
	switch {
	case strings.HasPrefix(name, "https://"):
		display = strings.TrimPrefix(name, "https://")
		registerHash(name, display)
		registerHash(strings.TrimSuffix(strings.TrimPrefix(name, "https://"), "/"), display)
	case strings.HasPrefix(name, "http://"):
		display = strings.TrimPrefix(name, "http://")
		registerHash(name, display)
		registerHash(strings.TrimSuffix(strings.TrimPrefix(name, "http://"), "/"), display)
	default:
		display = strings.TrimSuffix(name, "/")
		registerHash(display, display)
		registerHash("https://"+display, display)
		registerHash("http://"+display, display)
	}

}

func registerHash(origin, display string) {
	sig := hashURL(origin)
	mu.Lock()
	extra[sig] = display
	mu.Unlock()
}

// LoadFile reads one origin (or hostname) per line, ignoring blanks and lines
// starting with '#'. A missing file is not an error.
func LoadFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	mu.Lock()
	loaded = true
	before := len(extra)
	mu.Unlock()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		Register(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}

	mu.RLock()
	defer mu.RUnlock()
	return len(extra) - before, nil
}

// Lookup maps an application parameter to a site name. known is false when the
// origin is not in the built-in list or the user's origins file.
func Lookup(sig [32]byte) (site string, known bool) {
	if site, ok := builtin[sig]; ok {
		return site, true
	}
	mu.RLock()
	defer mu.RUnlock()
	if site, ok := extra[sig]; ok {
		return site, true
	}
	return fmt.Sprintf("unknown site %x", sig[:6]), false
}

func FromAppParam(sig [32]byte) string {
	site, _ := Lookup(sig)
	return site
}
