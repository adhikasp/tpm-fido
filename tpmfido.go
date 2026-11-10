package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psanford/tpm-fido/attestation"
	"github.com/psanford/tpm-fido/fidoauth"
	"github.com/psanford/tpm-fido/fidohid"
	"github.com/psanford/tpm-fido/memory"
	"github.com/psanford/tpm-fido/pinentry"
	"github.com/psanford/tpm-fido/sitesignatures"
	"github.com/psanford/tpm-fido/statuscode"
	"github.com/psanford/tpm-fido/tpm"
)

var backend = flag.String("backend", "tpm", "tpm|memory")
var device = flag.String("device", "/dev/tpmrm0", "TPM device path")
var origins = flag.String("origins", defaultOriginsPath(), "known site origins, one per line (# comments)")
var pinentryPath = flag.String("pinentry", "", "pinentry program to use (default: autodetect, first one that runs wins)")

func defaultOriginsPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "known-origins.txt"
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "tpm-fido", "known-origins.txt")
}

func main() {
	flag.Parse()

	if *pinentryPath != "" {
		pinentry.PrompterOverride = *pinentryPath
	}

	if n, err := sitesignatures.LoadFile(*origins); err != nil {
		log.Printf("reading origins file %s: %s", *origins, err)
	} else if n > 0 {
		log.Printf("loaded %d extra site name(s) from %s", n, *origins)
	}

	s := newServer()
	s.run()
}

// presencePrompt names the site the request is for, so the dialog is not blank.
// A site is only named when its application parameter matches a known origin;
// otherwise the user is told the site is unrecognised.
func presencePrompt(action string, appParam [32]byte) pinentry.Prompt {
	site, known := sitesignatures.Lookup(appParam)

	p := pinentry.Prompt{
		Title:  "Security key",
		OK:     "Allow",
		Cancel: "Cancel",
	}
	if known {
		p.Desc = site
	} else {
		p.Desc = "Unrecognised site (" + strings.TrimPrefix(site, "unknown site ") + ")"
	}

	switch action {
	case "register":
		p.Prompt = "Create a new security key for this site?"
	case "authenticate":
		p.Prompt = "Sign in to this site with the key?"
	default:
		p.Prompt = "Use the security key?"
	}
	return p
}

type server struct {
	pe     *pinentry.Pinentry
	signer Signer
}

type Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	Counter() uint32
}

func newServer() *server {
	s := server{
		pe: pinentry.New(),
	}
	if *backend == "tpm" {
		signer, err := tpm.New(*device)
		if err != nil {
			panic(err)
		}
		s.signer = signer
	} else if *backend == "memory" {
		signer, err := memory.New()
		if err != nil {
			panic(err)
		}
		s.signer = signer
	}
	return &s
}

func (s *server) run() {
	ctx := context.Background()

	if !pinentry.HasGUIPrompter() {
		log.Printf("warning: no gui pinentry binary found in PATH; requests will have nothing to confirm with")
	}

	token, err := fidohid.New(ctx, "tpm-fido")
	if err != nil {
		log.Fatalf("create fido hid error: %s", err)
	}

	go token.Run(ctx)

	for evt := range token.Events() {
		if evt.Error != nil {
			log.Printf("got token error: %s", err)
			continue
		}

		req := evt.Req

		if req.Command == fidoauth.CmdAuthenticate {
			log.Printf("got AuthenticateCmd site=%s", sitesignatures.FromAppParam(req.Authenticate.ApplicationParam))

			s.handleAuthenticate(ctx, token, evt)
		} else if req.Command == fidoauth.CmdRegister {
			log.Printf("got RegisterCmd site=%s", sitesignatures.FromAppParam(req.Register.ApplicationParam))
			s.handleRegister(ctx, token, evt)
		} else if req.Command == fidoauth.CmdVersion {
			log.Print("got VersionCmd")
			s.handleVersion(ctx, token, evt)
		} else {
			log.Printf("unsupported request type: 0x%02x\n", req.Command)
			// send a not supported error for any commands that we don't understand.
			// Browsers depend on this to detect what features the token supports
			// (i.e. the u2f backwards compatibility)
			token.WriteResponse(ctx, evt, nil, statuscode.ClaNotSupported)
		}
	}
}

func (s *server) handleVersion(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	token.WriteResponse(parentCtx, evt, []byte("U2F_V2"), statuscode.NoError)
}

func (s *server) handleAuthenticate(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle := req.Authenticate.KeyHandle
	appParam := req.Authenticate.ApplicationParam[:]

	dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))

	_, err := s.signer.SignASN1(keyHandle, appParam, dummySig[:])
	if err != nil {
		log.Printf("invalid key: %s (key handle size: %d)", err, len(keyHandle))

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}

		return
	}

	switch req.Authenticate.Ctrl {
	case fidoauth.CtrlCheckOnly,
		fidoauth.CtrlDontEnforeUserPresenceAndSign,
		fidoauth.CtrlEnforeUserPresenceAndSign:
	default:
		log.Printf("unknown authenticate control value: %d", req.Authenticate.Ctrl)

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send wrong-data msg err: %s", err)
		}
		return
	}

	if req.Authenticate.Ctrl == fidoauth.CtrlCheckOnly {
		// check if the provided key is known by the token
		log.Printf("check-only success")
		// test-of-user-presence-required: note that despite the name this signals a success condition
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}
		return
	}

	var userPresent uint8

	if req.Authenticate.Ctrl == fidoauth.CtrlEnforeUserPresenceAndSign {

		pinResultCh, err := s.pe.ConfirmPresence(presencePrompt("authenticate", req.Authenticate.ApplicationParam), req.Authenticate.ChallengeParam, req.Authenticate.ApplicationParam)

		if err != nil {
			log.Printf("pinentry err: %s", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)

			return
		}

		childCtx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
		defer cancel()

		select {
		case result := <-pinResultCh:
			if result.OK {
				userPresent = 0x01
			} else {
				if result.Error != nil {
					log.Printf("Got pinentry result err: %s", result.Error)
				}

				// Got user cancelation, we want to propagate that so the browser gives up.
				// This isn't normally supported by a key so there's no status code for this.
				// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
				err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
				if err != nil {
					log.Printf("Write WrongData resp err: %s", err)
				}
				return
			}
		case <-childCtx.Done():
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			if err != nil {
				log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			}
			return
		}
	}

	signCounter := s.signer.Counter()

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sig, err := s.signer.SignASN1(keyHandle, appParam, sigHash.Sum(nil))
	if err != nil {
		log.Fatalf("auth sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	err = token.WriteResponse(parentCtx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write auth response err: %s", err)
		return
	}
}

func (s *server) handleRegister(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	ctx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
	defer cancel()
	req := evt.Req

	pinResultCh, err := s.pe.ConfirmPresence(presencePrompt("register", req.Register.ApplicationParam), req.Register.ChallengeParam, req.Register.ApplicationParam)

	if err != nil {
		log.Printf("pinentry err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)

		return
	}

	select {
	case result := <-pinResultCh:
		if !result.OK {
			if result.Error != nil {
				log.Printf("Got pinentry result err: %s", result.Error)
			}

			// Got user cancelation, we want to propagate that so the browser gives up.
			// This isn't normally supported by a key so there's no status code for this.
			// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
			err := token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
			if err != nil {
				log.Printf("Write WrongData resp err: %s", err)
				return
			}
			return
		}

		s.registerSite(parentCtx, token, evt)
	case <-ctx.Done():
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func (s *server) registerSite(ctx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle, x, y, err := s.signer.RegisterKey(req.Register.ApplicationParam[:])
	if err != nil {
		log.Printf("RegisteKey err: %s", err)
		return
	}

	if len(keyHandle) > 255 {
		log.Printf("Error: keyHandle too large: %d, max=255", len(keyHandle))
		return
	}

	childPubKey := elliptic.Marshal(elliptic.P256(), x, y)

	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sum := sigHash.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sum)
	if err != nil {
		log.Fatalf("attestation sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	out.Write(sig)

	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write register response err: %s", err)
		return
	}
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
