package pinentry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
)

// Prompt is what the user sees when the token asks for confirmation. Empty
// fields fall back to the old generic labels.
type Prompt struct {
	Title  string // window title (default "TPM-FIDO")
	Desc   string // the site asking, shown at the top
	Prompt string // the question above the buttons
	OK     string // label for the accept button
	Cancel string // label for the decline button
}

func New() *Pinentry {
	return &Pinentry{}
}

type Pinentry struct {
	mu            sync.Mutex
	activeRequest *request
}

type request struct {
	timeout       time.Duration
	pendingResult chan Result
	extendTimeout chan time.Duration

	challengeParam   [32]byte
	applicationParam [32]byte
}

type Result struct {
	OK    bool
	Error error
}

func (pe *Pinentry) ConfirmPresence(pd Prompt, challengeParam, applicationParam [32]byte) (chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	timeout := 10 * time.Second

	if pe.activeRequest != nil {
		if challengeParam != pe.activeRequest.challengeParam || applicationParam != pe.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := pe.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(timeout):
				log.Printf("pinentry: could not extend confirmation timeout")
			}
		}()

		return pe.activeRequest.pendingResult, nil
	}

	pe.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
	}

	go pe.prompt(pe.activeRequest, pd)

	return pe.activeRequest.pendingResult, nil
}

func (pe *Pinentry) prompt(req *request, pd Prompt) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(req.timeout):
			// we expect requests to come in every ~750ms.
			// If we've been waiting for 2 seconds the client
			// is likely gone.
		}

		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, cmd, err := launchPinEntry(childCtx)
	if err != nil {
		sendResult(Result{
			OK:    false,
			Error: fmt.Errorf("failed to start pinentry: %w", err),
		})
		return
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	title := pd.Title
	if title == "" {
		title = "TPM-FIDO"
	}
	p.SetTitle(title)
	if pd.Desc != "" {
		p.SetDesc(pd.Desc)
	}
	if pd.Prompt != "" {
		p.SetPrompt(pd.Prompt)
	} else {
		p.SetPrompt(title)
	}
	if pd.OK != "" {
		p.SetOkBtn(pd.OK)
	}
	if pd.Cancel != "" {
		p.SetCancelBtn(pd.Cancel)
	}

	promptResult := make(chan bool)

	go func() {
		err := p.Confirm()
		promptResult <- err == nil
	}()

	timer := time.NewTimer(req.timeout)

	for {
		select {
		case ok := <-promptResult:
			sendResult(Result{
				OK: ok,
			})
			return
		case <-timer.C:
			sendResult(Result{
				OK:    false,
				Error: errors.New("request timed out"),
			})
			return
		case d := <-req.extendTimeout:
			log.Printf("pinentry: extending confirmation timeout by %s", d)
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
	}
}

// PrompterOverride names a specific pinentry binary to use, set from -pinentry
// or TPM_FIDO_PINENTRY. Empty means autodetect.
var PrompterOverride string

// Prompters are tried in order. pinentry-gnome3 comes first because its dialog
// is the most likely to exist on a desktop, but every entry is treated as a
// candidate rather than a promise: a prompter that fails to start is skipped
// instead of leaving the user staring at a browser with no dialog (upstream
// issues #45, #29, #41).
var guiPrompters = []string{
	"pinentry-gnome3",
	"pinentry-qt6",
	"pinentry-qt5",
	"pinentry-qt4",
	"pinentry-qt",
	"pinentry-gtk-2",
	"pinentry-gtk",
	"pinentry-x11",
	"pinentry-fltk",
	"pinentry-bemenu",
}

// HasGUIPrompter reports whether any known prompter binary is installed. Used
// once at startup so a missing prompter is a warning in the log, not a minute
// of a browser waiting for a dialog that can never appear.
func HasGUIPrompter() bool {
	for _, name := range guiPrompters {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

// prompterCandidates returns the binaries to try, with an explicit override
// first. The rest of the list still follows, so a typo or a package removal
// degrades to a working dialog instead of no dialog at all.
func prompterCandidates() []string {
	override := PrompterOverride
	if override == "" {
		override = os.Getenv("TPM_FIDO_PINENTRY")
	}
	if override == "" {
		return guiPrompters
	}
	return append([]string{override}, guiPrompters...)
}

func launchPinEntry(ctx context.Context) (*pinentry.Client, *exec.Cmd, error) {
	var tried []string

	for _, name := range prompterCandidates() {
		path, err := exec.LookPath(name)
		if err != nil {
			tried = append(tried, name+" (not installed)")
			continue
		}

		c, cmd, err := startPinEntry(ctx, path)
		if err != nil {
			// The common failure is a binary that exists but cannot run (a
			// removed shared library, no display, a sandbox). Say so: silence
			// here is what makes "the key does nothing" impossible to debug.
			log.Printf("pinentry: %s unusable: %s", path, err)
			tried = append(tried, path+" ("+err.Error()+")")
			continue
		}

		log.Printf("pinentry: using %s", path)
		return c, cmd, nil
	}

	// Last resort: the distro's pinentry dispatcher, which knows about
	// /etc/pinentry/preexec. It may be curses, but it is better than nothing.
	if path, err := exec.LookPath("pinentry"); err == nil {
		if c, cmd, err := startPinEntry(ctx, path); err == nil {
			log.Printf("pinentry: using %s (fallback)", path)
			return c, cmd, nil
		} else {
			tried = append(tried, path+" ("+err.Error()+")")
		}
	}

	return nil, nil, fmt.Errorf("no usable pinentry program (tried %s)", strings.Join(tried, "; "))
}

func startPinEntry(ctx context.Context, path string) (*pinentry.Client, *exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, path)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	var c pinentry.Client
	c.Session, err = assuan.Init(assuan.ReadWriteCloser{
		ReadCloser:  stdout,
		WriteCloser: stdin,
	})
	if err != nil {
		// Reap the child: a prompter that failed its INIT handshake has
		// already exited or is about to, and leaving a zombie per attempt
		// would leak one for every request.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, err
	}

	return &c, cmd, nil
}
