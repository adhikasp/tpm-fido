package pinentry

import (
	"context"
	"os/exec"
	"testing"
)

func TestPrompterCandidatesOverrideFirst(t *testing.T) {
	old := PrompterOverride
	defer func() { PrompterOverride = old }()

	PrompterOverride = "/usr/bin/some-prompter"
	got := prompterCandidates()

	if len(got) < 2 || got[0] != "/usr/bin/some-prompter" {
		t.Fatalf("override should come first, got %v", got)
	}
	// The built-in list must still follow, so a broken override degrades to a
	// working dialog instead of none.
	if got[1] != guiPrompters[0] {
		t.Fatalf("expected %q after the override, got %q", guiPrompters[0], got[1])
	}
}

func TestPrompterCandidatesEnvFallback(t *testing.T) {
	old := PrompterOverride
	PrompterOverride = ""
	defer func() { PrompterOverride = old }()

	t.Setenv("TPM_FIDO_PINENTRY", "/opt/custom/pinentry")
	if got := prompterCandidates(); got[0] != "/opt/custom/pinentry" {
		t.Fatalf("env override ignored, got %v", got)
	}

	// The flag beats the environment.
	PrompterOverride = "/flag/wins"
	if got := prompterCandidates(); got[0] != "/flag/wins" {
		t.Fatalf("flag should beat env, got %v", got)
	}
}

// A prompter that cannot complete the assuan handshake must be reported as an
// error rather than handed back as a usable client. This is the case that used
// to surface as a browser spinning forever with no dialog (upstream #45).
func TestStartPinEntryRejectsBrokenProgram(t *testing.T) {
	path, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no /bin/false to test with")
	}

	if _, _, err := startPinEntry(context.Background(), path); err == nil {
		t.Fatal("expected an error from a prompter that exits immediately")
	}
}
