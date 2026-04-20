package aithos

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestProtocolVersion(t *testing.T) {
	if ProtocolVersion != "0.1.0" {
		t.Errorf("ProtocolVersion = %q, want %q", ProtocolVersion, "0.1.0")
	}
}

func TestPackageVersion(t *testing.T) {
	if PackageVersion != "0.0.1" {
		t.Errorf("PackageVersion = %q, want %q", PackageVersion, "0.0.1")
	}
}

func TestCeremonialDID(t *testing.T) {
	if !strings.HasPrefix(CeremonialDID, "did:aithos:") {
		t.Errorf("CeremonialDID = %q, want prefix %q", CeremonialDID, "did:aithos:")
	}
}

func TestVerifyBundleReturnsNotImplemented(t *testing.T) {
	if err := VerifyBundle("does-not-matter.ethos"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("VerifyBundle error = %v, want ErrNotImplemented", err)
	}
}

func TestResolveDIDReturnsNotImplemented(t *testing.T) {
	if err := ResolveDID(CeremonialDID); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("ResolveDID error = %v, want ErrNotImplemented", err)
	}
}

func TestBirthFSContainsExpectedFiles(t *testing.T) {
	want := []string{
		"birth.json",
		"birth-declaration.md",
		"aithos-birth.ethos",
		"did.json",
	}
	fsys := BirthFS()
	for _, name := range want {
		info, err := fs.Stat(fsys, name)
		if err != nil {
			t.Errorf("BirthFS missing %q: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("BirthFS %q is empty", name)
		}
	}
}
