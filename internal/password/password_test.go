package password

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(h, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("correct password did not verify")
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	h, _ := Hash("hunter2")
	ok, err := Verify(h, "hunter3")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong password verified")
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := Hash("same")
	b, _ := Hash("same")
	if a == b {
		t.Fatal("two hashes of the same password are identical — salt is not random")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"notahash",
		"$argon2id$v=19$m=65536,t=3,p=2$onlyfourparts",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",  // wrong variant
		"$argon2id$v=13$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2g", // wrong version
		"$argon2id$v=19$m=bad,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!notb64$aGFzaGhhc2g",
	}
	for _, c := range cases {
		if _, err := Verify(c, "x"); err == nil {
			t.Errorf("Verify(%q) returned nil error, want error", c)
		}
	}
}

func TestEncodedFormatIsStable(t *testing.T) {
	h, _ := Hash("x")
	ok, err := Verify(h, "x")
	if err != nil || !ok {
		t.Fatalf("self-produced hash %q failed to verify: ok=%v err=%v", h, ok, err)
	}
}
