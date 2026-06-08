package pii

import "testing"

func TestClassValues(t *testing.T) {
	want := map[Class]bool{
		"account_number":  true,
		"private_address": true,
		"private_date":    true,
		"private_email":   true,
		"private_person":  true,
		"private_phone":   true,
		"private_url":     true,
		"secret":          true,
	}
	got := []Class{
		ClassAccountNumber, ClassAddress, ClassDate, ClassEmail,
		ClassPerson, ClassPhone, ClassURL, ClassSecret,
	}
	if len(got) != len(want) {
		t.Fatalf("have %d class constants, want %d", len(got), len(want))
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected class value %q", c)
		}
	}
}
