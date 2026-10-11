package mask

import (
	"strings"
	"testing"
)

func found(text string) map[Category][]string {
	out := map[Category][]string{}
	for _, s := range findRules(text) {
		out[s.Category] = append(out[s.Category], text[s.Start:s.End])
	}
	return out
}

func TestRulesFindStructuredValues(t *testing.T) {
	jwt := "eyJ" + strings.Repeat("a", 20) + ".eyJ" + strings.Repeat("b", 20) + "." + strings.Repeat("c", 20)
	key := "sk-" + strings.Repeat("z", 30)
	pem := "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("A", 40) + "\n-----END PRIVATE KEY-----"
	cases := []struct {
		text string
		cat  Category
		want string
	}{
		{"write to " + testEmail + " today", Email, testEmail},
		{"IBAN " + testIBAN + ".", Payment, testIBAN},
		{"card " + testCard + " exp", Payment, testCard},
		{"call " + testPhone + " after six", Phone, testPhone},
		{"Authorization: Bearer " + strings.Repeat("q", 24), Credential, strings.Repeat("q", 24)},
		{"token " + jwt + " end", Credential, jwt},
		{"key " + key, Credential, key},
		{pem, Credential, pem},
		{"SSN 123-45-6789", GovID, "123-45-6789"},
		{"at 52.520008, 13.404954 now", Location, "52.520008, 13.404954"},
	}
	for _, c := range cases {
		got := found(c.text)[c.cat]
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%q: %v found %v, want %q (all: %v)", c.text, c.cat, got, c.want, found(c.text))
		}
	}
}

func TestRulesRejectLookalikes(t *testing.T) {
	for _, text := range []string{
		"order 4111 1111 1111 1112 (bad Luhn)",
		"DE89 3704 0044 0532 0130 01",
		"version 1.2.3.4567 released 2026-10-10",
		"meeting at 10:30, room 4012",
		"price 1,299.00 EUR",
		"build 20261010T204843Z",
	} {
		if f := findRules(text); len(f) != 0 {
			t.Errorf("%q: unexpected %v", text, f)
		}
	}
}

func TestTrackerSpans(t *testing.T) {
	cases := map[string]string{
		"https://a.test/p?utm_source=x":                  "https://a.test/p",
		"https://a.test/p?id=1&utm_source=x":             "https://a.test/p?id=1",
		"https://a.test/p?utm_source=x&id=1":             "https://a.test/p?id=1",
		"https://a.test/p?a=1&gclid=2&b=3#frag":          "https://a.test/p?a=1&b=3#frag",
		"https://a.test/p?utm_medium=m&utm_source=s&k=v": "https://a.test/p?k=v",
	}
	for in, want := range cases {
		out := in
		spans := findTrackers(in)
		for i := len(spans) - 1; i >= 0; i-- {
			out = out[:spans[i].Start] + out[spans[i].End:]
		}
		if out != want {
			t.Errorf("%s -> %s, want %s", in, out, want)
		}
	}
}
