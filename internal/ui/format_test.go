package ui

import "testing"

func TestFormatInt(t *testing.T) {
	cases := map[int]string{
		0: "0", 14: "14", 999: "999", 1000: "1,000",
		41209: "41,209", 1234567: "1,234,567", -4200: "-4,200",
	}
	for in, want := range cases {
		if got := formatInt(in); got != want {
			t.Errorf("formatInt(%d) = %q, want %q", in, got, want)
		}
	}
}
