package detector_test

import (
	"testing"

	"github.com/laojianzi/godlp/detector"
)

func TestIsMasked(t *testing.T) {
	type args struct {
		in string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"not masked", args{"test"}, false},
		{"masked *", args{"test*"}, true},
		{"masked #", args{"test#"}, true},
		{"masked *#", args{"test*#"}, true},
		{"masked #*", args{"test#*"}, true},
		{"masked #**##*", args{"test#**##*"}, true},
		{"masked *##**#", args{"test*##**#"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detector.IsMasked(tt.args.in); got != tt.want {
				t.Errorf("IsMasked() = %v, want %v", got, tt.want)
			}
		})
	}
}
