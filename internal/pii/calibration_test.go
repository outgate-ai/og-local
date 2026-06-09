package pii

import "testing"

const calibrationJSON = `{
  "operating_points": {
    "default": {
      "biases": {
        "transition_bias_background_stay": 1,
        "transition_bias_background_to_start": 2,
        "transition_bias_end_to_background": 3,
        "transition_bias_end_to_start": 4,
        "transition_bias_inside_to_continue": 5,
        "transition_bias_inside_to_end": 6
      }
    }
  }
}`

func TestParseBiases(t *testing.T) {
	b, err := ParseBiases([]byte(calibrationJSON), "default")
	if err != nil {
		t.Fatalf("ParseBiases: %v", err)
	}
	if b.BackgroundStay != 1 || b.BackgroundToStart != 2 || b.EndToBackground != 3 ||
		b.EndToStart != 4 || b.InsideToContinue != 5 || b.InsideToEnd != 6 {
		t.Errorf("biases = %+v, want 1..6", b)
	}
}

func TestParseBiasesMissingOperatingPoint(t *testing.T) {
	if _, err := ParseBiases([]byte(calibrationJSON), "nope"); err == nil {
		t.Error("expected error for missing operating point")
	}
}

func TestParseBiasesInvalidJSON(t *testing.T) {
	if _, err := ParseBiases([]byte("{not json"), "default"); err == nil {
		t.Error("expected error for invalid JSON")
	}
}
