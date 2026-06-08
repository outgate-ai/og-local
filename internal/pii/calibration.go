package pii

import (
	"encoding/json"
	"fmt"
)

func ParseBiases(data []byte, operatingPoint string) (TransitionBiases, error) {
	var doc struct {
		OperatingPoints map[string]struct {
			Biases struct {
				BackgroundStay    float64 `json:"transition_bias_background_stay"`
				BackgroundToStart float64 `json:"transition_bias_background_to_start"`
				EndToBackground   float64 `json:"transition_bias_end_to_background"`
				EndToStart        float64 `json:"transition_bias_end_to_start"`
				InsideToContinue  float64 `json:"transition_bias_inside_to_continue"`
				InsideToEnd       float64 `json:"transition_bias_inside_to_end"`
			} `json:"biases"`
		} `json:"operating_points"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return TransitionBiases{}, err
	}
	op, ok := doc.OperatingPoints[operatingPoint]
	if !ok {
		return TransitionBiases{}, fmt.Errorf("pii: operating point %q not found", operatingPoint)
	}
	return TransitionBiases{
		BackgroundStay:    op.Biases.BackgroundStay,
		BackgroundToStart: op.Biases.BackgroundToStart,
		EndToBackground:   op.Biases.EndToBackground,
		EndToStart:        op.Biases.EndToStart,
		InsideToContinue:  op.Biases.InsideToContinue,
		InsideToEnd:       op.Biases.InsideToEnd,
	}, nil
}
