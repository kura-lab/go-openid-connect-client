package hash

import (
	"testing"
)

func TestGenerateHalfOfSHA256(t *testing.T) {

	data := [][]string{
		{
			"this is raw data",
			"FwzVMe7jspU5O5gtjPD_Gw",
		},
	}

	for _, value := range data {
		if actual := GenerateHalfOfSHA256(value[0]); actual != value[1] {
			t.Errorf("not match generated hash. expected: %v, actual: %v.", value[1], actual)
		}
	}
}

func TestGenerateSHA256(t *testing.T) {

	data := [][]string{
		{
			"this is raw data",
			"FwzVMe7jspU5O5gtjPD_G7-XhUfzzR8WPHW7jluYiQo",
		},
	}

	for _, value := range data {
		if actual := GenerateSHA256(value[0]); actual != value[1] {
			t.Errorf("not match generated hash. expected: %v, actual: %v.", value[1], actual)
		}
	}
}
