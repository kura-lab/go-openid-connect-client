package strings

import (
	"testing"
)

func TestContainsSuccesses(t *testing.T) {

	data := [][]interface{}{
		{
			"aaa",
			[]string{"aaa"},
		},
		{
			"aaa",
			[]string{"aaa", "bbb", "ccc"},
		},
		{
			"bbb",
			[]string{"aaa", "bbb", "ccc"},
		},
		{
			"ccc",
			[]string{"aaa", "bbb", "ccc"},
		},
	}

	for _, value := range data {
		if !Contains(value[0].(string), value[1].([]string)) {
			t.Errorf("not cantain %v in %#v.", value[0].(string), value[1].([]string))
		}
	}
}

func TestContainsFaileres(t *testing.T) {

	data := [][]interface{}{
		{
			"bbb",
			[]string{"aaa"},
		},
		{
			"ddd",
			[]string{"aaa", "bbb", "ccc"},
		},
	}

	for _, value := range data {
		if Contains(value[0].(string), value[1].([]string)) {
			t.Errorf("cantains %v in %#v.", value[0].(string), value[1].([]string))
		}
	}
}
