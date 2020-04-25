package strings

// Contains is check if a value exists in string array.
func Contains(src string, arr []string) bool {
	for _, value := range arr {
		if src == value {
			return true
		}
	}
	return false
}
