package utils

func ArrayContainsString(arr []string, element *string) bool {
	for _, val := range arr {
		if val == *element {
			return true
		}
	}

	return false
}

func ArrayEmptyOrNil(arr []string) bool {
	if arr == nil || len(arr) == 0 {
		return true
	}

	return false
}
