package prometheus

func InvertMap(input map[string]uint64) map[uint64]string {
	newMap := make(map[uint64]string)
	for key, val := range input {
		newMap[val] = key
	}
	return newMap
}
