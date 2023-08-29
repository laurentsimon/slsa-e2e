package pointer

func To[K any](object K) *K {
	return &object
}
