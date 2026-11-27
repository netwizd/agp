package inventory

// ReadProtectedFile reads a bounded installation-owned file through descriptors
// whose entire path has been checked. Private files also require mode 0600 or
// stricter. It never follows symbolic links.
func ReadProtectedFile(name string, private bool) ([]byte, error) {
	return readClientFile(name, private)
}
