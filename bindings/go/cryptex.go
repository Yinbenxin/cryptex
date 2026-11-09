// Package cryptex provides Go bindings for the cryptex cryptographic library
package cryptex

/*
#cgo LDFLAGS: -L../../core/target/release -lcryptex
#include <stdlib.h>

char* cryptex_version();
void cryptex_free_string(char* ptr);
*/
import "C"

// Version returns the library version
func Version() string {
	cVersion := C.cryptex_version()
	defer C.cryptex_free_string(cVersion)
	return C.GoString(cVersion)
}

// Additional algorithm functions will be added here as they are implemented
