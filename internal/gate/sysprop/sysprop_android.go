//go:build android && cgo

package sysprop

/*
#include <stdlib.h>
#include <sys/system_properties.h>
*/
import "C"

import "unsafe"

// On the phone only the real property counts: an OGL_PROP_ override in the environment would decide
// ro.debuggable and the gate mode (og-os M12). Host builds keep the override for tests.
func get(name string) string {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	buf := (*C.char)(C.malloc(C.PROP_VALUE_MAX))
	defer C.free(unsafe.Pointer(buf))
	n := C.__system_property_get(cname, buf)
	if n <= 0 {
		return ""
	}
	return C.GoStringN(buf, n)
}
