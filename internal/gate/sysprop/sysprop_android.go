//go:build android && cgo

package sysprop

/*
#include <stdlib.h>
#include <sys/system_properties.h>
*/
import "C"

import "unsafe"

func get(name string) string {
	if v := fromEnv(name); v != "" {
		return v
	}
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
