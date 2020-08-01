package org.whidra.binders

import io.micronaut.core.annotation.Introspected
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.QueryValue

@Introspected
class BinaryParam(val binary: String, val repository: String) {
}