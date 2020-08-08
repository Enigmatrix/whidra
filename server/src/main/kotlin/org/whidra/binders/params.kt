package org.whidra.binders

import io.micronaut.core.annotation.Introspected
import io.micronaut.http.annotation.QueryValue
import io.micronaut.session.Session
import io.micronaut.session.annotation.SessionValue

@Introspected
class BinaryParam {
    @QueryValue
    lateinit var binary: String

    @QueryValue
    lateinit var repository: String
}