package org.whidra.controllers

import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.RequestBean
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.session.Session
import io.micronaut.session.annotation.SessionValue
import org.whidra.binders.BinaryParam
import org.whidra.binders.client

@Controller("/hello")
open class HelloController {
    @Get("/1")
    fun hello(session: Session): String {
        return "hello from session " + session.get("hello").get()
    }

    @Get("2")
    fun hello2(@SessionValue hello: String): String {
        return "hello from session " + hello
    }

    @Get("/test")
    open fun test(session: Session, @RequestBean binary: BinaryParam): String {
        return "{ bin: ${binary.binary}, repo: ${binary.repository} }"
    }

    @Get("sess")
    @Secured(SecurityRule.IS_ANONYMOUS)
    fun sess(sess: Session): Map<String, Any> {
        sess.client()
        return sess.asMap()
    }
}