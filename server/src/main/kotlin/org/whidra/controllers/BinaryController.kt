package org.whidra.controllers

import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.*
import io.micronaut.http.multipart.StreamingFileUpload
import io.micronaut.http.server.types.files.StreamedFile
import io.micronaut.session.Session
import io.micronaut.session.annotation.SessionValue
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.security.SecurityScheme
import io.swagger.v3.oas.annotations.tags.*
import org.whidra.binders.BinaryParam
import org.whidra.model.*
import org.whidra.model.Function
import javax.validation.Valid

@Controller("/api/binary")
@Tag(name = "Binary")
open class BinaryController { // TODO allOpen is bugged?
    @Get("/functions")
    // @Operation(security = [SecurityRequirement(name = "sessionCookie")])
    open fun functions(session: Session, @RequestBean binary: BinaryParam): List<Function> { // TODO suspend here writes wrong parameter values
        println("{ bin: ${binary.binary}, repo: ${binary.repository} }")
        TODO("unimplemented")
    }

    @Get("/code", produces = [MediaType.TEXT_XML])
    suspend fun code(binary: BinaryParam, function: String): StreamedFile {
        TODO("unimplemented")
    }

    @Post("/upload", consumes = [MediaType.MULTIPART_FORM_DATA])
    suspend fun upload(file: StreamingFileUpload, repository: String): Binary {
        TODO("unimplemented")
    }

}