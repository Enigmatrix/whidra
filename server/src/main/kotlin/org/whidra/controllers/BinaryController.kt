package org.whidra.controllers

import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.*
import io.micronaut.http.multipart.StreamingFileUpload
import io.micronaut.http.server.types.files.StreamedFile
import io.reactivex.Single
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.*
import org.whidra.binders.BinaryParam
import org.whidra.model.*
import org.whidra.model.Function

@Controller("/api/binary")
@Tag(name = "Binary")
class BinaryController {
    @Get("/functions")
    suspend fun functions(binary: BinaryParam): List<Function> {
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