package utils

import io.ktor.http.HttpStatusCode

open class AppException(msg: String, val code: HttpStatusCode) : Exception(msg)

open class UnauthorizedException(msg: String = "Not logged in.", code:HttpStatusCode = HttpStatusCode.Unauthorized): AppException(msg, code)

class LoggedInException: UnauthorizedException("Already logged in.")

class IncorrectLoginException: UnauthorizedException("Incorrect login details.")

class BadRequest(msg: String): AppException(msg, HttpStatusCode.BadRequest)

class FormFieldMissing(field: String): AppException("Field $field missing in form request.", HttpStatusCode.BadRequest)


