package com.sphereon.vdx.ades

class PKIException(message: String) : Exception(message)
class SigningException(message: String) : Exception(message)
class TimestampException(message: String? = null, override val cause: Throwable? = null) : Exception(message, cause)
class SignClientException(message: String) : Exception(message)
