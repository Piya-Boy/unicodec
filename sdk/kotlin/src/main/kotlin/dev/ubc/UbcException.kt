package dev.ubc

/** A UBC failure carrying a portable, stable error identifier. */
class UbcException(val code: ErrorCode) : RuntimeException(code.stableId)
