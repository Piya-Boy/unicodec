package dev.ubc

/** One UBC metadata TLV entry (SPEC.md section 2.2.1). */
class MetadataEntry(val tag: Int, value: ByteArray) {
    val value: ByteArray = value.copyOf()

    override fun equals(other: Any?): Boolean =
        other is MetadataEntry && tag == other.tag && value.contentEquals(other.value)

    override fun hashCode(): Int = 31 * tag + value.contentHashCode()
}
