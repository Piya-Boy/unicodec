package dev.ubc

/** Single entry point registering every test file's cases, then running them all. */
fun main() {
    HeaderMetadataVectorsTest.register()
    PlainVectorsTest.register()
    EncryptedVectorsTest.register()
    StreamingTest.register()
    ConformanceTest.register()
    val success = TestRunner.runAll()
    if (!success) {
        kotlin.system.exitProcess(1)
    }
}
