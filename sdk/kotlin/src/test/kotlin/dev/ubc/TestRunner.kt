package dev.ubc

/**
 * Minimal test harness: no Gradle/JUnit in this build (plain `kotlinc` CLI only, confirmed
 * explicitly rather than fighting a second build-tool bootstrap this session). Each test
 * file registers its cases into [TestRunner.tests]; [main] runs them all and exits non-zero
 * on any failure, giving a CI-usable signal without a test framework dependency.
 */
object TestRunner {
    private val tests = mutableListOf<Pair<String, () -> Unit>>()

    fun test(name: String, body: () -> Unit) {
        tests.add(name to body)
    }

    fun runAll(): Boolean {
        var passed = 0
        var failed = 0
        for ((name, body) in tests) {
            try {
                body()
                passed++
                println("PASS: $name")
            } catch (e: Throwable) {
                failed++
                println("FAIL: $name -- ${e.message}")
                e.printStackTrace()
            }
        }
        println("---")
        println("$passed passed, $failed failed, ${passed + failed} total")
        return failed == 0
    }
}

fun assertEquals(expected: Any?, actual: Any?, message: String = "") {
    val equal = when {
        expected is ByteArray && actual is ByteArray -> expected.contentEquals(actual)
        else -> expected == actual
    }
    if (!equal) {
        throw AssertionError("$message: expected <$expected> but was <$actual>")
    }
}

fun assertTrue(condition: Boolean, message: String = "") {
    if (!condition) {
        throw AssertionError("$message: expected true")
    }
}

fun assertFalse(condition: Boolean, message: String = "") {
    if (condition) {
        throw AssertionError("$message: expected false")
    }
}

fun assertThrowsUbc(code: ErrorCode, message: String = "", body: () -> Unit) {
    try {
        body()
        throw AssertionError("$message: expected UbcException with code $code but nothing was thrown")
    } catch (e: UbcException) {
        if (e.code != code) {
            throw AssertionError("$message: expected code $code but was ${e.code}")
        }
    }
}
