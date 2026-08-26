// This module uses JUnit only. The root build also offers jqwik to modules that
// contain property tests, but this module must not resolve an unused engine.
configurations.matching { it.name.startsWith("test") }.configureEach {
    exclude(group = "net.jqwik", module = "jqwik")
}

dependencies {
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.13.2")
}
