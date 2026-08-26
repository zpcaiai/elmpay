repositories { mavenCentral() }

configurations.configureEach { exclude(group = "net.jqwik", module = "jqwik") }

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
