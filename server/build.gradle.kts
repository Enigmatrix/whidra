import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

val ktor_version = "1.2.5"

plugins {
    kotlin("jvm") version "1.3.41"
    application
}

group = "whidra"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven("https://jitpack.io")
}

dependencies {
    implementation(kotlin("stdlib"))

    implementation(files("./ghidra.jar"))

    implementation("io.ktor:ktor-server-core:$ktor_version")
    implementation("io.ktor:ktor-server-netty:$ktor_version")
    implementation("io.ktor:ktor-jackson:$ktor_version")
    implementation("io.ktor:ktor-websockets:$ktor_version")
    implementation("io.ktor:ktor-server-sessions:$ktor_version")

    implementation("ch.qos.logback:logback-classic:1.2.3")
}

application {
    mainClassName = "MainKt"
}
