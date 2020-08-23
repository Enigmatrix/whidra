import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

group = "org.whidra"
version = "1.0-SNAPSHOT"

val ktorVersion = "1.4.0"

plugins {
    kotlin("jvm") version "1.4.0"
    application
}

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    implementation(kotlin("stdlib-jdk8")) // stdlib-jdk8
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("ch.qos.logback:logback-classic:1.2.3")
}

tasks {
    withType<KotlinCompile> {
        kotlinOptions.jvmTarget = "1.8" // 1.8
    }
}

application {
    mainClassName = "org.whidra.MainKt"
}
