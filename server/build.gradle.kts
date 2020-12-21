import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

group = "org.whidra"
version = "1.0-SNAPSHOT"

plugins {
    kotlin("jvm") version "1.4.0"
    application
}

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("ch.qos.logback:logback-classic:1.2.3")
}

tasks {
    withType<KotlinCompile> {
        kotlinOptions.jvmTarget = "11"
    }
}

application {
    mainClassName = "org.whidra.MainKt"
}
