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
    maven { setUrl("https://jitpack.io")}
    jcenter()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("io.ktor:ktor-jackson:$ktorVersion")
    implementation("ch.qos.logback:logback-classic:1.2.3")
    implementation("com.github.papsign:Ktor-OpenAPI-Generator:-SNAPSHOT")
}

tasks {
    withType<KotlinCompile> {
        kotlinOptions.jvmTarget = "11"
    }
}

application {
    mainClassName = "org.whidra.MainKt"
}
