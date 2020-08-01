package org.whidra.bridge

import ghidra.*
import ghidra.framework.*
import ghidra.util.*

object Ghidra {
    val host = "0.0.0.0"
    val port = 13100
    val adminUser = "ghidra"
    val defaultPassword = "changeme"

    fun init() {
        if(!Application.isInitialized())
            Application.initializeApplication(
                GhidraJarApplicationLayout(),
                HeadlessGhidraApplicationConfiguration()
            )

        val pass = System.getenv("GHIDRA_ADMIN_PASS") ?: defaultPassword
        try {
            Client(adminUser, defaultPassword).use {
                it.setPassword(pass)
            }

        } catch (e: Exception) {
            // TODO change this to our logback logger
            Msg.warn(null, "Unable to change admin password", e)
        }

    }

    // new user
    // delete user
    // change user perms
}