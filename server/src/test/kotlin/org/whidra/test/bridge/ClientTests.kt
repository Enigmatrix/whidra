package org.whidra.test.bridge

import io.kotest.core.spec.style.*
import io.kotest.matchers.*
import io.kotlintest.matchers.collections.*
import org.whidra.bridge.*

class ClientTests : AnnotationSpec() {
    @BeforeEach
    fun beforeTest() {
        Ghidra.init()
    }

    @Test
    fun `connection succeeds`() {
        Client("ghidra", "changeme").use {
            it.users() contentEquals arrayOf("ghidra")
        }
    }

    @Test
    fun `create repository succeeds`() {
        Client("ghidra", "changeme").use {
            it.createRepository("test1")
        }

        Client("ghidra", "changeme").use {
            it.repositoryNames() shouldContainAll listOf("test1")
            it.deleteRepository("test1")
        }
    }

    @Test
    fun `delete repository succeeds`() {
        Client("ghidra", "changeme").use {
            it.createRepository("test2")
        }
        Client("ghidra", "changeme").use {
            it.deleteRepository("test2")
        }
        Client("ghidra", "changeme").use {
            it.repositoryNames() shouldNotContainAll listOf("test2")
        }
    }
}
