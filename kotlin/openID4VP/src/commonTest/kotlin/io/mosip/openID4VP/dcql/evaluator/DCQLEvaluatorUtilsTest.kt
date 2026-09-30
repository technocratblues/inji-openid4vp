package io.mosip.openID4VP.dcql.evaluator

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.wallet.Credential
import java.io.ByteArrayOutputStream
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
private const val CRED_1 = "cred-1"
class DCQLEvaluatorUtilsTest {

    private val encoder = Base64.getUrlEncoder().withoutPadding()

    @Test
    fun `expandCredentialTag throws when ldp credential data is not map`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            expandCredentialTag(Credential(FormatType.LDP_VC, "invalid", CRED_1))
        }
        assertEquals("Credential data is not in the expected format", exception.message)
    }

    @Test
    fun `expandCredentialTag throws when mdoc credential is not string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            expandCredentialTag(Credential(FormatType.MSO_MDOC, mapOf("docType" to "x"), CRED_1))
        }
        assertEquals("MDOC credential is not a String", exception.message)
    }

    @Test
    fun `expandCredentialTag throws when mdoc docType is missing`() {
        try {
            mockkStatic("io.mosip.openID4VP.common.DecoderKt")
            mockkStatic("io.mosip.openID4VP.common.CborUtilsKt")
            every { decodeFromBase64Url(any()) } returns byteArrayOf(1)
            every { decodeCbor(any()) } returns CborMap().apply {
                put(UnicodeString("issuerSigned"), UnicodeString("placeholder"))
            }

            val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
                expandCredentialTag(Credential(FormatType.MSO_MDOC, "mock-mdoc", CRED_1))
            }
            assertEquals("docType missing or invalid in credential", exception.message)
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun `expandCredentialTag throws when sd-jwt credential is not string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            expandCredentialTag(Credential(FormatType.VC_SD_JWT, 123, CRED_1))
        }
        assertEquals("SD-JWT credential is not a String", exception.message)
    }

    @Test
    fun `convertToProcessedCredentials throws when ldp credential data is not map`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            convertToProcessedCredentials(
                listOf(CRED_1),
                mapOf(CRED_1 to Credential(FormatType.LDP_VC, "invalid", CRED_1))
            )
        }
        assertEquals("Credential data is not in the expected format", exception.message)
    }

    @Test
    fun `convertToProcessedCredentials throws when mdoc credential is not string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            convertToProcessedCredentials(
                listOf(CRED_1),
                mapOf(CRED_1 to Credential(FormatType.MSO_MDOC, mapOf("docType" to "x"), CRED_1))
            )
        }
        assertEquals("MDOC credential is not a String", exception.message)
    }

    @Test
    fun `convertToProcessedCredentials throws when sd-jwt credential is not string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            convertToProcessedCredentials(
                listOf(CRED_1),
                mapOf(CRED_1 to Credential(FormatType.VC_SD_JWT, false, CRED_1))
            )
        }
        assertEquals("SD-JWT credential is not a String", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer throws when selected element is not object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf("name"), 1)
        }
        assertEquals("currently selected element(s) is not an object", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer throws when selected element is not array for index`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf(0), mapOf("items" to listOf(1, 2)))
        }
        assertEquals("currently selected element(s) is not an array", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer throws when selected element is not array for null pointer`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf(null), mapOf("items" to listOf(1, 2)))
        }
        assertEquals("currently selected element(s) is not an array", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer throws for unexpected path pointer component`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf(true), mapOf("name" to "alice"))
        }
        assertEquals("Unexpected path pointer component", exception.message)
    }

    @Test
    fun `extractSdJwtPayloadMap throws when sd-jwt credential is empty`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            extractSdJwtPayloadMap("")
        }
        assertEquals("SD-JWT credential is malformed or empty", exception.message)
    }

    @Test
    fun `extractSdJwtPayloadMap throws when sd-jwt jwt part is malformed`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            extractSdJwtPayloadMap("invalidjwt")
        }
        assertEquals("SD-JWT credential JWT part is malformed", exception.message)
    }

    private fun encodeMdoc(entries: Map<String, String>): String {
        val cborMap = CborMap().apply {
            entries.forEach { (key, value) ->
                put(UnicodeString(key), UnicodeString(value))
            }
        }
        val output = ByteArrayOutputStream()
        CborEncoder(output).encode(cborMap)
        return encoder.encodeToString(output.toByteArray())
    }
}



