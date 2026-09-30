package io.mosip.openID4VP.dcql.evaluator

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.dcql.query.ClaimsQuery
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dcql.evaluator.DCQLTestFixtures.sdJwtCredential
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
private const val EMPLOYEE_CARD = "employee-card"
private const val EMPLOYEE_URL = "https://example.com/employee"
private const val SDJWT_1 = "sdjwt-1"
private const val MDOC_1 = "mdoc-1"
class DcqlEvaluatorTest {

    private val evaluator = DcqlEvaluator()

    @BeforeTest
    fun setUp() {
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should match sd-jwt credential by format and vct`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.sdJwtCredential(id = SDJWT_1)))

        assertTrue(result.success)
        assertEquals(
            listOf(SDJWT_1),
            result.queryMatches[EMPLOYEE_CARD]?.matchingCredentials?.map { it.credentialId }
        )
    }

    @Test
    fun `should match mdoc credential by doctype`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.mdocCredential(MDOC_1)))

        assertTrue(result.success)
        assertEquals(MDOC_1, result.queryMatches["mobile-id"]?.matchingCredentials?.first()?.credentialId)
    }

    @Test
    fun `should match claims by nested path including null`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "w3c-card",
                    format = FormatType.LDP_VC.value,
                    claims = listOf(
                        ClaimsQuery(id = "given-name", path = listOf("credentialSubject", "given_name"))
                    )
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.w3cCredential(id = "ldp-1")))

        assertTrue(result.success)
        assertEquals(1, result.queryMatches["w3c-card"]?.matchingCredentials?.first()?.matchingClaims?.size)
    }
    @Test
    fun `should match sd-jwt claims by array index path`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-sd-jwt",
                    format = FormatType.VC_SD_JWT.value,
                    claims = listOf(
                        ClaimsQuery(path = listOf("degrees", 0, "type"))
                    )
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(sdJwtCredential(id = SDJWT_1)))

        assertTrue(result.success)
        assertEquals(1, result.queryMatches["employee-sd-jwt"]?.matchingCredentials?.first()?.matchingClaims?.size)
    }

    @Test
    fun `should return failure with meta mismatch reason when vct does not match`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                DCQLTestFixtures.sdJwtCredential(
                    id = SDJWT_1,
                    vct = "https://example.com/other"
                )
            )
        )

        assertFalse(result.success)
        assertNull(result.queryMatches[EMPLOYEE_CARD]?.matchingCredentials)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches[EMPLOYEE_CARD]?.failureReason
        )
    }

    @Test
    fun `should return failure with no matching formats when format does not match`() {
        val query = DCQLQuery(
            credentials = listOf(CredentialQuery(id = EMPLOYEE_CARD, format = FormatType.VC_SD_JWT.value))
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.mdocCredential(MDOC_1)))

        assertFalse(result.success)
        assertNull(result.queryMatches[EMPLOYEE_CARD]?.matchingCredentials)
        assertEquals(
            DCQLEvaluationErrorCodes.NO_MATCHING_FORMATS_FOUND.value,
            result.queryMatches[EMPLOYEE_CARD]?.failureReason
        )
    }

    @Test
    fun `should return multiple matching credentials when multiple is true`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    multiple = true,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                DCQLTestFixtures.sdJwtCredential(id = SDJWT_1),
                DCQLTestFixtures.sdJwtCredential(id = "sdjwt-2")
            )
        )

        assertTrue(result.success)
        assertEquals(2, result.queryMatches[EMPLOYEE_CARD]?.matchingCredentials?.size)
        assertTrue(result.queryMatches[EMPLOYEE_CARD]?.allowMultipleCredentials == true)
    }

    @Test
    fun `should match sd-jwt credential with empty meta`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "any-sdjwt",
                    format = FormatType.VC_SD_JWT.value
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.sdJwtCredential(id = SDJWT_1)))

        assertTrue(result.success)
        assertEquals(SDJWT_1, result.queryMatches["any-sdjwt"]?.matchingCredentials?.first()?.credentialId)
    }

    @Test
    fun `should fail when holder binding is required but credential has no cnf`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "bound-card",
                    format = FormatType.VC_SD_JWT.value,
                    requireCryptographicHolderBinding = true,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(DCQLTestFixtures.sdJwtCredential(id = "sdjwt-no-cnf", holderBinding = false))
        )

        assertFalse(result.success)
        assertNull(result.queryMatches["bound-card"]?.matchingCredentials)
    }

    @Test
    fun `should evaluate multiple credential queries independently`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "sdjwt-query",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = "mdoc-query",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                DCQLTestFixtures.sdJwtCredential(id = SDJWT_1),
                DCQLTestFixtures.mdocCredential(MDOC_1)
            )
        )

        assertTrue(result.success)
        assertEquals(2, result.queryMatches.size)
        assertEquals(SDJWT_1, result.queryMatches["sdjwt-query"]?.matchingCredentials?.first()?.credentialId)
        assertEquals(MDOC_1, result.queryMatches["mdoc-query"]?.matchingCredentials?.first()?.credentialId)
    }
}

