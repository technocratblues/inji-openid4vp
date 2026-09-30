package io.mosip.openID4VP.helper

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dcql.evaluator.DCQLEvaluationErrorCodes
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.CredentialSetQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.dcql.evaluator.DCQLTestFixtures
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
private const val EMPLOYEE_CARD = "employee-card"
private const val EMPLOYEE_URL = "https://example.com/employee"
private const val SDJWT_1 = "sdjwt-1"
private const val MOBILE_ID = "mobile-id"
private const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
class DCQLHelperTest {

    private val helper = DCQLHelper()

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
    fun `should get matching credentials for single query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                )
            )
        )

        val result = helper.getMatchingCredentials(listOf(DCQLTestFixtures.sdJwtCredential(SDJWT_1)), query)

        assertTrue(result.success)
        assertEquals(
            SDJWT_1,
            result.queryMatches[EMPLOYEE_CARD]?.matchingCredentials?.first()?.credentialId
        )
    }

    @Test
    fun `should return failure when credentials do not satisfy query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                )
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.sdJwtCredential(SDJWT_1, vct = "https://example.com/other")),
            query
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches[EMPLOYEE_CARD]?.failureReason
        )
    }

    @Test
    fun `should satisfy required credential set when all options are fulfilled`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = MOBILE_ID,
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to MDL_DOCTYPE)
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf(EMPLOYEE_CARD, MOBILE_ID)))
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(
                DCQLTestFixtures.sdJwtCredential(SDJWT_1),
                DCQLTestFixtures.mdocCredential("mdoc-1")
            ),
            query
        )

        assertTrue(result.success)
        assertEquals(1, result.credentialSets.size)
        assertEquals(2, result.queryMatches.size)
    }

    @Test
    fun `should fail when required credential set option is not fulfilled`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = MOBILE_ID,
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to MDL_DOCTYPE)
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf(EMPLOYEE_CARD, MOBILE_ID)))
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.sdJwtCredential(SDJWT_1)),
            query
        )

        assertFalse(result.success)
    }

    @Test
    fun `should synthesize one required credential set per query when credentialSets is null`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = MOBILE_ID,
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to MDL_DOCTYPE)
                )
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(
                DCQLTestFixtures.sdJwtCredential(SDJWT_1),
                DCQLTestFixtures.mdocCredential("mdoc-1")
            ),
            query
        )

        assertEquals(2, result.credentialSets.size)
        assertEquals(listOf(listOf(EMPLOYEE_CARD)), result.credentialSets[0].options)
        assertTrue(result.credentialSets[0].required)
        assertEquals(listOf(listOf(MOBILE_ID)), result.credentialSets[1].options)
        assertTrue(result.credentialSets[1].required)
    }

    @Test
    fun `should succeed when optional credential set is not fulfilled`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf(EMPLOYEE_URL))
                ),
                CredentialQuery(
                    id = MOBILE_ID,
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to MDL_DOCTYPE)
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(
                    options = listOf(listOf(EMPLOYEE_CARD, MOBILE_ID)),
                    required = false
                )
            )
        )

        val result = helper.getMatchingCredentials(
            listOf(DCQLTestFixtures.sdJwtCredential(SDJWT_1)),
            query
        )

        assertTrue(result.success)
    }
}
