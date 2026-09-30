package io.mosip.openID4VP.dcql.query

import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertIs
import kotlin.test.assertTrue
private const val EMPLOYEE_CARD = "employee-card"
private const val VC_SD_JWT = "vc+sd-jwt"
private const val GIVEN_NAME = "given-name"
class DCQLQueryTest {

    @Test
    fun `should serialize and deserialize dcql query correctly`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = VC_SD_JWT,
                    multiple = true,
                    meta = mapOf(
                        "vct_values" to listOf("EmployeeCardCredential"),
                        "priority" to 1,
                        "holder_binding_required" to true,
                        "nested" to mapOf("level" to "gold")
                    ),
                    requireCryptographicHolderBinding = false,
                    claims = listOf(
                        ClaimsQuery(
                            id = GIVEN_NAME,
                            path = listOf("credentialSubject", "given_name", null, 0),
                            values = listOf(
                                ClaimValue.StringValue("Alice"),
                                ClaimValue.LongValue(1),
                                ClaimValue.BoolValue(true)
                            )
                        )
                    ),
                    claimSets = listOf(listOf(GIVEN_NAME))
                ),
                CredentialQuery(
                    id = "licence",
                    format = "mso_mdoc",
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                )
            ),
            credentialSets = listOf(
                CredentialSetQuery(
                    options = listOf(listOf(EMPLOYEE_CARD), listOf("licence")),
                    required = false
                )
            )
        )

        val json = Json.encodeToString(DCQLQuerySerializer, query)
        val decoded = Json.decodeFromString(DCQLQuerySerializer, json)

        assertEquals(query, decoded)
        assertTrue(json.contains("\"credential_sets\""))
        assertTrue(json.contains("\"claim_sets\""))
        assertTrue(json.contains("\"require_cryptographic_holder_binding\":false"))
    }

    @Test
    fun `should deserialize using serializer with defaults and typed values`() {
        val json = """
            {
              "credentials": [
                {
                  "id": "cred1",
                  "format": "$VC_SD_JWT",
                  "meta": {
                    "priority": 2,
                    "holder_binding_required": true,
                    "labels": ["alpha", "beta"]
                  },
                  "claims": [
                    {
                      "id": "$GIVEN_NAME",
                      "path": ["credentialSubject", "given_name"],
                      "values": ["Alice", 42, true]
                    }
                  ],
                  "claim_sets": [["$GIVEN_NAME"]]
                }
              ]
            }
        """.trimIndent()

        val query = Json.decodeFromString(DCQLQuerySerializer, json)
        val credential = query.credentials.first()
        val claims = credential.claims!!.first()

        assertFalse(credential.multiple)
        assertTrue(credential.requireCryptographicHolderBinding)
        assertEquals(2, credential.meta["priority"])
        assertEquals(true, credential.meta["holder_binding_required"])
        assertEquals(listOf("alpha", "beta"), credential.meta["labels"])
        assertEquals(listOf(GIVEN_NAME), credential.claimSets!!.first())
        assertIs<ClaimValue.StringValue>(claims.values!![0])
        assertIs<ClaimValue.LongValue>(claims.values[1])
        assertIs<ClaimValue.BoolValue>(claims.values[2])
    }

    @Test
    fun `should serialize with expected field names and omit default optional fields`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "cred1",
                    format = VC_SD_JWT,
                    claims = listOf(
                        ClaimsQuery(
                            id = "name",
                            path = listOf("credentialSubject", "name")
                        )
                    ),
                    claimSets = listOf(listOf("name"))
                )
            )
        )

        val json = Json.encodeToString(DCQLQuerySerializer, query)

        assertTrue(json.contains("\"claim_sets\""))
        assertTrue(json.contains("\"meta\":{}"))
        assertFalse(json.contains("\"multiple\""))
        assertFalse(json.contains("\"require_cryptographic_holder_binding\""))
    }

    @Test
    fun `should throw json encoding failure when meta contains non string nested key`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "cred1",
                    format = VC_SD_JWT,
                    meta = mapOf("nested" to mapOf(1 to "value"))
                )
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.JsonEncodingFailed> {
            Json.encodeToString(DCQLQuerySerializer, query)
        }

        assertTrue(exception.message!!.contains("Only string keys are supported"))
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
    }

    @Test
    fun `should create valid query with single credential query`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = EMPLOYEE_CARD,
                    format = VC_SD_JWT,
                    claims = listOf(ClaimsQuery(path = listOf("given_name")))
                )
            )
        )

        assertEquals(1, query.credentials.size)
        assertEquals(EMPLOYEE_CARD, query.credentials.first().id)
        assertNull(query.credentialSets)
    }

    @Test
    fun `should create valid query with multiple credential queries`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "sdjwt", format = VC_SD_JWT),
                CredentialQuery(id = "mdoc", format = "mso_mdoc", multiple = true)
            )
        )

        assertEquals(2, query.credentials.size)
        assertTrue(query.credentials.last().multiple)
    }

    @Test
    fun `should create valid query with credential sets`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "sdjwt", format = VC_SD_JWT),
                CredentialQuery(id = "mdoc", format = "mso_mdoc")
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf("sdjwt"), listOf("mdoc")))
            )
        )

        assertNotNull(query.credentialSets)
        assertEquals(1, query.credentialSets.size)
        assertTrue(query.credentialSets.first().required)
    }

    @Test
    fun `should throw when credentials list is empty`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            DCQLQuery(credentials = emptyList())
        }

        assertOpenId4VPException(
            exception,
            "Invalid Input: dcql_query->credentials value cannot be empty or null",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw when credential query ids are duplicated`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(
                    CredentialQuery(id = "duplicate", format = VC_SD_JWT),
                    CredentialQuery(id = "duplicate", format = "mso_mdoc")
                )
            )
        }

        assertOpenId4VPException(
            exception,
            "Credential Query ids must be unique within dcql_query",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw when credential set references unknown query id`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            DCQLQuery(
                credentials = listOf(CredentialQuery(id = "known", format = VC_SD_JWT)),
                credentialSets = listOf(CredentialSetQuery(options = listOf(listOf("unknown"))))
            )
        }

        assertOpenId4VPException(
            exception,
            "credential_sets references unknown credential id 'unknown'",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should validate claims query with valid path components`() {
        val claimsQuery = ClaimsQuery(
            id = "degree",
            path = listOf("credentialSubject", "degrees", null, 0),
            values = listOf(ClaimValue.StringValue("Bachelor"))
        )

        claimsQuery.validate(isClaimSetsAvailable = true)

        assertEquals(4, claimsQuery.path.size)
        assertFalse(claimsQuery.values.isNullOrEmpty())
    }

    @Test
    fun `should throw when claims query path is empty`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            ClaimsQuery(path = emptyList()).validate(isClaimSetsAvailable = false)
        }

        assertOpenId4VPException(
            exception,
            "Invalid Input: claims_query->path value cannot be empty or null",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `ClaimValue from should return StringValue for string input`() {
        val result = ClaimValue.from("hello")

        assertEquals(ClaimValue.StringValue("hello"), result)
    }

    @Test
    fun `ClaimValue from should return LongValue for int input`() {
        val result = ClaimValue.from(42)

        assertEquals(ClaimValue.LongValue(42L), result)
    }

    @Test
    fun `ClaimValue from should return LongValue for long input`() {
        val result = ClaimValue.from(100L)

        assertEquals(ClaimValue.LongValue(100L), result)
    }

    @Test
    fun `ClaimValue from should return BoolValue for true boolean input`() {
        val result = ClaimValue.from(true)

        assertEquals(ClaimValue.BoolValue(true), result)
    }

    @Test
    fun `ClaimValue from should return BoolValue for false boolean input`() {
        val result = ClaimValue.from(false)

        assertEquals(ClaimValue.BoolValue(false), result)
    }

    @Test
    fun `ClaimValue from should throw for null input`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            ClaimValue.from(null)
        }

        assertOpenId4VPException(
            exception,
            "Claim value must be a string, integer, or boolean",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `ClaimValue from should throw for unsupported type input`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            ClaimValue.from(listOf("unsupported"))
        }

        assertOpenId4VPException(
            exception,
            "Claim value must be a string, integer, or boolean",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }
}



