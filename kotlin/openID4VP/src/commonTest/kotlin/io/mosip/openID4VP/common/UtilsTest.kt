package io.mosip.openID4VP.common

import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.jose.jwk.Curve
import io.mockk.*
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import kotlin.test.*
import java.security.PublicKey
private const val UNSUPPORTED_JWS_ALGORITHM_MESSAGE =
    "Unable to resolve a supported JWS algorithm for key"
// Test helper: Creates a PublicKey with predictable class name for testing unsupported algorithms
class TestPublicKey(val keyAlgorithm: String) : PublicKey {
    override fun getAlgorithm(): String = keyAlgorithm
    override fun getEncoded(): ByteArray = byteArrayOf()
    override fun getFormat(): String = "TEST"
}

class UtilsTest {

    @Test
    fun `isValidUrl should return true for valid URLs per RFC 3986`() {
        val validUrls = listOf(
            "https://example.com/path?query=value#fragment",
            // RFC 3986 structure: port + multi-segment path + query + fragment
            "https://example.com:8042/over/there?name=ferret#nose",
            // percent-encoded octets in path and query
            "https://example.com/a%20b?q=hello%20world",
            // empty path segment
            "https://example.com//empty/seg",
            // '/', '?' and '@' allowed within query and fragment
            "https://example.com/p?a=1/2&b=x?y#f/g?h"
        )

        validUrls.forEach { url -> assertTrue(isValidUrl(url), "expected valid: $url") }
    }

    @Test
    fun `isValidUrl should return false for invalid URL`() {


        val testUrls = listOf(
            "www.example.com",
            "http://example.com/space here",
            "http://",
            "https://example",
            "http://example.com/file%/name",
            "http://example.com:99999",
            "http:///example.com",
            "http://example.com/search?q=hello%20world#@fragment",
            "http://:8080",
            "",
            "https://example.com/invalid|character",
            // non-https scheme is rejected even with valid RFC 3986 structure
            "foo://example.com:8042/over/there?name=ferret#nose",
            // malformed percent-encoding (not followed by two hex digits)
            "https://example.com/file%/name",
            // whitespace is not allowed
            "https://example.com/space here",
            // trailing newline must not be accepted
            "https://example.com/path\n"
        )

        testUrls.forEach { url -> assertFalse(isValidUrl(url), "expected invalid: $url") }
    }


    @Test
    fun `convertJsonToMap should correctly parse JSON string`() {
        val json = "{\"key\":\"value\"}"
        val result = convertJsonToMap(json)
        assertEquals("value", result["key"])
    }

    @Test
    fun `isJWT should return true for valid JWT`() {
        val jwt = "header.payload.signature"
        assertTrue(isJWS(jwt))
    }

    @Test
    fun `isJWT should return false for invalid JWT`() {
        val jwt = "invalid.jwt"
        assertFalse(isJWS(jwt))
    }

    @Test
    fun `determineHttpMethod should return correct HTTP method`() {
        assertEquals(HttpMethod.GET, determineHttpMethod("get"))
        assertEquals(HttpMethod.POST, determineHttpMethod("post"))
    }

    @Test
    fun `determineHttpMethod should throw exception for unsupported method`() {
        assertFailsWith<IllegalArgumentException> {
            determineHttpMethod("put")
        }
    }

    @Test
    fun `getStringValue should return correct string value from map`() {
        val map = mapOf("key" to "value")
        assertEquals("value", getStringValue(map, "key"))
        assertNull(getStringValue(map, "nonexistent"))
    }

    internal data class MockDataClass(
        val key: String,
        @JsonProperty("key_with_more_than_one_word")
        val keyWithMoreThanOneWord: String,
        @JsonProperty("nullable_field")
        val nullableField: String? = null,
    )

    @Test

    fun `should serialize data class instance to JSON with all properties specified`() {
        val mockDataClass = MockDataClass(
            key = "id_credential",
            keyWithMoreThanOneWord = "ldp_vp",
            nullableField = "value",
        )

        val descriptorMapJson = encodeToJsonString<MockDataClass>(
            mockDataClass,
            "mockDataClass",
            "UtilsTest"
        )
        "{\"key\":\"id_credential\",\"number\":1,\"key_with_more_than_one_word\":\"ldp_vp\"}"

        assertEquals(
            "{\"key\":\"id_credential\",\"key_with_more_than_one_word\":\"ldp_vp\",\"nullable_field\":\"value\"}",
            descriptorMapJson
        )
    }


    @Test
    fun `should serialize data class without nullable fields to JSON successfully`() {
        val mockDataClass = MockDataClass(
            key = "id_credential",
            keyWithMoreThanOneWord = "ldp_vp",
        )

        val descriptorMapJson = encodeToJsonString<MockDataClass>(
            mockDataClass,
            "mockDataClass",
            "UtilsTest"
        )

        assertEquals(
            "{\"key\":\"id_credential\",\"key_with_more_than_one_word\":\"ldp_vp\"}",
            descriptorMapJson
        )
    }

    @Test
    fun toHex_emptyByteArray_returnsEmptyString() {
        val emptyArray = ByteArray(0)
        assertEquals("", emptyArray.toHex())
    }

    @Test
    fun toHex_simpleByteArray_returnsCorrectHexString() {
        val bytes = byteArrayOf(10, 20, 30, 40, 50)
        assertEquals("0a141e2832", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithSmallValues_includesLeadingZeros() {
        val bytes = byteArrayOf(0, 1, 15)
        assertEquals("00010f", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithNegativeValues_handlesCorrectly() {
        val bytes = byteArrayOf(-1, -128)
        assertEquals("ff80", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithMixedValues_convertsCorrectly() {
        val bytes = byteArrayOf(0, 15, 16, 127, -128, -1)
        assertEquals("000f107f80ff", bytes.toHex())
    }

    @Test
    fun testResolveFromJwksUri() {
        val jwksUri = "https://mock-verifier.com/.well-known/jwks.json"
        val keyId = "f4a0c7f3f1b1e3a1b1e3a1b1e3a1b1e3a1b1e3a1b"
        mockkObject(NetworkManagerClient)
        val mockJwksResponse = """
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "-Fy3lMapzR3wpaYNCFq29GDEn_NoR3pBsc511q1Cxqw",
                        "alg": "EdDSA",
                        "kid": "f4a0c7f3f1b1e3a1b1e3a1b1e3a1b1e3a1b1e3a1b",
                        "use": "sig"
                    }
                ]
            }
        """.trimIndent()
        every {
            NetworkManagerClient.sendHTTPRequest(jwksUri, HttpMethod.GET)
        } returns NetworkResponse(
            200, mockJwksResponse,
            headers = mapOf()
        )

        val publicKey = resolveJwksFromUri(jwksUri, keyId)

        assertNotNull(publicKey)
    }

    @Test
    fun `resolveJWSAlgorithm should return correct algorithm for various key types`() {
        data class TestCase(
            val description: String,
            val keyType: String,
            val expectedAlgo: String,
            val setupMock: () -> java.security.PublicKey
        )

        val testCases = listOf(
            TestCase("RSA key", "RSA", "RS256") {
                mockk<java.security.interfaces.RSAPublicKey>().apply {
                    every { algorithm } returns "RSA"
                }
            },
            TestCase("Ed25519 key", "Ed25519", "EdDSA") {
                mockk<java.security.PublicKey>().apply {
                    every { algorithm } returns "Ed25519"
                }
            },
            TestCase("P-256 EC key", "EC", "ES256") {
                mockk<java.security.interfaces.ECPublicKey>().apply {
                    every { algorithm } returns "EC"
                    every { params } returns Curve.P_256.toECParameterSpec()
                }
            },
            TestCase("P-384 EC key", "EC", "ES384") {
                mockk<java.security.interfaces.ECPublicKey>().apply {
                    every { algorithm } returns "EC"
                    every { params } returns Curve.P_384.toECParameterSpec()
                }
            },
            TestCase("P-521 EC key", "EC", "ES512") {
                mockk<java.security.interfaces.ECPublicKey>().apply {
                    every { algorithm } returns "EC"
                    every { params } returns Curve.P_521.toECParameterSpec()
                }
            },
            TestCase("secp256k1 EC key", "EC", "ES256K") {
                mockk<java.security.interfaces.ECPublicKey>().apply {
                    every { algorithm } returns "EC"
                    every { params } returns Curve.SECP256K1.toECParameterSpec()
                }
            }
        )

        mockkConstructor(DidPublicKeyResolver::class)

        try {
            testCases.forEach { testCase ->
                val mockPublicKey = testCase.setupMock()

                every {
                    anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
                } returns mockPublicKey

                val result = resolveJWSAlgorithm("did:test")
                assertEquals(
                    testCase.expectedAlgo,
                    result,
                    "Failed for ${testCase.description}: expected ${testCase.expectedAlgo} but got $result"
                )
            }
        } finally {
            unmockkConstructor(DidPublicKeyResolver::class)
        }
    }

    @Test
    fun `resolveJWSAlgorithm should throw InvalidData for unsupported key algorithm`() {
        mockkConstructor(DidPublicKeyResolver::class)
        mockkStatic(Curve::class)

        try {
            // Test case 1: Generic unsupported key algorithm (DH) - use real TestPublicKey for stable class name
            every {
                anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
            } returns TestPublicKey("DH")

            val dhException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
                resolveJWSAlgorithm("did:test:dh", "TestClass")
            }
            assertOpenId4VPException(
                dhException,
                UNSUPPORTED_JWS_ALGORITHM_MESSAGE,
                OpenID4VPErrorCodes.INVALID_REQUEST,
                expectedUnderlyingErrorMessage = "Unsupported key type: TestPublicKey"
            )

            // Test case 2: EC key with unsupported/unmapped curve (Curve.forECParameterSpec returns null)
            val mockECKeyUnmappedCurve = mockk<java.security.interfaces.ECPublicKey>().apply {
                every { algorithm } returns "EC"
                every { params } returns mockk<java.security.spec.ECParameterSpec>()
            }
            every {
                anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
            } returns mockECKeyUnmappedCurve
            every {
                Curve.forECParameterSpec(any())
            } returns null

            val ecNullCurveException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
                resolveJWSAlgorithm("did:test:ec-null-curve", "TestClass")
            }
            assertOpenId4VPException(
                ecNullCurveException,
                UNSUPPORTED_JWS_ALGORITHM_MESSAGE,
                OpenID4VPErrorCodes.INVALID_REQUEST,
                expectedUnderlyingErrorMessage = "Unknown or unsupported EC curve parameters"
            )

            // Test case 3: EC key with resolved curve but unsupported in the when statement
            val mockECKeyUnsupportedCurve = mockk<java.security.interfaces.ECPublicKey>().apply {
                every { algorithm } returns "EC"
                every { params } returns mockk<java.security.spec.ECParameterSpec>()
            }
            every {
                anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
            } returns mockECKeyUnsupportedCurve

            val mockUnsupportedCurve = mockk<Curve>().apply {
                every { name } returns "UNSUPPORTED_CURVE"
            }
            every {
                Curve.forECParameterSpec(any())
            } returns mockUnsupportedCurve

            val ecUnsupportedCurveException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
                resolveJWSAlgorithm("did:test:ec-unsupported-curve", "TestClass")
            }
            assertOpenId4VPException(
                ecUnsupportedCurveException,
                UNSUPPORTED_JWS_ALGORITHM_MESSAGE,
                OpenID4VPErrorCodes.INVALID_REQUEST,
                expectedUnderlyingErrorMessage = "Unsupported EC curve: UNSUPPORTED_CURVE"
            )
        } finally {
            unmockkConstructor(DidPublicKeyResolver::class)
            unmockkStatic(Curve::class)
        }
    }
}

