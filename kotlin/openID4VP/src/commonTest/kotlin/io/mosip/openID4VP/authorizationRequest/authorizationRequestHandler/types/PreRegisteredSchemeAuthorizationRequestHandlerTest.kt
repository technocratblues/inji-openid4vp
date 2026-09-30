package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.common.resolveJwksFromUri
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.testData.JWSUtil.Companion.buildTestJwk
import org.junit.jupiter.api.Test
import kotlin.test.*
private const val MOCK_CLIENT_ID = "mock-client"
private const val TEST_CLIENT_ID = "test-client"
private const val UNTRUSTED_CLIENT_ID = "untrusted-client-id"
class PreRegisteredSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletConfig: WalletConfig
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)
    private val validClientId = MOCK_CLIENT_ID
    private var trustedVerifiers: MutableList<Verifier> = mutableListOf(
        Verifier(
            MOCK_CLIENT_ID, listOf(
                "https://mock-verifier.com/response-uri", "https://verifier.env2.com/responseUri"
            )
        ),
        Verifier(
            clientId = TEST_CLIENT_ID,
            responseUris = listOf("https://example.com/callback"),
            jwksUri = "https://example.com/.well-known/jwks.json",
            allowUnsignedRequest = false
        )
    )
    private val jwksUri = "https://example.com/.well-known/jwks.json"

    @BeforeTest
    fun setup() {

        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to validClientId,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to responseUrl,
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
        )

        walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            trustedVerifiers = trustedVerifiers
        )

        mockkStatic("io.mosip.openID4VP.common.UtilsKt")
    }

    @Test
    fun `validateClientId should pass when client ID is trusted and validation is enabled`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateClientId()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateClientId should skip validation when validatePreRegisteredVerifier is false`() {
        authorizationRequestParameters[CLIENT_ID.value] = UNTRUSTED_CLIENT_ID
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            UNTRUSTED_CLIENT_ID,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig = WalletConfig(
                vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
                clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
                trustedVerifiers = trustedVerifiers,
                validateTrustedVerifier = false
            ),
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateClientId()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateClientId should throw exception when client ID is not trusted`() {
        authorizationRequestParameters[CLIENT_ID.value] = UNTRUSTED_CLIENT_ID
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            UNTRUSTED_CLIENT_ID,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<Exception> {
            handler.validateClientId()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `process should validate and return wallet metadata with requestObjectSigningAlgValuesSupported preserved`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseUri,
            walletNonce
        )

        val processedMetadata = handler.getWalletMetadata(walletConfig)

        assertEquals(
            listOf(SignatureAlgorithm.EdDSA.value),
            processedMetadata["request_object_signing_alg_values_supported"]
        )
    }


    @Test
    fun `validateAndParseRequestFields should pass for trusted client with valid response URI`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateAndParseRequestFields should not throw exception when client metadata of the pre-registered verifier is not known and its available in authorization request`() {
        val trustedVerifiersWithoutClientMetadata: List<Verifier> = listOf(
            Verifier(
                MOCK_CLIENT_ID,
                listOf(
                    "https://mock-verifier.com/response-uri",
                    "https://verifier.env2.com/responseUri"
                ),
            )
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            (authorizationRequestParameters + mapOf(
                CLIENT_METADATA.value to clientMetadataString
            )) as MutableMap<String, Any>,
            WalletConfig(trustedVerifiers = trustedVerifiersWithoutClientMetadata),
            setResponseUri,
            walletNonce
        )

        assertDoesNotThrow {
            handler.validateAndParseRequestFields()
        }
    }

    @Test
    fun `setResponseUrl should reject both response_uri and redirect_uri for direct_post`() {
        authorizationRequestParameters[REDIRECT_URI.value] = "https://example.com/redirect"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.setResponseUrl()
        }
        assertTrue(exception.message?.contains("redirect_uri should not be present") == true)
    }

    @Test
    fun `setResponseUrl should reject both response_uri and redirect_uri for direct_post_jwt`() {
        authorizationRequestParameters[RESPONSE_MODE.value] = "direct_post.jwt"
        authorizationRequestParameters[REDIRECT_URI.value] = "https://example.com/redirect"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.setResponseUrl()
        }
        assertTrue(exception.message?.contains("redirect_uri should not be present") == true)
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when response URI is not trusted`() {
        authorizationRequestParameters[RESPONSE_URI.value] =
            "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseUri,
            walletNonce
        )

        val exception = assertFailsWith<Exception> {
            handler.validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `validateAndParseRequestFields should skip validation when validatePreRegisteredVerifier is false`() {
        authorizationRequestParameters[RESPONSE_URI.value] =
            "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig = WalletConfig(
                vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
                clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
                trustedVerifiers = trustedVerifiers,
                validateTrustedVerifier = false
            ),
            setResponseUri,
            walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `should extract key successfully when kid is present`() {
        val testKid = "test-key"
        authorizationRequestParameters[CLIENT_ID.value] = TEST_CLIENT_ID
        every { resolveJwksFromUri(any(), any()) } returns Jwks(jwkList)

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = TEST_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val publicKey = handler.extractPublicKey(SignatureAlgorithm.EdDSA, testKid)

        assertNotNull(publicKey)
        assertEquals("Ed25519", publicKey.algorithm)
        assertTrue(publicKey.encoded.isNotEmpty())
    }


    @Test
    fun `should throw when kid is present and not found in client metadata`() {
        val testKid = "some-other-key"
        val testJwk = buildTestJwk(kid = testKid)
        authorizationRequestParameters[CLIENT_ID.value] = TEST_CLIENT_ID
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(testJwk))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = TEST_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, "non-existent")
        }

        assertTrue(ex.message.contains("Public key extraction failed for kid"))
    }

    @Test
    fun `should throw error when no jwks_uri available in the trusted verifier`() {
        authorizationRequestParameters[CLIENT_ID.value] = MOCK_CLIENT_ID // this client does not have jwks_uri as per trustedVerifiers

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = MOCK_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, null)
        }

        assertTrue(ex.message.contains("Public key extraction failed - Public key information not available in pre-registered data to verify the signed Authorization Request"))
    }

    @Test
    fun `should pick key by alg if no kid and one matching key present`() {
        val testJwk: Jwk = buildTestJwk(kid = null)
        authorizationRequestParameters[CLIENT_ID.value] = TEST_CLIENT_ID
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(testJwk))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = TEST_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val publicKey = handler.extractPublicKey(SignatureAlgorithm.EdDSA, null)
        assertNotNull(publicKey)
    }

    @Test
    fun `should throw if multiple sig-use keys present and no kid`() {
        val key1 = buildTestJwk(kid = "k1")
        val key2 = buildTestJwk(kid = "k2")
        authorizationRequestParameters[CLIENT_ID.value] = TEST_CLIENT_ID
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(key1, key2))


        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = TEST_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, null)
        }

        assertTrue(ex.message.contains("Multiple ambiguous keys found for EdDSA with signature usage"))
    }

    @Test
    fun `should throw if no matching keys for alg`() {
        val key = buildTestJwk(kty = "RSA", crv = "") // non-EdDSA key
        authorizationRequestParameters[CLIENT_ID.value] = TEST_CLIENT_ID
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(key))


        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = TEST_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, null)
        }

        assertTrue(ex.message.contains("No public key found for algorithm: EdDSA with signature usage"))
    }

    @Test
    fun `should throw if curve is unsupported in matching key`() {
        val unsupportedCurveJWK = buildTestJwk(crv = "XYZ")
        authorizationRequestParameters[CLIENT_ID.value] = TEST_CLIENT_ID
        every { resolveJwksFromUri(jwksUri, any()) } returns Jwks(listOf(unsupportedCurveJWK))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = TEST_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, "test-kid")
        }
        assertTrue(ex.message.contains("Public key extraction failed - Curve - XYZ is not supported. Supported: Ed25519"))
    }

    @Test
    fun `isRequestObjectSupported should return boolean value for trusted client with valid response URI`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseUri,
            walletNonce
        )

        assertFalse(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should return false when validatePreRegisteredVerifier is false`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig = WalletConfig(
                vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
                clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
                trustedVerifiers = trustedVerifiers,
                validateTrustedVerifier = false
            ),
            setResponseUri,
            walletNonce
        )
        assertTrue(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should throw when client id not in trusted verifiers`() {
        authorizationRequestParameters[CLIENT_ID.value] = "unknown-client"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "unknown-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )
        val ex = assertFailsWith<OpenID4VPExceptions.InvalidVerifier> {
            handler.isUnsignedRequestSupported()
        }
        assertTrue(ex.message!!.contains("Verifier is not trusted by the wallet"))
    }

    @Test
    fun `isRequestObjectSupported should return false when verifier does not allow unsigned request`() {
        val verifier = Verifier(
            clientId = TEST_CLIENT_ID,
            jwksUri = jwksUri,
            allowUnsignedRequest = false,
            responseUris = listOf("https://example.com/response")
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = TEST_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters.apply { put(CLIENT_ID.value, TEST_CLIENT_ID) },
            walletConfig = WalletConfig(trustedVerifiers = listOf(verifier)),
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )
        assertFalse(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should return true when verifier allows unsigned request`() {
        val verifier = Verifier(
            clientId = TEST_CLIENT_ID,
            jwksUri = jwksUri,
            allowUnsignedRequest = true,
            responseUris = listOf("https://example.com/response")
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = TEST_CLIENT_ID,
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters.apply { put(CLIENT_ID.value, TEST_CLIENT_ID) },
            walletConfig = WalletConfig(trustedVerifiers = listOf(verifier)),
            setResponseUri = setResponseUri,
            walletNonce = walletNonce
        )
        assertTrue(handler.isUnsignedRequestSupported())
    }
}
