package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.common.resolveJWSAlgorithm
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.walletConfig
import kotlin.test.*
private const val MOCK_VERIFIER_RESPONSE = "https://mock-verifier.com/response"
private const val LDP_QUERY_1 = "ldp-query-1"
private const val LDP_QUERY_2 = "ldp-query-2"
private const val INPUT_DESCRIPTOR_ID1 = "input-descriptor-id1"
private const val INPUT_DESCRIPTOR_ID2 = "input-descriptor-id2"
class UnsignedLdpVPTokenBuilderTest {

    private val verifiableCredentials = listOf(ldpCredential1, ldpCredential2)
    private val id = "649d581c-f291-4969-9cd5-2c27385a348f"
    private val holder = "did:example:123456789"
    private val challenge = "test-challenge"
    private val domain = "test-domain.com"
    private val mockCanonicalizedData = "canonicalized-data"

    private val testAuthorizationRequest = AuthorizationPresentationExchangeRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(presentationDefinitionMap, PresentationDefinitionSerializer),
        responseUri = MOCK_VERIFIER_RESPONSE,
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
    )

    private val testDcqlAuthorizationRequest = AuthorizationDcqlRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = MOCK_VERIFIER_RESPONSE,
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
        dcqlQuery = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = LDP_QUERY_1, format = "ldp_vc", requireCryptographicHolderBinding = true),
                CredentialQuery(id = LDP_QUERY_2, format = "ldp_vc", requireCryptographicHolderBinding = true),
            )
        )
    )

    private val testDcqlAuthorizationRequestNoBinding = AuthorizationDcqlRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = MOCK_VERIFIER_RESPONSE,
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
        dcqlQuery = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "ldp-no-binding", format = "ldp_vc", requireCryptographicHolderBinding = false),
            )
        )
    )

    private val testDcqlAuthorizationRequestMultiple = AuthorizationDcqlRequest(
        clientId = domain,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = MOCK_VERIFIER_RESPONSE,
        redirectUri = null,
        nonce = challenge,
        state = null,
        walletNonce = null,
        dcqlQuery = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = LDP_QUERY_1, format = "ldp_vc", requireCryptographicHolderBinding = true),
                CredentialQuery(id = LDP_QUERY_2, format = "ldp_vc", requireCryptographicHolderBinding = true),
            )
        )
    )

    @BeforeTest
    fun setup() {
        mockkObject(URDNA2015Canonicalization)
        every { URDNA2015Canonicalization.canonicalize(any()) } returns mockCanonicalizedData

        mockkStatic(::resolveJWSAlgorithm)
        every { resolveJWSAlgorithm(any(), any()) } returns "EdDSA"

        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            val input = firstArg<String>()
            java.util.Base64.getUrlDecoder().decode(input)
        }

        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            val input = firstArg<ByteArray>()
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(input)
        }
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) with JsonWebSignature2020`() {
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, INPUT_DESCRIPTOR_ID1),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, INPUT_DESCRIPTOR_ID2)
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )
        val (payload, unsignedTokens) = builder.build(mappings)
        val vpPayloads = payload as Map<*, *>
        assertEquals(2, vpPayloads.size)
        val firstIdentifier = mappings.first().identifier
        assertNotNull(firstIdentifier)
        val vpPayload = vpPayloads[firstIdentifier] as LdpVPToken
        assertEquals(2, vpPayload.context.size)
        assertTrue(vpPayload.context.contains("https://www.w3.org/2018/credentials/v1"))
        assertTrue(vpPayload.context.contains("https://w3id.org/security/suites/jws-2020/v1"))
        assertEquals(listOf("VerifiablePresentation"), vpPayload.type)
        assertEquals(listOf(ldpCredential1), vpPayload.verifiableCredential)
        assertEquals(id, vpPayload.id)
        val (expectedHolder, _) = UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(ldpCredential1)
        val sanitizedExpectedHolder = UnsignedLdpVPTokenBuilder.sanitizeHolderId(expectedHolder)
        assertEquals(sanitizedExpectedHolder, vpPayload.holder)
        val proof = vpPayload.proof
        assertNotNull(proof)
        assertEquals(SignatureSuiteAlgorithm.JsonWebSignature2020.value, proof?.type)
        assertEquals(null, proof?.created)
        assertEquals(sanitizedExpectedHolder, proof?.verificationMethod)
        assertEquals(domain, proof?.domain)
        assertEquals(challenge, proof?.challenge)
        assertEquals(2, unsignedTokens.size)
        val expectedHeaderMap = mapOf(
            "alg" to "EdDSA",
            "crit" to listOf("b64"),
            "b64" to false
        )
        val expectedHeaderJson = encodeToJsonString(expectedHeaderMap, "jwsHeader", "UnsignedLdpVPTokenBuilder")
        val expectedHeaderBase64Url = encodeToBase64Url(expectedHeaderJson.toByteArray(Charsets.UTF_8))
        val expectedRawPayloadBytes = java.util.Base64.getUrlDecoder().decode(mockCanonicalizedData)
        val expectedDataToSign = expectedHeaderBase64Url.toByteArray(Charsets.UTF_8) + byteArrayOf(0x2E.toByte()) + expectedRawPayloadBytes
        assertContentEquals(expectedDataToSign, unsignedTokens.first().dataToSign)
        assertEquals(FormatType.LDP_VC, unsignedTokens.first().format)
        assertEquals(sanitizedExpectedHolder, unsignedTokens.first().holderKeyReference)
        assertEquals("EdDSA", unsignedTokens.first().signatureAlgorithm)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) canonicalization error handling`() {
        every { URDNA2015Canonicalization.canonicalize(any()) } throws RuntimeException("Canonicalization failed")
        val mappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, INPUT_DESCRIPTOR_ID1),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, INPUT_DESCRIPTOR_ID2)
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )
        val exception = assertFailsWith<RuntimeException> {
            builder.build(mappings)
        }
        assertEquals("Canonicalization failed", exception.message)
    }

    @Test
    fun `test build(credentialInputDescriptorMappings) sets nestedPath correctly`() {
        val credentialInputDescriptorMappings = listOf(
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential1, INPUT_DESCRIPTOR_ID1),
            CredentialInputDescriptorMapping(FormatType.LDP_VC, ldpCredential2, INPUT_DESCRIPTOR_ID2)
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )

        builder.build(credentialInputDescriptorMappings)

        assertEquals("$.verifiableCredential[0]", credentialInputDescriptorMappings[0].nestedPath)
        assertEquals("$.verifiableCredential[0]", credentialInputDescriptorMappings[1].nestedPath)
    }

    @Test
    fun `test buildDcql extracts holder and signature suite from credential`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = LDP_QUERY_1
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequest,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        )
        val (payloads, unsignedTokens) = builder.build(mappings)

        assertEquals(1, unsignedTokens.size)
        assertEquals(FormatType.LDP_VC, unsignedTokens.first().format)
        assertEquals(SignatureSuiteAlgorithm.JsonWebSignature2020.value,
            (payloads.values.first() as? LdpVPToken)?.proof?.type)
        assertNotNull(mappings[0].identifier)
    }

    @Test
    fun `test buildDcql skips signing for non-holder-binding credential`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = "ldp-no-binding"
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequestNoBinding,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        )
        val (payloads, unsignedTokens) = builder.build(mappings)

        assertEquals(0, unsignedTokens.size)
        assertEquals(1, payloads.size)
        assertTrue(payloads.values.first() is LdpVcToken)
        assertNotNull(mappings[0].identifier)
    }

    @Test
    fun `test buildDcql builds per-credential VP tokens`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = LDP_QUERY_1
            ),
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential2,
                credentialQueryId = LDP_QUERY_2
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequestMultiple,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        )
        val (payloads, unsignedTokens) = builder.build(mappings)

        assertEquals(2, unsignedTokens.size)
        assertEquals(2, payloads.size)
        assertNotEquals(mappings[0].identifier, mappings[1].identifier)
    }

    @Test
    fun `test buildDcql throws for non-DCQL authorization request`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = LDP_QUERY_1
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            id = id,
            walletConfig
        )
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(mappings)
        }
        assertTrue(exception.message.contains("Expected AuthorizationDcqlRequest"))
    }

    @Test
    fun `test buildDcql throws for unknown credential query id`() {
        val mappings = mutableListOf(
            CredentialToCredentialQueryIdMapping(
                format = FormatType.LDP_VC,
                credential = ldpCredential1,
                credentialQueryId = "unknown-query-id"
            )
        )
        val builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest = testDcqlAuthorizationRequest,
            specVersion = SpecVersion.V1,
            id = id,
            walletConfig
        )
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(mappings)
        }
        assertTrue(exception.message.contains("No matching credential query found"))
    }

    @Test
    fun `test extractHolderAndSignatureSuite extracts correctly`() {
        val (holderId, suite) = UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(ldpCredential1)
        assertTrue(holderId.startsWith("did:jwk:"))
        assertEquals(SignatureSuiteAlgorithm.JsonWebSignature2020.value, suite)
    }

    @Test
    fun `test extractHolderAndSignatureSuite throws for invalid credential`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite("not-a-map")
        }
    }

    @Test
    fun `test extractHolderAndSignatureSuite throws for missing credentialSubject`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(mapOf("type" to "VerifiableCredential"))
        }
    }

    @Test
    fun `test extractHolderAndSignatureSuite throws for missing holder id`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder.extractHolderAndSignatureSuite(
                mapOf("credentialSubject" to mapOf("name" to "test"))
            )
        }
    }

    @Test
    fun `test sanitizeHolderId sanitizes correctly`() {
        assertEquals("abc-def_ghi#0", UnsignedLdpVPTokenBuilder.sanitizeHolderId("abc+def/ghi"))
        assertEquals("nodid#0", UnsignedLdpVPTokenBuilder.sanitizeHolderId("nodid"))
        assertEquals("base64url#0", UnsignedLdpVPTokenBuilder.sanitizeHolderId("base64url=="))
    }
}

