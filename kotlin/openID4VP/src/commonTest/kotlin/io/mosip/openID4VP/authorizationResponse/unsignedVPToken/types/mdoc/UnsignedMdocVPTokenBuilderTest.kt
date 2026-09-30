package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.resolveMdocKeyAndAlg
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.testData.clientId
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import io.mosip.openID4VP.testData.walletConfig
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.*

private const val INPUT_DESCRIPTOR_ID1 = "input-descriptor-id1"
private const val INPUT_DESCRIPTOR_ID2 = "input-descriptor-id2"

class UnsignedMdocVPTokenBuilderTest {
    private val secondMdocCredential = "second_mdoc_credential"
    private lateinit var firstDecodedMap: Map
    private lateinit var secondDecodedMap: Map

    private val testAuthorizationRequest = AuthorizationPresentationExchangeRequest(
        clientId = clientId,
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(presentationDefinitionMap, PresentationDefinitionSerializer),
        responseUri = responseUrl,
        redirectUri = null,
        nonce = verifierNonce,
        state = null,
        walletNonce = null,
    )

    @BeforeTest
    fun setUp() {
        mockkStatic(::getDecodedMdocCredential)
        mockkStatic(::resolveMdocKeyAndAlg)
        every { resolveMdocKeyAndAlg(any(), any()) } returns Pair("keyRef", "ES256")
        firstDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType1"))
        }
        secondDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType2"))
        }
    }


    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should create token with empty device auth when credentialInputDescriptorMappings list is empty`() {
        val result = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig
        ).build(emptyList())

        val unsignedTokens = result.second
        val payloadMap = result.first as? kotlin.collections.Map<*, *>
        assertNotNull(payloadMap)
        assertTrue(payloadMap.isEmpty())
        assertTrue(unsignedTokens.isEmpty())
    }

    @Test
    fun `should handle multiple different mdoc credentials correctly with credentialInputDescriptorMappings`() {
        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap
        val mappings = listOf(
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                mdocCredential,
                INPUT_DESCRIPTOR_ID1
            ),
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                secondMdocCredential,
                INPUT_DESCRIPTOR_ID2
            )
        )
        val result = UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce
        ,
            walletConfig
        ).build(mappings)
        val unsignedTokens = result.second
        @Suppress("UNCHECKED_CAST")
        val payloadMap = result.first as? kotlin.collections.Map<String, String>
        assertNotNull(payloadMap)
        assertEquals(2, payloadMap.size)
        assertEquals(2, unsignedTokens.size)

        val identifiers = mappings.map { mapping ->
            requireNotNull(mapping.identifier) { "identifier should be set for each mapping" }
        }
        assertTrue(identifiers.all { it.isNotBlank() })
        assertEquals(identifiers.toSet(), payloadMap.keys)
        assertEquals(identifiers, unsignedTokens.map { it.id })

        identifiers.forEachIndexed { index, identifier ->
            assertContentEquals(
                io.mosip.openID4VP.common.hexToByteArray(payloadMap[identifier]!!),
                unsignedTokens[index].dataToSign
            )
        }
        assertEquals(listOf("keyRef", "keyRef"), unsignedTokens.map { it.holderKeyReference })
        assertEquals(listOf("ES256", "ES256"), unsignedTokens.map { it.signatureAlgorithm })
    }

    @Test
    fun `should throw exception for malformed mdoc credential with credentialInputDescriptorMappings`() {
        mockkStatic(::getDecodedMdocCredential)
        every { getDecodedMdocCredential(any()) } throws IllegalArgumentException("Invalid CBOR data")
        val mappings = listOf(
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                "invalid_mdoc_credential",
                INPUT_DESCRIPTOR_ID1
            )
        )
        val exception = assertFailsWith<IllegalArgumentException> {
            UnsignedMdocVPTokenBuilder(
                authorizationRequest = testAuthorizationRequest,
                specVersion = SpecVersion.DRAFT_23,
                responseUri = responseUrl,
                mdocGeneratedNonce = walletNonce,
                walletConfig
            ).build(mappings)
        }
        assertEquals("Invalid CBOR data", exception.message)
    }

    @Test
    fun `should set nestedPath correctly in credentialInputDescriptorMappings`() {
        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap
        val mappings = listOf(
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                mdocCredential,
                INPUT_DESCRIPTOR_ID1
            ),
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                secondMdocCredential,
                INPUT_DESCRIPTOR_ID2
            )
        )
        UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig
        ).build(mappings)
        assertNull(mappings[0].nestedPath)
        assertNull(mappings[1].nestedPath)
    }

    @Test
    fun `should set identifier correctly in credentialInputDescriptorMappings`() {
        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap
        val mappings = listOf(
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                mdocCredential,
                INPUT_DESCRIPTOR_ID1
            ),
            CredentialInputDescriptorMapping(
                FormatType.MSO_MDOC,
                secondMdocCredential,
                INPUT_DESCRIPTOR_ID2
            ),
        )
        UnsignedMdocVPTokenBuilder(
            authorizationRequest = testAuthorizationRequest,
            specVersion = SpecVersion.DRAFT_23,
            responseUri = responseUrl,
            mdocGeneratedNonce = walletNonce,
            walletConfig
        ).build(mappings)
        assertTrue(!mappings[0].identifier.isNullOrBlank())
        assertTrue(!mappings[1].identifier.isNullOrBlank())
        assertNotEquals(mappings[0].identifier, mappings[1].identifier)
    }
}
