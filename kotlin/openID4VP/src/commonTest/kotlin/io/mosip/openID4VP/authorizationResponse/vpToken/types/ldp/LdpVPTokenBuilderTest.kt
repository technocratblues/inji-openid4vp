package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToMultibaseBase58btc
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.testData.ldpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.constants.FormatType.LDP_VC
import kotlin.test.*
private const val TEST_TIMESTAMP = "2023-01-01T12:00:00Z"
private const val DID_EXAMPLE_KEY = "did:example:123#key-1"
private const val EXAMPLE_DOMAIN = "example.com"
private const val DID_EXAMPLE = "did:example:123"
private const val RANDOM_UUID = "random-uuid"
private const val INPUT_DESCRIPTOR_ID1 = "input-descriptor-id1"
private const val UUID_1 = "uuid-1"
private const val VERIFIABLE_CREDENTIAL_PATH = "$.verifiableCredential[0]"
private const val UUID_2 = "uuid-2"
class LdpVPTokenBuilderTest {

    private lateinit var mockLdpPayload: LdpVPToken
    private lateinit var mockUnsignedVPToken: UnsignedVPToken
    private lateinit var mockProof: Proof
    private val testNonce = "test-nonce-123"
    private val mockSignatureBytes = "test-proof-value-123".toByteArray(Charsets.UTF_8)
    private val mockHeaderBase64Url = "eyJhbGciOiJFZERTQSJ9"
    private val mockJwsDataToSign = mockHeaderBase64Url.toByteArray(Charsets.UTF_8) + byteArrayOf(0x2E) + "payload".toByteArray(Charsets.UTF_8)

    @BeforeTest
    fun setUp() {
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            val input = firstArg<ByteArray>()
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(input)
        }

        mockProof = Proof(
            type = "Ed25519Signature2020",
            created = TEST_TIMESTAMP,
            verificationMethod = DID_EXAMPLE_KEY,
            proofPurpose = "authentication",
            challenge = testNonce,
            proofValue = null,
            jws = null,
            domain = EXAMPLE_DOMAIN
        )

        mockLdpPayload = LdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = listOf(mapOf("id" to "vc-1")),
            id = "vpId-123",
            holder = DID_EXAMPLE,
            proof = mockProof
        )

        mockUnsignedVPToken = UnsignedVPToken(
            id = RANDOM_UUID,
            format = LDP_VC,
            holderKeyReference = DID_EXAMPLE,
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2020.value,
            dataToSign = "dataToSign".toByteArray(Charsets.UTF_8)
        )
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2020 successfully`() {
        val builder = LdpVPTokenBuilder()
        val signingResult = VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = mockSignatureBytes
        )

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, mockLdpPayload.verifiableCredential[0], INPUT_DESCRIPTOR_ID1)
                    .apply { identifier = RANDOM_UUID }
            ),
            unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to mockLdpPayload), listOf(mockUnsignedVPToken)),
            vpTokenSigningResults = listOf(signingResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(mockLdpPayload.context, vpToken.context)
        assertEquals(mockLdpPayload.type, vpToken.type)
        assertEquals(mockLdpPayload.verifiableCredential, vpToken.verifiableCredential)
        assertEquals(mockLdpPayload.id, vpToken.id)
        assertEquals(mockLdpPayload.holder, vpToken.holder)
        assertEquals(encodeToMultibaseBase58btc(mockSignatureBytes), vpToken.proof?.proofValue)
        assertEquals(null, vpToken.proof?.jws)
        assertEquals( """DescriptorMap(id=input-descriptor-id1, format=ldp_vp, path=${'$'}[0], pathNested=null)""", descriptorMaps.first().toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build one LDP VP token per selected credential`() {
        val builder = LdpVPTokenBuilder()
        val firstPayload = mockLdpPayload.copy(verifiableCredential = listOf(mockLdpPayload.verifiableCredential[0]))
        val secondCredential = mapOf("id" to "vc-2")
        val secondPayload = mockLdpPayload.copy(verifiableCredential = listOf(secondCredential))
        val firstMapping = CredentialInputDescriptorMapping(
            LDP_VC,
            firstPayload.verifiableCredential[0],
            INPUT_DESCRIPTOR_ID1
        ).apply {
            identifier = UUID_1
            nestedPath = VERIFIABLE_CREDENTIAL_PATH
        }
        val secondMapping = CredentialInputDescriptorMapping(
            LDP_VC,
            secondPayload.verifiableCredential[0],
            "input-descriptor-id2"
        ).apply {
            identifier = UUID_2
            nestedPath = VERIFIABLE_CREDENTIAL_PATH
        }

        val unsignedToken1 = mockUnsignedVPToken.copy(id = UUID_1)
        val unsignedToken2 = mockUnsignedVPToken.copy(id = UUID_2)

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(firstMapping, secondMapping),
            unsignedVPTokenResult = Pair(
                mapOf(
                    UUID_1 to firstPayload,
                    UUID_2 to secondPayload
                ),
                listOf(unsignedToken1, unsignedToken2)
            ),
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(id = UUID_1, signedData = "signature-1".toByteArray()),
                VPTokenSigningResult(id = UUID_2, signedData = "signature-2".toByteArray())
            ),
            rootIndex = 2
        )

        assertEquals(2, vpTokens.size)
        assertEquals(listOf(firstPayload.verifiableCredential[0]), (vpTokens[0] as LdpVPToken).verifiableCredential)
        assertEquals(listOf(secondPayload.verifiableCredential[0]), (vpTokens[1] as LdpVPToken).verifiableCredential)
        assertEquals("$[2]", descriptorMaps[0].path)
        assertEquals("$[3]", descriptorMaps[1].path)
        assertEquals(VERIFIABLE_CREDENTIAL_PATH, descriptorMaps[0].pathNested?.path)
        assertEquals(VERIFIABLE_CREDENTIAL_PATH, descriptorMaps[1].pathNested?.path)
        assertEquals(4, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with JsonWebSignature2020 successfully`() {
        val signingResult = VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = mockSignatureBytes
        )
        val jwsProof = Proof(
            type = SignatureSuiteAlgorithm.JsonWebSignature2020.value,
            created = TEST_TIMESTAMP,
            verificationMethod = DID_EXAMPLE_KEY,
            challenge = testNonce,
            domain = EXAMPLE_DOMAIN
        )
        val jwsPayload = mockLdpPayload.copy(proof = jwsProof)

        val jwsUnsignedVPToken = UnsignedVPToken(
            id = RANDOM_UUID,
            format = LDP_VC,
            holderKeyReference = DID_EXAMPLE,
            signatureAlgorithm = "EdDSA",
            dataToSign = mockJwsDataToSign
        )

        val builder = LdpVPTokenBuilder()

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, jwsPayload.verifiableCredential[0], INPUT_DESCRIPTOR_ID1)
                    .apply { identifier = RANDOM_UUID }
            ),
            unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to jwsPayload), listOf(jwsUnsignedVPToken)),
            vpTokenSigningResults = listOf(signingResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        val expectedJws = "$mockHeaderBase64Url..${encodeToBase64Url(mockSignatureBytes)}"
        assertEquals(expectedJws, vpToken.proof?.jws)
        assertEquals(null, vpToken.proof?.proofValue)
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with RSASignature2018 successfully`() {
        val rsaSignatureBytes = "test-rsa-signature".toByteArray(Charsets.UTF_8)
        val rsaSigningResult = VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = rsaSignatureBytes
        )
        val rsaProof = Proof(
            type = SignatureSuiteAlgorithm.RSASignature2018.value,
            created = TEST_TIMESTAMP,
            verificationMethod = DID_EXAMPLE_KEY,
            challenge = testNonce,
            domain = EXAMPLE_DOMAIN
        )
        val rsaPayload = mockLdpPayload.copy(proof = rsaProof)

        val builder = LdpVPTokenBuilder()

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, rsaPayload.verifiableCredential[0], INPUT_DESCRIPTOR_ID1)
                    .apply { identifier = RANDOM_UUID }
            ),
            unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to rsaPayload), listOf(mockUnsignedVPToken)),
            vpTokenSigningResults = listOf(rsaSigningResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(encodeToBase64Url(rsaSignatureBytes), vpToken.proof?.signatureValue)
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2018 successfully`() {
        val edSignatureBytes = "test-ed25519-2018-signature".toByteArray(Charsets.UTF_8)
        val edSigningResult = VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = edSignatureBytes
        )
        val edProof = Proof(
            type = SignatureSuiteAlgorithm.Ed25519Signature2018.value,
            created = TEST_TIMESTAMP,
            verificationMethod = DID_EXAMPLE_KEY,
            challenge = testNonce,
            domain = EXAMPLE_DOMAIN
        )
        val edPayload = mockLdpPayload.copy(proof = edProof)

        val edUnsignedVPToken = UnsignedVPToken(
            id = RANDOM_UUID,
            format = LDP_VC,
            holderKeyReference = DID_EXAMPLE,
            signatureAlgorithm = "EdDSA",
            dataToSign = mockJwsDataToSign
        )

        val builder = LdpVPTokenBuilder()

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, edPayload.verifiableCredential[0], INPUT_DESCRIPTOR_ID1)
                    .apply { identifier = RANDOM_UUID }
            ),
            unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to edPayload), listOf(edUnsignedVPToken)),
            vpTokenSigningResults = listOf(edSigningResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        val expectedJws = "$mockHeaderBase64Url..${encodeToBase64Url(edSignatureBytes)}"
        assertEquals(expectedJws, vpToken.proof?.jws)
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should use existing LdpVPToken from testData`() {
        val testToken = ldpVPToken as LdpVPToken
        val payloadCopy = LdpVPToken(
            context = testToken.context,
            type = testToken.type,
            verifiableCredential = testToken.verifiableCredential,
            id = testToken.id,
            holder = testToken.holder,
            proof = testToken.proof?.apply {
                proofValue = null
                jws = null
            }
        )

        val signingResult = VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = "new-proof-value".toByteArray(Charsets.UTF_8)
        )
        val builder = LdpVPTokenBuilder()

        val unsignedToken = UnsignedVPToken(
            id = RANDOM_UUID,
            format = LDP_VC,
            holderKeyReference = DID_EXAMPLE,
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2020.value,
            dataToSign = "dataToSign".toByteArray(Charsets.UTF_8)
        )

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, payloadCopy.verifiableCredential[0], INPUT_DESCRIPTOR_ID1)
                    .apply { identifier = RANDOM_UUID }
            ),
            unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to payloadCopy), listOf(unsignedToken)),
            vpTokenSigningResults = listOf(signingResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(encodeToMultibaseBase58btc("new-proof-value".toByteArray(Charsets.UTF_8)), vpToken.proof?.proofValue)
    }

    @Test
    fun `should handle null proof in unsigned token`() {
        val payloadWithNullProof = mockLdpPayload.copy(proof = null)
        val signingResult = VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = "some-sig".toByteArray(Charsets.UTF_8)
        )

        val builder = LdpVPTokenBuilder()

        assertFailsWith<NullPointerException> {
            builder.build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(LDP_VC, mockLdpPayload.verifiableCredential[0], INPUT_DESCRIPTOR_ID1)
                        .apply { identifier = RANDOM_UUID }
                ),
                unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to payloadWithNullProof), listOf(mockUnsignedVPToken)),
                vpTokenSigningResults = listOf(signingResult),
                rootIndex = 0
            )
        }
    }

    @Test
    fun `should throw MissingInput when LDP signature is missing`() {
        val exception = assertFailsWith<io.mosip.openID4VP.exceptions.OpenID4VPExceptions.MissingInput> {
            LdpVPTokenBuilder().build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(LDP_VC, mockLdpPayload.verifiableCredential[0], INPUT_DESCRIPTOR_ID1)
                        .apply { identifier = RANDOM_UUID }
                ),
                unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to mockLdpPayload), listOf(mockUnsignedVPToken)),
                vpTokenSigningResults = emptyList(),
                rootIndex = 0
            )
        }

        assertEquals("Missing LDP signature", exception.message)
    }

    @Test
    fun `should throw InvalidData when extra LDP signatures are provided`() {
        val exception = assertFailsWith<io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData> {
            LdpVPTokenBuilder().build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(LDP_VC, mockLdpPayload.verifiableCredential[0], INPUT_DESCRIPTOR_ID1)
                        .apply { identifier = RANDOM_UUID }
                ),
                unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to mockLdpPayload), listOf(mockUnsignedVPToken)),
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult(RANDOM_UUID, "signature-1".toByteArray()),
                    VPTokenSigningResult(RANDOM_UUID, "signature-2".toByteArray())
                ),
                rootIndex = 0
            )
        }

        assertEquals("LDP signing results count does not match selected credentials count", exception.message)
    }

    @Test
    fun `should build LdpVPToken using build method and return correct vp token, descriptor map and next index`() {
        val mapping = CredentialInputDescriptorMapping(
            format = LDP_VC,
            credential = mockLdpPayload.verifiableCredential[0],
            inputDescriptorId = INPUT_DESCRIPTOR_ID1
        ).apply { identifier = RANDOM_UUID }
        val signingResult = VPTokenSigningResult(
            id = RANDOM_UUID,
            signedData = mockSignatureBytes
        )
        val unsignedVPTokenResult = Pair(mapOf(RANDOM_UUID to mockLdpPayload), listOf(mockUnsignedVPToken))
        val builder = LdpVPTokenBuilder()
        val result = builder.build(
            credentialInputDescriptorMappings = listOf(mapping),
            unsignedVPTokenResult = unsignedVPTokenResult,
            vpTokenSigningResults = listOf(signingResult),
            rootIndex = 0
        )
        assertNotNull(result)
        assertEquals(1, result.first.size)
        assertEquals(1, result.second.size)
        assertEquals(1, result.third)
        assertEquals(INPUT_DESCRIPTOR_ID1, result.second[0].id)
        assertEquals(io.mosip.openID4VP.constants.VPFormatType.LDP_VP.value, result.second[0].format)
        assertEquals(encodeToMultibaseBase58btc(mockSignatureBytes), (result.first[0] as LdpVPToken).proof?.proofValue)
    }

    private fun ldpVPToken(vpTokens: List<VPToken>): LdpVPToken {
        assertNotNull(vpTokens)
        assertTrue(vpTokens.size == 1)
        val vpToken = vpTokens.first() as LdpVPToken
        return vpToken
    }
}

