package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.Array
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mockk.*
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.common.resolveMdocKeyAndAlg
import io.mosip.openID4VP.testData.mdocCredential
import kotlin.test.*
import co.nstant.`in`.cbor.model.Map as CborMap
private const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
private const val ELC_DOCTYPE = "org.iso.18013.5.1.elc"
private const val TEST_SIGNATURE_DATA_BASE64 = "c2lnbmF0dXJlX2RhdGE="
class MdocVPTokenBuilderJvmTest {

    private val docType = MDL_DOCTYPE

    @BeforeTest
    fun setUp() {
        mockkStatic(::resolveMdocKeyAndAlg)
        every { resolveMdocKeyAndAlg(any(), any()) } returns Pair("keyRef", "ES256")
        mockkStatic(::getDecodedMdocCredential)
        every { getDecodedMdocCredential(any()) } answers {
            val cred = firstArg<String>()
            val map = Map()
            // Use the credential to determine docType: first call returns mDL, second returns elc
            if (!cred.startsWith("om5")) { // mdocCredential from testData starts differently from encodeCbor output
                map.put(UnicodeString("docType"), UnicodeString(MDL_DOCTYPE))
            } else {
                map.put(UnicodeString("docType"), UnicodeString(ELC_DOCTYPE))
            }
            map
        }
    }

    @Test
    fun `should decode base64 using JVM decoder`() {
        val input = "aGVsbG8=" // "hello"
        val decoded = decodeFromBase64Url(input)
        assertEquals("hello", decoded.toString(Charsets.UTF_8))

        val id = "random-uuid"
        val unsignedVPToken = UnsignedVPToken(
            id = id,
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuthBytes".toByteArray()
        )
        val vpTokenSigningResults = listOf(VPTokenSigningResult(
            id = id,
            signedData = TEST_SIGNATURE_DATA_BASE64.toByteArray()
        ))

        val (vpTokens, descriptorMaps, nextIndex) = MdocVPTokenBuilder().build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredential,
                    MDL_DOCTYPE
                ).apply { identifier = id }
            ),
            unsignedVPTokenResult = Pair(
                mapOf(docType to "deviceAuthentication"),
                listOf(unsignedVPToken)
            ),
            vpTokenSigningResults = vpTokenSigningResults,
            rootIndex = 0
        )

        val vpToken = mdocVPToken(vpTokens)

        val decodedResult = decodeFromBase64Url(vpToken.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as Map

        assertEquals("1.0", decodedCbor[UnicodeString("version")].toString())
        assertEquals(0, decodedCbor[UnicodeString("status")].toString().toInt())
        assertNotNull(decodedCbor[UnicodeString("documents")])
        assertEquals(1, descriptorMaps.size)
        assertEquals("[DescriptorMap(id=org.iso.18013.5.1.mDL, format=mso_mdoc, path=\$[0], pathNested=null)]", descriptorMaps.toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should return token with multiple documents for multiple credentials`() {
        val mdocCredential2 = encodeCbor(
            cborMapOf(
                "docType" to ELC_DOCTYPE,
                "issuerSigned" to cborMapOf()
            )
        )

        val id = "random-uuid1"
        val id2 = "random-uuid2"
        val unsignedVPToken1 = UnsignedVPToken(
            id = id,
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth1".toByteArray()
        )
        val unsignedVPToken2 = UnsignedVPToken(
            id = id2,
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth2".toByteArray()
        )
        val vpTokenSigningResults = listOf(
            VPTokenSigningResult(
                id = id,
                signedData = TEST_SIGNATURE_DATA_BASE64.toByteArray()
            ),
            VPTokenSigningResult(
                id = id2,
                signedData = TEST_SIGNATURE_DATA_BASE64.toByteArray()
            )
        )

        val (vpTokens, descriptorMaps, nextIndex) = MdocVPTokenBuilder().build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    mdocCredential,
                    MDL_DOCTYPE
                ).apply { identifier = id },
                CredentialInputDescriptorMapping(
                    FormatType.MSO_MDOC,
                    encodeToBase64Url(mdocCredential2),
                    ELC_DOCTYPE
                ).apply { identifier = id2 }
            ),
            unsignedVPTokenResult = Pair(
                mapOf(
                    id to "deviceAuthentication2",
                    id2 to "deviceAuthentication1"
                ),
                listOf(unsignedVPToken1, unsignedVPToken2)
            ),
            vpTokenSigningResults = vpTokenSigningResults,
            rootIndex = 0
        )

        val vpToken = mdocVPToken(vpTokens)
        val decodedResult = decodeFromBase64Url(vpToken.base64EncodedDeviceResponse)
        val decodedCbor = CborDecoder(decodedResult.inputStream()).decode()[0] as CborMap

        val documents = decodedCbor[UnicodeString("documents")] as Array
        assertNotNull(documents)
        assertEquals(documents.dataItems.size, 2)

        assertEquals(1, nextIndex)
        assertEquals("[DescriptorMap(id=org.iso.18013.5.1.mDL, format=mso_mdoc, path=\$[0], pathNested=null), DescriptorMap(id=org.iso.18013.5.1.elc, format=mso_mdoc, path=\$[0], pathNested=null)]", descriptorMaps.toString())
    }

    @Test
    fun `should throw exception when device authentication signature is missing`() {
        val id = "random-uuid"
        val unsignedVPToken = UnsignedVPToken(
            id = id,
            format = FormatType.MSO_MDOC,
            holderKeyReference = "keyRef",
            signatureAlgorithm = "ES256",
            dataToSign = "deviceAuth1".toByteArray()
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            MdocVPTokenBuilder().build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(
                        FormatType.MSO_MDOC,
                        mdocCredential,
                        MDL_DOCTYPE
                    ).apply { identifier = id }
                ),
                unsignedVPTokenResult = Pair(
                    mapOf(id to "deviceAuthentication1"),
                    listOf(unsignedVPToken)
                ),
                vpTokenSigningResults = emptyList(),
                rootIndex = 0
            )
        }

        assertEquals(
            "Missing VP token signing result for credential identifier random-uuid",
            exception.message
        )
    }

    private fun mdocVPToken(vpTokens: List<MdocVPToken>): MdocVPToken {
        assertNotNull(vpTokens)
        assertEquals(vpTokens.size, 1)
        val vpToken = vpTokens.first()
        return vpToken
    }
}

