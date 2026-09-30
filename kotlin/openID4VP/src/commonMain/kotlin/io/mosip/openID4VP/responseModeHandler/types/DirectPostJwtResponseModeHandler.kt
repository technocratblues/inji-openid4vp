package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.authorizationResponse.toMap
import io.mosip.openID4VP.constants.EncryptionMethod
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.EncryptionAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
private const val CLIENT_METADATA_REQUIRED_MESSAGE = "client_metadata must be present for given response mode"
private val className = DirectPostJwtResponseModeHandler::class.simpleName!!

class DirectPostJwtResponseModeHandler : ResponseModeBasedHandler() {
    override fun validate(
        clientMetadata: ClientMetadataDraft23?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Boolean
    ) {
        requireNotNull(clientMetadata) {
            throwInvalidDataException(CLIENT_METADATA_REQUIRED_MESSAGE)
        }

        val alg = clientMetadata.authorizationEncryptedResponseAlg
            ?: throwMissingInputException("authorization_encrypted_response_alg")

        val enc = clientMetadata.authorizationEncryptedResponseEnc
            ?: throwMissingInputException("authorization_encrypted_response_enc")

        val jwks = clientMetadata.jwks
            ?: throwMissingInputException("jwks")

        validateEncryption(
            verifierEncryptionAlg = listOf(alg),
            verifierEnc = listOf(enc),
            walletConfig = walletConfig,
            shouldValidate = shouldValidateWithWalletMetadata
        )

        selectEncryptionKey(jwks.keys, listOf(alg))
    }

    override fun validate(
        clientMetadata: ClientMetadata?,
        walletConfig: WalletConfig,
        shouldValidateWithWalletMetadata: Boolean
    ) {
        requireNotNull(clientMetadata) {
            throwInvalidDataException(CLIENT_METADATA_REQUIRED_MESSAGE)
        }

        val encValues = clientMetadata.encryptedResponseEncValuesSupported
        if (encValues.isNullOrEmpty()) {
            throwMissingInputException("encrypted_response_enc_values_supported")
        }

        val jwks = clientMetadata.jwks
            ?: throwMissingInputException("jwks")

        val verifierEncryptionAlgs = jwks.keys.mapNotNull { it.alg }.distinct()
        if (verifierEncryptionAlgs.isEmpty()) {
            throwInvalidDataException("No jwk with algorithm found in client_metadata.jwks")
        }
        validateEncryption(
            verifierEncryptionAlg = verifierEncryptionAlgs,
            verifierEnc = encValues,
            walletConfig = walletConfig,
            shouldValidate = shouldValidateWithWalletMetadata
        )
        val walletSupportedEncryptionAlgorithms =
            walletConfig.authorizationEncryptionAlgValuesSupported?.map { it.value } ?: listOf(
                EncryptionAlgorithm.ECDH_ES.value
            )
        selectEncryptionKey(jwks.keys, walletSupportedEncryptionAlgorithms)
    }

    private fun validateEncryption(
        verifierEncryptionAlg: List<String>,
        verifierEnc: List<String>,
        walletConfig: WalletConfig,
        shouldValidate: Boolean
    ) {
        if (shouldValidate) {
            val supportedAlgs = walletConfig.authorizationEncryptionAlgValuesSupported
                ?: throwInvalidDataException("authorization_encryption_alg_values_supported must be present in wallet_metadata")

            val supportedAlgValues = supportedAlgs.map { it.value }
            if (!verifierEncryptionAlg.any { supportedAlgValues.contains(it) }) {
                throwInvalidDataException("Authorization response encryption algorithm is not supported")
            }

            val supportedEncs = walletConfig.authorizationEncryptionEncValuesSupported
                ?: throwInvalidDataException("authorization_encryption_enc_values_supported must be present in wallet_metadata")

            val supportedEncValues = supportedEncs.map { it.value }
            if (!verifierEnc.any { supportedEncValues.contains(it) }) {
                throwInvalidDataException("authorization_encrypted_response_enc is not supported")
            }
        }
    }

    private fun throwMissingInputException(fieldName: String): Nothing {
        throw OpenID4VPExceptions.MissingInput(listOf("client_metadata", fieldName), "", className)
    }

    private fun throwInvalidDataException(message: String): Nothing {
        throw OpenID4VPExceptions.InvalidData(message, className)
    }

    override fun sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        url: String,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletConfig: WalletConfig
    ): NetworkResponse {
        val encryptedBodyParams = getAuthorizationResponse(
            authorizationRequest,
            authorizationResponse,
            walletNonce,
            walletConfig
        )

        return sendHTTPRequest(
            url = url,
            method = HttpMethod.POST,
            bodyParams = encryptedBodyParams,
            headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
        )
    }

    override fun getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletConfig: WalletConfig
    ): Map<String, String> {
        return encryptResponse(
            authorizationRequest, walletNonce,
            authorizationResponse.toMap(),
            walletConfig
        )
    }

    override fun getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ): Map<String, String> {
        return authorizationResponse.toJsonEncodedMap()
    }

    override fun getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletConfig: WalletConfig
    ): Jwk? {
        return SpecVersionHandler.from(authorizationRequest)
            .getVerifierPublicKey(authorizationRequest, walletConfig, className)
    }

    private fun encryptResponse(
        authorizationRequest: AuthorizationRequest,
        walletNonce: String,
        responseParams: Map<String, Any>,
        walletConfig: WalletConfig
    ): Map<String, String> {
        val specVersionHandler = SpecVersionHandler.from(authorizationRequest)
        val jweHandler = specVersionHandler.getJWEHandler(
            authorizationRequest,
            walletNonce,
            walletConfig,
            className
        )
        val encryptedBody = jweHandler.generateEncryptedResponse(responseParams)
        return mapOf("response" to encryptedBody)
    }

    private sealed class SpecVersionHandler {
        object V1 : SpecVersionHandler()
        object Draft23 : SpecVersionHandler()

        companion object {
            fun from(authorizationRequest: AuthorizationRequest): SpecVersionHandler {
                return if (authorizationRequest is AuthorizationPresentationExchangeRequest) Draft23 else V1
            }
        }

        fun getVerifierPublicKey(
            authorizationRequest: AuthorizationRequest,
            walletConfig: WalletConfig,
            className: String
        ): Jwk {
            return when (this) {
                is Draft23 -> {
                    val clientMetadata =
                        (authorizationRequest as AuthorizationPresentationExchangeRequest).clientMetadata!!
                    selectEncryptionKey(
                        clientMetadata.jwks!!.keys,
                        listOf(clientMetadata.authorizationEncryptedResponseAlg!!)
                    )
                }

                is V1 -> {
                    val clientMetadata =
                        (authorizationRequest as? AuthorizationDcqlRequest)?.clientMetadata
                            ?: throw OpenID4VPExceptions.InvalidData(
                                CLIENT_METADATA_REQUIRED_MESSAGE,
                                className
                            )
                    val verifierJwks = clientMetadata.jwks
                        ?: throw OpenID4VPExceptions.MissingInput(
                            listOf("client_metadata", "jwks"),
                            "",
                            className
                        )
                    val supportedAlgs =
                        walletConfig?.authorizationEncryptionAlgValuesSupported?.map { it.value }
                            ?: listOf(EncryptionAlgorithm.ECDH_ES.value)
                    selectEncryptionKey(verifierJwks.keys, supportedAlgs)
                }
            }
        }

        fun getJWEHandler(
            authorizationRequest: AuthorizationRequest,
            walletNonce: String,
            walletConfig: WalletConfig,
            className: String
        ): JWEHandler {
            return when (this) {
                is Draft23 -> {
                    val clientMetadata =
                        (authorizationRequest as AuthorizationPresentationExchangeRequest).clientMetadata!!
                    val verifierPublicKey =
                        getVerifierPublicKey(authorizationRequest, walletConfig, className)
                    JWEHandler(
                        keyEncryptionAlg = clientMetadata.authorizationEncryptedResponseAlg!!,
                        contentEncryptionAlg = clientMetadata.authorizationEncryptedResponseEnc!!,
                        publicKey = verifierPublicKey,
                        walletNonce = walletNonce,
                        verifierNonce = authorizationRequest.nonce
                    )
                }

                is V1 -> {
                    val clientMetadata =
                        (authorizationRequest as? AuthorizationDcqlRequest)?.clientMetadata
                            ?: throw OpenID4VPExceptions.InvalidData(
                                CLIENT_METADATA_REQUIRED_MESSAGE,
                                className
                            )
                    val encValues = clientMetadata.encryptedResponseEncValuesSupported
                    if (encValues.isNullOrEmpty()) {
                        throw OpenID4VPExceptions.InvalidData(
                            "Unsupported content encryption algorithm",
                            className
                        )
                    }
                    val walletEncValues =
                        walletConfig?.authorizationEncryptionEncValuesSupported?.map { it.value }
                            ?: listOf(EncryptionMethod.A256GCM.value)
                    val contentEncryptionAlgorithm =
                        walletEncValues.firstOrNull { encValues.contains(it) }
                            ?: throw OpenID4VPExceptions.InvalidData(
                                "Unsupported content encryption algorithm",
                                className
                            )
                    val verifierPublicKey =
                        getVerifierPublicKey(authorizationRequest, walletConfig, className)
                    val verifierPublicKeyAlg = verifierPublicKey.alg
                        ?: throw OpenID4VPExceptions.InvalidData(
                            "Algorithm must be specified for the encryption key in jwks",
                            className
                        )
                    JWEHandler(
                        keyEncryptionAlg = verifierPublicKeyAlg,
                        contentEncryptionAlg = contentEncryptionAlgorithm,
                        publicKey = verifierPublicKey,
                        walletNonce = walletNonce,
                        verifierNonce = authorizationRequest.nonce
                    )
                }
            }
        }
    }

    private companion object {
        fun selectEncryptionKey(keys: List<Jwk>, algValues: List<String>): Jwk {
            val matchingKeys = keys.filter { algValues.contains(it.alg) }
            if (matchingKeys.isEmpty()) {
                throw OpenID4VPExceptions.InvalidData(
                    "No jwk matching the specified algorithm found for encryption",
                    className
                )
            }

            if (matchingKeys.size == 1) {
                return matchingKeys.first()
            }

            val encryptionKeys = matchingKeys.filter { it.use == "enc" }
            if (encryptionKeys.size == 1) {
                return encryptionKeys.first()
            }

            throw OpenID4VPExceptions.InvalidData(
                "Multiple jwks matching the specified algorithm found for encryption",
                className
            )
        }
    }
}
