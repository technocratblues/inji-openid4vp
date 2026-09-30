package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.SpecVersion
import kotlin.test.*

private const val DID_WEB_CLIENT_ID = "decentralized_identifier:did:web:example.com"
private const val UNKNOWN_PREFIX_CLIENT_ID = "foo:bar"
private const val VERIFIER_EXAMPLE_URL = "https://verifier.example.com"
private const val MY_CLIENT_ID = "my-client"
/**
 * Tests for AuthorizationRequestUtils.kt changes from PR #111:
 * - extractClientIdPrefix: infers prefix from client_id format
 * - extractClientIdPartOnly: extracts the actual client_id without prefix
 * - findSpecVersion: determines spec version from client_id_prefix and request params
 * - findSpecVersionUsingRequestParameters: determines spec version from dcql_query vs presentation_definition
 */
class AuthorizationRequestUtilsTest {

    // === extractClientIdPrefix ===

    @Test
    fun `extractClientIdPrefix returns pre-registered when client_id has no colon`() {
        val params = mapOf<String, Any>("client_id" to "my-client-id")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns redirect_uri when client_id starts with redirect_uri prefix`() {
        val params = mapOf<String, Any>("client_id" to "redirect_uri:https://example.com/callback")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.REDIRECT_URI.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns did when client_id starts with did prefix`() {
        val params = mapOf<String, Any>("client_id" to "did:web:example.com:service")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdScheme.DID.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns decentralized_identifier when client_id starts with that prefix`() {
        val params = mapOf<String, Any>("client_id" to DID_WEB_CLIENT_ID)
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns pre-registered for simple alphanumeric client_id`() {
        val params = mapOf<String, Any>("client_id" to "verifier123")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns pre-registered when client_id has unrecognized prefix`() {
        val params = mapOf<String, Any>("client_id" to UNKNOWN_PREFIX_CLIENT_ID)
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns pre-registered when client_id starts with URL scheme`() {
        val params = mapOf<String, Any>("client_id" to VERIFIER_EXAMPLE_URL)
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns pre-registered when client_id starts with pre-registered prefix`() {
        val params = mapOf<String, Any>("client_id" to "pre-registered:foo")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    // === extractClientIdPartOnly ===

    @Test
    fun `extractClientIdPartOnly returns full client_id for did prefix`() {
        val params = mapOf<String, Any>("client_id" to "did:web:mosip.github.io:service")
        val result = extractClientIdPartOnly(params)
        assertEquals("did:web:mosip.github.io:service", result)
    }

    @Test
    fun `extractClientIdPartOnly returns part after colon for redirect_uri prefix`() {
        val params = mapOf<String, Any>("client_id" to "redirect_uri:https://example.com/callback")
        val result = extractClientIdPartOnly(params)
        assertEquals("https://example.com/callback", result)
    }

    @Test
    fun `extractClientIdPartOnly returns DID URL after stripping decentralized_identifier prefix`() {
        val params = mapOf<String, Any>("client_id" to DID_WEB_CLIENT_ID)
        val result = extractClientIdPartOnly(params)
        // For V1 decentralized_identifier prefix, strip the prefix to get actual DID URL
        assertEquals("did:web:example.com", result)
    }

    @Test
    fun `extractClientIdPartOnly returns full client_id when no colon present`() {
        val params = mapOf<String, Any>("client_id" to "simple-client")
        val result = extractClientIdPartOnly(params)
        assertEquals("simple-client", result)
    }

    @Test
    fun `extractClientIdPartOnly returns full client_id for unrecognized prefix`() {
        val params = mapOf<String, Any>("client_id" to UNKNOWN_PREFIX_CLIENT_ID)
        val result = extractClientIdPartOnly(params)
        assertEquals(UNKNOWN_PREFIX_CLIENT_ID, result)
    }

    @Test
    fun `extractClientIdPartOnly returns full client_id for URL scheme`() {
        val params = mapOf<String, Any>("client_id" to VERIFIER_EXAMPLE_URL)
        val result = extractClientIdPartOnly(params)
        assertEquals(VERIFIER_EXAMPLE_URL, result)
    }

    // === findSpecVersionUsingRequestParameters ===

    @Test
    fun `findSpecVersionUsingRequestParameters returns V1 when dcql_query is present`() {
        val params = mapOf<String, Any>(
            "dcql_query" to "{}",
            "client_id" to "test"
        )
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.V1, result)
    }

    @Test
    fun `findSpecVersionUsingRequestParameters returns DRAFT_23 when presentation_definition is present`() {
        val params = mapOf<String, Any>(
            "presentation_definition" to "{}",
            "client_id" to "test"
        )
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.DRAFT_23, result)
    }

    @Test
    fun `findSpecVersionUsingRequestParameters returns DRAFT_23 when presentation_definition_uri is present`() {
        val params = mapOf<String, Any>(
            "presentation_definition_uri" to "https://example.com/pd",
            "client_id" to "test"
        )
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.DRAFT_23, result)
    }

    @Test
    fun `findSpecVersionUsingRequestParameters returns DRAFT_23 when neither dcql_query nor presentation_definition present`() {
        val params = mapOf<String, Any>("client_id" to "test")
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.DRAFT_23, result)
    }

    @Test
    fun `findSpecVersionUsingRequestParameters prefers dcql_query over presentation_definition`() {
        val params = mapOf<String, Any>(
            "dcql_query" to "{}",
            "presentation_definition" to "{}",
            "client_id" to "test"
        )
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.V1, result)
    }

    // === findSpecVersion ===

    @Test
    fun `findSpecVersion returns V1 for any prefix other than pre-registered or decentralized_identifier (did)`() {
        val params = mapOf<String, Any>(
            "presentation_definition" to "{}",
            "client_id" to "redirect_uri:https://example.com"
        )
        val result = findSpecVersionUsingClientId(
            clientId = "redirect_uri:https://example.com",
            clientIdPrefix = ClientIdPrefix.REDIRECT_URI.value,
            trustedVerifiers = emptyList()
        )
        assertEquals(SpecVersion.V1, result)
    }

    @Test
    fun `findSpecVersion returns V1 for decentralized_identifier prefix`() {
        val params = mapOf<String, Any>(
            "client_id" to DID_WEB_CLIENT_ID,
            "request_uri" to "https://example.com/request"
        )
        val result = findSpecVersionUsingClientId(
            clientId = DID_WEB_CLIENT_ID,
            clientIdPrefix = ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value,
            trustedVerifiers = emptyList()
        )
        assertEquals(SpecVersion.V1, result)
    }

    @Test
    fun `findSpecVersion returns trustedVerifier specVersion for pre-registered when verifier found`() {
        val verifiers = listOf(
            Verifier(MY_CLIENT_ID, listOf("https://example.com/response"), specVersion = SpecVersion.DRAFT_23)
        )
        val params = mapOf<String, Any>("client_id" to MY_CLIENT_ID)
        val result = findSpecVersionUsingClientId(
            clientId = MY_CLIENT_ID,
            clientIdPrefix = ClientIdPrefix.PRE_REGISTERED.value,
            trustedVerifiers = verifiers
        )
        assertEquals(SpecVersion.DRAFT_23, result)
    }

    @Test
    fun `findSpecVersion returns V1 for pre-registered when verifier not found in trustedVerifiers`() {
        val verifiers = listOf(
            Verifier("other-client", listOf("https://example.com/response"))
        )
        val params = mapOf<String, Any>(
            "client_id" to "unknown-client",
            "request_uri" to "https://example.com/request"
        )
        val result = findSpecVersionUsingClientId(
            clientId = "unknown-client",
            clientIdPrefix = ClientIdPrefix.PRE_REGISTERED.value,
            trustedVerifiers = verifiers
        )
        assertEquals(SpecVersion.V1, result)
    }

    @Test
    fun `findSpecVersion falls back to v1 for unknown prefix`() {
        val params = mapOf<String, Any>(
            "client_id" to "custom:something",
            "presentation_definition" to "{}"
        )
        val result = findSpecVersionUsingClientId(
            clientId = "custom:something",
            clientIdPrefix = "custom",
            trustedVerifiers = emptyList()
        )
        assertEquals(SpecVersion.V1, result)
    }
}
