package com.example.keycloak.s2

import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import org.jboss.logging.Logger
import org.keycloak.component.ComponentModel
import org.keycloak.credential.CredentialInput
import org.keycloak.credential.CredentialInputValidator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.storage.StorageId
import org.keycloak.storage.UserStorageProvider
import org.keycloak.storage.user.UserLookupProvider

/**
 * Delegates password validation to Service2 by issuing a Basic Auth request against its secure endpoint.
 */
class S2UserStorageProvider(
    private val session: KeycloakSession,
    private val model: ComponentModel,
    private val secureEndpoint: URI,
    private val timeout: Duration
) : UserStorageProvider, UserLookupProvider, CredentialInputValidator {

    private val httpClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(timeout)
        .build()

    override fun close() {
        // Nothing to close
    }

    override fun getUserById(realm: RealmModel, id: String): UserModel? {
        val storageId = StorageId(id)
        val externalId = storageId.externalId
        return externalId?.let { createAdapter(realm, it) }
    }

    override fun getUserByUsername(realm: RealmModel, username: String?): UserModel? {
        val trimmed = username?.trim().orEmpty()
        if (trimmed.isEmpty()) {
            return null
        }
        return createAdapter(realm, trimmed)
    }

    override fun getUserByEmail(realm: RealmModel, email: String?): UserModel? {
        val trimmed = email?.trim().orEmpty()
        if (trimmed.isEmpty()) {
            return null
        }
        val username = trimmed.substringBefore('@')
        return createAdapter(realm, username)
    }

    override fun supportsCredentialType(credentialType: String?): Boolean =
        credentialType == PASSWORD_CREDENTIAL_TYPE

    override fun isConfiguredFor(realm: RealmModel, user: UserModel, credentialType: String?): Boolean =
        supportsCredentialType(credentialType)

    override fun isValid(realm: RealmModel, user: UserModel, credentialInput: CredentialInput): Boolean {
        if (!supportsCredentialType(credentialInput.type)) {
            return false
        }
        val password = credentialInput.challengeResponse ?: return false
        val username = user.username
        return validateAgainstService(username, password)
    }

    private fun createAdapter(realm: RealmModel, username: String): UserModel {
        LOGGER.debugf("Creating adapter for username %s", username)
        return S2UserAdapter(session, realm, model, this, username)
    }

    private fun validateAgainstService(username: String, password: String): Boolean {
        LOGGER.debugf("Validating credentials for %s using Service2", username)
        val request = HttpRequest.newBuilder(secureEndpoint)
            .timeout(timeout)
            .header("Authorization", buildBasicAuth(username, password))
            .GET()
            .build()
        return try {
            val response = httpClient.send(request, HttpResponse.BodyHandlers.discarding())
            when (response.statusCode()) {
                200 -> {
                    LOGGER.debugf("Service2 accepted credentials for %s", username)
                    true
                }
                401 -> {
                    LOGGER.debugf("Service2 rejected credentials for %s", username)
                    false
                }
                else -> {
                    LOGGER.warnf(
                        "Unexpected status %d while validating %s via Service2",
                        response.statusCode(),
                        username
                    )
                    false
                }
            }
        } catch (e: IOException) {
            LOGGER.errorf(e, "IO error while validating %s against Service2", username)
            false
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            LOGGER.warnf(e, "Request interrupted while validating %s", username)
            false
        }
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger(S2UserStorageProvider::class.java)
        private const val PASSWORD_CREDENTIAL_TYPE = "password"

        private fun buildBasicAuth(username: String, password: String): String {
            val token = "$username:$password"
            val encoded = Base64.getEncoder().encodeToString(token.toByteArray(StandardCharsets.UTF_8))
            return "Basic $encoded"
        }
    }
}
