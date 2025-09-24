package com.example.keycloak.s2

import java.util.Collections
import java.util.stream.Stream
import java.util.stream.StreamSupport
import org.keycloak.component.ComponentModel
import org.keycloak.credential.CredentialInput
import org.keycloak.credential.CredentialModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.SubjectCredentialManager
import org.keycloak.models.UserModel
import org.keycloak.storage.StorageId
import org.keycloak.storage.adapter.AbstractUserAdapter

/**
 * Minimal user adapter that exposes Service2 users to Keycloak.
 */
class S2UserAdapter(
    session: KeycloakSession,
    realm: RealmModel,
    model: ComponentModel,
    private val provider: S2UserStorageProvider,
    private val username: String
) : AbstractUserAdapter.Streams(session, realm, model) {

    private val id: String = StorageId.keycloakId(model, username)
    private val credentialManager: SubjectCredentialManager = S2SubjectCredentialManager()
    private val attributes: MutableMap<String, List<String>> = mutableMapOf(
        UserModel.USERNAME to listOf(username),
        UserModel.EMAIL to listOf("$username@service2.local"),
        UserModel.FIRST_NAME to listOf("Service2"),
        UserModel.LAST_NAME to listOf("User")
    )

    override fun credentialManager(): SubjectCredentialManager = credentialManager

    override fun getId(): String = id

    override fun getUsername(): String = username

    override fun setUsername(username: String) {
        throw UnsupportedOperationException("Read only user")
    }

    override fun getEmail(): String? =
        attributes[UserModel.EMAIL]?.firstOrNull()

    override fun setEmail(email: String) {
        throw UnsupportedOperationException("Read only user")
    }

    override fun getFirstName(): String? =
        attributes[UserModel.FIRST_NAME]?.firstOrNull()

    override fun setFirstName(firstName: String) {
        throw UnsupportedOperationException("Read only user")
    }

    override fun getLastName(): String? =
        attributes[UserModel.LAST_NAME]?.firstOrNull()

    override fun setLastName(lastName: String) {
        throw UnsupportedOperationException("Read only user")
    }

    override fun getAttributes(): Map<String, List<String>> =
        Collections.unmodifiableMap(attributes)

    override fun getAttributeStream(name: String): Stream<String> =
        attributes[name]?.let { StreamSupport.stream(it.spliterator(), false) } ?: Stream.empty()

    override fun setAttribute(name: String, values: MutableList<String>) {
        throw UnsupportedOperationException("Read only user")
    }

    override fun setSingleAttribute(name: String, value: String) {
        throw UnsupportedOperationException("Read only user")
    }

    override fun removeAttribute(name: String) {
        throw UnsupportedOperationException("Read only user")
    }

    private inner class S2SubjectCredentialManager : SubjectCredentialManager {
        override fun isValid(inputs: MutableList<CredentialInput>?): Boolean {
            if (inputs.isNullOrEmpty()) {
                return false
            }
            return inputs.all { provider.isValid(realm, this@S2UserAdapter, it) }
        }

        override fun updateCredential(input: CredentialInput?): Boolean {
            throw UnsupportedOperationException("Read only user")
        }

        override fun updateStoredCredential(cred: CredentialModel?) {
            throw UnsupportedOperationException("Read only user")
        }

        override fun createStoredCredential(cred: CredentialModel?): CredentialModel {
            throw UnsupportedOperationException("Read only user")
        }

        override fun removeStoredCredentialById(id: String?): Boolean {
            throw UnsupportedOperationException("Read only user")
        }

        override fun getStoredCredentialById(id: String?): CredentialModel? = null

        override fun getStoredCredentialsStream(): Stream<CredentialModel> = Stream.empty()

        override fun getStoredCredentialsByTypeStream(type: String?): Stream<CredentialModel> = Stream.empty()

        override fun getStoredCredentialByNameAndType(name: String?, type: String?): CredentialModel? = null

        override fun moveStoredCredentialTo(id: String?, newPreviousCredentialId: String?): Boolean {
            throw UnsupportedOperationException("Read only user")
        }

        override fun updateCredentialLabel(credentialId: String?, credentialLabel: String?) {
            throw UnsupportedOperationException("Read only user")
        }

        override fun disableCredentialType(credentialType: String?) {
            throw UnsupportedOperationException("Read only user")
        }

        override fun getDisableableCredentialTypesStream(): Stream<String> = Stream.empty()

        override fun isConfiguredFor(type: String?): Boolean =
            provider.isConfiguredFor(realm, this@S2UserAdapter, type)

        override fun isConfiguredLocally(type: String?): Boolean = isConfiguredFor(type)

        override fun getConfiguredUserStorageCredentialTypesStream(): Stream<String> = Stream.empty()

        override fun createCredentialThroughProvider(model: CredentialModel?): CredentialModel {
            throw UnsupportedOperationException("Read only user")
        }
    }
}
