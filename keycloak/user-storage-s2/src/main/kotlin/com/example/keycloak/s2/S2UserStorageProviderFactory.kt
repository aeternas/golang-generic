package com.example.keycloak.s2

import java.net.URI
import java.net.URISyntaxException
import java.time.Duration
import org.jboss.logging.Logger
import org.keycloak.component.ComponentModel
import org.keycloak.models.KeycloakSession
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.storage.UserStorageProviderFactory

/**
 * Factory that creates [S2UserStorageProvider] instances.
 */
class S2UserStorageProviderFactory : UserStorageProviderFactory<S2UserStorageProvider> {

    override fun create(session: KeycloakSession, model: ComponentModel): S2UserStorageProvider {
        val baseUrl = model.config.getFirst(CONFIG_BASE_URL)
        val endpoint = model.config.getFirst(CONFIG_ENDPOINT)
        val timeoutRaw = model.config.getFirst(CONFIG_TIMEOUT)

        val targetEndpoint = resolveEndpoint(baseUrl, endpoint)
        val timeout = parseTimeout(timeoutRaw)

        LOGGER.debugf(
            "Creating S2 user storage provider with endpoint %s and timeout %s",
            targetEndpoint,
            timeout
        )
        return S2UserStorageProvider(session, model, targetEndpoint, timeout)
    }

    override fun getId(): String = PROVIDER_ID

    override fun getConfigProperties(): MutableList<ProviderConfigProperty> = mutableListOf(
        BASE_URL,
        ENDPOINT,
        TIMEOUT
    )

    private fun resolveEndpoint(baseUrl: String?, endpoint: String?): URI {
        var effectiveBase = baseUrl?.trim().orEmpty()
        if (effectiveBase.isEmpty()) {
            effectiveBase = defaultValue(BASE_URL)
        }

        var effectiveEndpoint = endpoint?.trim().orEmpty()
        if (effectiveEndpoint.isEmpty()) {
            effectiveEndpoint = defaultValue(ENDPOINT)
        }

        val normalisedEndpoint = if (effectiveEndpoint.startsWith("/")) {
            effectiveEndpoint
        } else {
            "/$effectiveEndpoint"
        }

        return try {
            val baseUri = URI(effectiveBase)
            baseUri.resolve(normalisedEndpoint)
        } catch (e: URISyntaxException) {
            throw IllegalArgumentException("Invalid Service2 URL configuration", e)
        }
    }

    private fun parseTimeout(timeoutRaw: String?): Duration {
        var value = timeoutRaw?.trim().orEmpty()
        if (value.isEmpty()) {
            value = defaultValue(TIMEOUT)
        }

        val millis = value.toLongOrNull()
            ?: throw IllegalArgumentException("Timeout must be a number")
        require(millis > 0) { "Timeout must be positive" }
        return Duration.ofMillis(millis)
    }

    private fun defaultValue(property: ProviderConfigProperty): String {
        val value = property.defaultValue
        return value?.toString().orEmpty()
    }

    companion object {
        const val PROVIDER_ID = "s2-user-storage"

        internal const val CONFIG_BASE_URL = "s2BaseUrl"
        internal const val CONFIG_ENDPOINT = "s2Endpoint"
        internal const val CONFIG_TIMEOUT = "s2TimeoutMillis"

        private val LOGGER: Logger = Logger.getLogger(S2UserStorageProviderFactory::class.java)

        private val BASE_URL = ProviderConfigProperty(
            CONFIG_BASE_URL,
            "Service base URL",
            "Base URL for Service2. The provider calls its Basic Auth endpoint to validate credentials.",
            ProviderConfigProperty.STRING_TYPE,
            "http://service2:8081"
        )

        private val ENDPOINT = ProviderConfigProperty(
            CONFIG_ENDPOINT,
            "Secure endpoint path",
            "Relative path that requires HTTP Basic authentication on Service2.",
            ProviderConfigProperty.STRING_TYPE,
            "/secure-data"
        )

        private val TIMEOUT = ProviderConfigProperty(
            CONFIG_TIMEOUT,
            "Request timeout (ms)",
            "Timeout in milliseconds when contacting Service2.",
            ProviderConfigProperty.STRING_TYPE,
            "2000"
        )
    }
}
