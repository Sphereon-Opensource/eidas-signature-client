package com.sphereon.vdx.ades.pki

import com.fasterxml.jackson.databind.ObjectMapper
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.model.CertificateProviderConfig
import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.PasswordInputCallback
import com.sphereon.vdx.ades.rest.client.ApiResponse
import com.sphereon.vdx.ades.rest.client.JSON
import com.sphereon.vdx.ades.rest.client.api.CertificatesApi
import com.sphereon.vdx.ades.rest.client.model.CertificateResponse
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull


class RestCertificateProviderServiceTest {
    private val mapper: ObjectMapper = JSON.getDefault().mapper


    @Test
    fun `Given an alias the REST Certificate Provider Service should return a key`() {
        val data: CertificateResponse = mapper.readValue(mockedRESTResponse, CertificateResponse::class.java)
        val certProvider = setupCertProviderMock(data)
        val key = certProvider.getKey("rest")

        assertNotNull(key)
        assertEquals("rest", key.alias)
        assertNotNull(key.certificate)
        assertEquals("1A485229434026D47F47ADE3BDCA499253F588C0", key.certificate?.fingerPrint)
        assertEquals("C=LU, OU=PKI-TEST, O=Nowina Solutions, CN=good-ca", key.certificate?.issuerDN)
        assertEquals("C=LU, OU=PKI-TEST, O=Nowina Solutions, CN=good-user", key.certificate?.subjectDN)
        assertEquals("10", key.certificate?.serialNumber)
        assertNotNull(key.certificate?.keyUsage)
        assertEquals(9, key.certificate?.keyUsage!!.size)
        assertEquals(true, key.certificate?.keyUsage!!["nonRepudiation"])
        assertEquals(LocalDateTime.parse("2021-04-01T15:00:16").toInstant(TimeZone.UTC), key.certificate?.notBefore)
        assertEquals(LocalDateTime.parse("2023-02-01T15:00:16").toInstant(TimeZone.UTC), key.certificate?.notAfter)

        assertNotNull(key.certificateChain)
        assertEquals(3, key.certificateChain!!.size)
        // We already tested a certificate above. So we only test for proper order of the cert chain here
        assertEquals("1A485229434026D47F47ADE3BDCA499253F588C0", key.certificateChain!![0].fingerPrint)
        assertEquals("9198F0B98F86315152C2B27D74112D422D111BF0", key.certificateChain!![1].fingerPrint)
        assertEquals("F013A0FD6D5B45D2DD1792879545AAB1CA6117EA", key.certificateChain!![2].fingerPrint)

    }

    private fun setupCertProviderMock(data: CertificateResponse): RestCertificateProviderService {
        val certApiMock = mockk<CertificatesApi>()

        every {
            certApiMock.getCertificateWithHttpInfo("rest")
        } returns ApiResponse(
            200,
            emptyMap(),
            data
        )

        val certProvider = spyk(RestCertificateProviderService(constructCertificateProviderSettings(), constructRestClientConfig()))
        every {
            certProvider.newCertApi()
        } returns certApiMock
        return certProvider
    }


    private fun constructRestClientConfig(baseUrl: String? = "http://mocked"): RestClientConfig {
        return RestClientConfig(
            baseUrl = baseUrl
        )
    }

    private fun constructCertificateProviderSettings(
        password: String = "password",
        enableCache: Boolean = false
    ): CertificateProviderSettings {

        return CertificateProviderSettings(
            id = "rest",
            config = CertificateProviderConfig(
                cacheEnabled = enableCache,
                type = CertificateProviderType.REST,

                ),
            passwordInputCallback = PasswordInputCallback(password = password.toCharArray())
        )

    }

    private val mockedRESTResponse: String = "{\n" +
            "  \"certificateAlias\": \"good-user\",\n" +
            "  \"certificate\": \"MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjEwNDAxMTUwMDE2WhcNMjMwMjAxMTUwMDE2WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMG1XQLFDs+sOTot11luAHEGXgFBc/Y2Nqx0GLX0yj2fGdlgPm2T342OVrnc10/i4PpNuU7M14r23lq4Ovy/bZ92D6Dx3fCIzLXG44c2HzbEEgJ9i+eDuvZZtQjKFDDYXXq762O4XQI3fdC79+gD/A1xTEKIfKl2YozeQm0GdH6Glr1+qMOUzvgxJeagb8XFpbACl800GijCpl87IC1lkH0eRdqQ0YBQALiGMMHVJ7++PK//Em0zYoC2Voe3lfz2IYTSJtwvda4GzuXTunL/6CXsIMWfPXM/2c2yvZthfQySCuF5LpL+aRHq27VKLLSNAXj93Tc6GItGWR2TCJ92WokCAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFMlVsVjS0AsZNBNcTPHLRGAtD5YmMA0GCSqGSIb3DQEBCwUAA4IBAQAXBQjQSHexe5QksRo+Jt66mgYr9HJUQrOGkex0k1GQXm+919uJnPGLyXzHW0CZCCA+EzyOqAKXaIbPEgR3UKlkZ9UkhRZ7aC2SUrRLnBvP8IqTc/JJuZaXjQJQ5yNHrWfnAW6m6smC8WsVFAhtUmzlaHAz6MP7tK9dJsCe6vBPyjUbDiJqRthEZ7n8x9ZI3Y2nO0ZHuGdpFSTlu9GY3+A96ENUEo9xDaPrdU/wEZobeS28BQozPcN00naDoIjkl14y/VBEf8pDCfHeLbTARsAh+TCS6wFq5ChNE/WnxkBZpOt+EAU7XMXOVEJPNggQegIIRdCs8kYXxY1e6Q42vNaS\",\n" +
            "  \"certificateChain\": [\n" +
            "    \"MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjEwNDAxMTUwMDE2WhcNMjMwMjAxMTUwMDE2WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMG1XQLFDs+sOTot11luAHEGXgFBc/Y2Nqx0GLX0yj2fGdlgPm2T342OVrnc10/i4PpNuU7M14r23lq4Ovy/bZ92D6Dx3fCIzLXG44c2HzbEEgJ9i+eDuvZZtQjKFDDYXXq762O4XQI3fdC79+gD/A1xTEKIfKl2YozeQm0GdH6Glr1+qMOUzvgxJeagb8XFpbACl800GijCpl87IC1lkH0eRdqQ0YBQALiGMMHVJ7++PK//Em0zYoC2Voe3lfz2IYTSJtwvda4GzuXTunL/6CXsIMWfPXM/2c2yvZthfQySCuF5LpL+aRHq27VKLLSNAXj93Tc6GItGWR2TCJ92WokCAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFMlVsVjS0AsZNBNcTPHLRGAtD5YmMA0GCSqGSIb3DQEBCwUAA4IBAQAXBQjQSHexe5QksRo+Jt66mgYr9HJUQrOGkex0k1GQXm+919uJnPGLyXzHW0CZCCA+EzyOqAKXaIbPEgR3UKlkZ9UkhRZ7aC2SUrRLnBvP8IqTc/JJuZaXjQJQ5yNHrWfnAW6m6smC8WsVFAhtUmzlaHAz6MP7tK9dJsCe6vBPyjUbDiJqRthEZ7n8x9ZI3Y2nO0ZHuGdpFSTlu9GY3+A96ENUEo9xDaPrdU/wEZobeS28BQozPcN00naDoIjkl14y/VBEf8pDCfHeLbTARsAh+TCS6wFq5ChNE/WnxkBZpOt+EAU7XMXOVEJPNggQegIIRdCs8kYXxY1e6Q42vNaS\",\n" +
            "    \"MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjEwNDAxMTUwMDE1WhcNMjMwMjAxMTUwMDE1WjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4wVcOTmqmu8d8x0sEiNJCTumrClvl15Y7kOgWX7gUXg4GYgL2e1s0+iO+ib2j89Uh0sYMzjugOiicxgdm/GBfOgAZPe6u1RPFm/eQpYCn18LixYNND4DGBEH0a2UPwnbtzrSLyIKKDN4/q3QitSVWS6YpeiTi6baFYA2z5JiYTdHTR9WYiaTm7T8gIPkO/lLQU+E7yEPlxjLYHMxPwXbtTWPhKim7ANc1Gnlp3nSiLe3vPrngi4ZwnZ45SpKaYmWm3pwmNQ+aZCLXo3Q6ghW3hd98Oq0E4kFDSx2xpGdA5TRLPaWFKayB1aGPlSaePyuDfjE0PigzTiE/M6GsvVUvAgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgEGMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQU5N2O67uUmMdemeCUf+N7xeHPJGUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAXr4rbRBGydpP11oD3Usyu6StRsxEz537O9xCkF8n1JvGGXPoX/IxSxJObLJIHsxB04kZ1f0uC0uGOh2vAUWfh+YiO6725B5OAb3xS89RZ0O0w7662ZAdlPyomo6CjR6YdL2YkkBmMRB9RUjVO03vQdrKNcXtuVWIIomBorHW92HFudNbxjnetjtNZDarYKImN7o2IwzI2ounv48k2Rm60EDmAl5r2gMQCNvx5BTmMft72SHzEe/4X8TwNTqP4UE8T913ebaMM+1zKWBOCOLdUVXxIvVW41Ijdf6OZtFbsJvdSlKNU4858DKa/Mc32txWjGOLKJHl/Y+TpJGePoU8Ug==\",\n" +
            "    \"MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjEwMzAxMTUwMDE0WhcNMjMwMzAxMTUwMDE0WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgO1nOJjRKVVuXuCQQWA2K1g2zot1wLTcyxIVkT3KxQhRmGd75Wvetz7Bi4iuYc8s0E3DPd2HngGjEC0sIRwBmsEoUEUZkYJ2tfs5eUkX+EuJmfnbDuVClyyt0tjNOwo2SM6e3CsAFIRKDUIqalOZP6+xwA8F/+B7BIcAoGrAl/dteeZ7IvGi/JDz/GiaRWZz9jnOJREpyZgwaOKjF4O6lV97ha5JlTFuakK+TG2ahRWZVf6As9q8nv7mUbEfh6Ue/Iq/ChhnGqcxowHOBUaEBxaw2vj9qFva5uUQ7XDZnHfP1lJrIU+jWhIHw8gDhoGf0WLQ7FXFk5oLuTWBcWlX1AgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQURuOmisVqD2N+rHEOU7tCZMG0BPAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAJW+bA3sRNwXnN9xW2W9sieu/6LQKr8YD/uYCXMfmiWmBmNW+0bLRE5uy42rZC3TcPfsveA4TYAErLERkhNCDXnePoM6Sb9YeIXts0PNRVX6K4urHF32m1zHplwCcl8XmbE1ZDnu461lYywLxGeN+/3iHLWAU5ehAZYzarrUNnllDTAiqEB4dSg/+gdjeRzdloPlqX/qgcvC9dQUMNAmf4PFVQUXL8ik0j1Xf6ET8gDx6W9eEAezh/6yz6UzvU4zhf8sRdMqkG3L/eEA8CZ69wsA5iHg5GC9JSq+b/gKMeqTTwjEvECz+5UgbBXfA495eCJLr+bL3NFr7sPSNfsSBog==\"\n" +
            "  ]\n" +
            "}"
}
