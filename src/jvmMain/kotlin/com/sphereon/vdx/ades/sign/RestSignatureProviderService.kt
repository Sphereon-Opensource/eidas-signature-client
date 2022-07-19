package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.IKeyProviderService
import com.sphereon.vdx.ades.pki.RestClientConfig
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.auth.HttpBearerAuth
import com.sphereon.vdx.ades.rest.client.auth.OAuth
import com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding
import com.sphereon.vdx.ades.rest.client.model.DetermineSignInput
import com.sphereon.vdx.ades.rest.client.model.Digest
import com.sphereon.vdx.ades.rest.client.model.DigestAlgorithm
import kotlinx.datetime.Instant

private const val BEARER_LITERAL = "bearer"
private const val OAUTH2_LITERAL = "oauth2"

