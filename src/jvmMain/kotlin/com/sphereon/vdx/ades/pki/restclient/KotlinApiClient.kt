package com.sphereon.vdx.ades.pki.restclient

import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.auth.Authentication

class KotlinApiClient(authMap: MutableMap<String, Authentication>?) : ApiClient(authMap) {
    init {
        json.mapper.registerKotlinModule()
    }
}
