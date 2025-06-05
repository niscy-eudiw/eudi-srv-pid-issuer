/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc

import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.cryptoProvider
import eu.europa.ec.eudi.pidissuer.domain.MsoDocType
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.Status
import id.walt.mdoc.mso.StatusListInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.toKotlinInstant
import org.cose.java.OneKey
import java.time.Clock
import kotlin.io.encoding.Base64
import kotlin.time.Duration

internal class MsoMdocSigner<in Credential>(
    private val clock: Clock,
    private val issuerSigningKey: IssuerSigningKey,
    private val validityDuration: Duration,
    private val docType: MsoDocType,
    private val usage: MDocBuilder.(Credential) -> Unit,
) {

    init {
        require(validityDuration.isPositive()) { "Validity duration must be positive" }
    }

    private val issuerCryptoProvider: SimpleCOSECryptoProvider by lazy {
        issuerSigningKey.cryptoProvider()
    }

    suspend fun sign(credential: Credential, deviceKey: ECKey, statusListToken: StatusListToken?): String =
        withContext(Dispatchers.IO) {
            val validityInfo = validityInfo()
            val deviceKeyInfo = deviceKeyInfo(deviceKey)
            val mdoc = MDocBuilder(docType)
                .apply { usage(credential) }
                .sign(
                    validityInfo = validityInfo,
                    deviceKeyInfo = deviceKeyInfo,
                    cryptoProvider = issuerCryptoProvider,
                    keyID = issuerSigningKey.key.keyID,
                    status = statusListToken?.toStatus(),
                )
            Base64.UrlSafe.encode(mdoc.issuerSigned.toMapElement().toCBOR())
        }

    private fun validityInfo(): ValidityInfo {
        val signedAt = clock.instant().toKotlinInstant()
        val validTo = signedAt + validityDuration
        return ValidityInfo(signed = signedAt, validFrom = signedAt, validUntil = validTo, expectedUpdate = null)
    }
}

private fun deviceKeyInfo(deviceKey: ECKey): DeviceKeyInfo {
    val publicKey = deviceKey.toECPublicKey()
    val key = OneKey(publicKey, null)
    val deviceKeyDataElement: MapElement = DataElement.fromCBOR(key.AsCBOR().EncodeToBytes())
    return DeviceKeyInfo(deviceKeyDataElement, null, null)
}

private fun StatusListToken.toStatus(): Status =
    Status(
        statusList = StatusListInfo(
            index = index,
            uri = statusList.toString(),
        ),
    )
