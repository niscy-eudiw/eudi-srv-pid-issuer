/*
 * Copyright (c) 2023-2026 European Commission
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
package eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc

import COSE.OneKey
import cbor.Cbor
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.certificate
import eu.europa.ec.eudi.pidissuer.adapter.out.cryptoProvider
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.x509.dropRootCA
import eu.europa.ec.eudi.pidissuer.domain.MsoDocType
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.domain.TokenStatusListSpec
import eu.europa.esig.dss.cbades.signature.CBAdESService
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters.X5ChainHeaderPlacement
import eu.europa.esig.dss.enumerations.COSEStructureType
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.enumerations.SignaturePackaging
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection
import eu.europa.esig.dss.token.DSSPrivateKeyAccessEntry
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.cose.COSECryptoProvider
import id.walt.mdoc.cose.COSESign1
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.MSO
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.toDeprecatedInstant
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.springframework.core.io.DefaultResourceLoader
import java.security.KeyStore
import java.security.PrivateKey
import kotlin.io.encoding.Base64
import java.time.Instant as JavaInstant
import java.util.Date as JavaDate

fun <Attr> encodeAttestationAttributesInMdoc(
    docType: MsoDocType,
    issuerSigningKey: IssuerSigningKey,
    usage: MDocBuilder.(Attr) -> Unit = {},
): EncodeAttestationAttributes<Attr> = EncodeAttestationAttributesInMdoc(issuerSigningKey, docType, usage)

private val base64UrlSafeNoPadding = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

private class EncodeAttestationAttributesInMdoc<in Attr>(
    private val issuerSigningKey: IssuerSigningKey,
    private val docType: MsoDocType,
    private val usage: MDocBuilder.(Attr) -> Unit,
) : EncodeAttestationAttributes<Attr> {
    private val issuerCryptoProvider: SimpleCOSECryptoProvider by lazy {
        issuerSigningKey.cryptoProvider(includeRootCA = false)
    }

    override suspend fun invoke(attestationAttributes: AttestationAttributes<Attr>): JsonElement {
        val (credential, issuedAt, expiresAt, _, deviceKey, statusListToken) = attestationAttributes
        require(deviceKey is ECKey) { "deviceKey must be ECKey" }
        require(expiresAt >= issuedAt) { "expiresAt must greater or equal to issuedAt" }
        val validityInfo =
            ValidityInfo(
                signed = issuedAt.dropFractionOfSeconds().toDeprecatedInstant(),
                validFrom = issuedAt.dropFractionOfSeconds().toDeprecatedInstant(),
                validUntil = expiresAt.dropFractionOfSeconds().toDeprecatedInstant(),
                expectedUpdate = null,
            )
        val deviceKeyInfo = deviceKeyInfo(deviceKey)
        val mdoc =
            MDocBuilder(docType)
                .apply { usage(credential) }
                .sign(validityInfo, deviceKeyInfo, statusListToken, issuerSigningKey)
        val encoded = base64UrlSafeNoPadding.encode(mdoc.issuerSigned.toMapElement().toCBOR())
        return JsonPrimitive(encoded)
    }
}

private suspend fun MDocBuilder.sign(
    validityInfo: ValidityInfo,
    deviceKeyInfo: DeviceKeyInfo,
    statusListToken: StatusListToken?,
    signingKey: IssuerSigningKey,
): MDoc {
    val service = CBAdESService(CommonCertificateVerifier())
    val signatureParameters =
        CBAdESSignatureParameters()
            .apply {
                signatureLevel = SignatureLevel.CB_AdES_BASELINE_B
                signaturePackaging = SignaturePackaging.ENVELOPING

                coseStructureType = COSEStructureType.COSE_SIGN1
                isTagged = true

                bLevel().signingDate = JavaDate.from(JavaInstant.ofEpochSecond(validityInfo.signed.value.epochSeconds))

                signingCertificate = CertificateToken(signingKey.certificate)
                certificateChain =
                    signingKey.key
                        .parsedX509CertChain
                        .dropRootCA()
                        .map { CertificateToken(it) }
                isIncludeCertificateChain = true
                x5ChainHeaderPlacement = X5ChainHeaderPlacement.protectedHeader
                isIncludeCertificateChainThumbprints = true

                digestAlgorithm =
                    when (signingKey.key.curve) {
                        Curve.P_256 -> DigestAlgorithm.SHA256
                        Curve.P_384 -> DigestAlgorithm.SHA384
                        Curve.P_521 -> DigestAlgorithm.SHA512
                        else -> error("Unsupported ECKey Curve '${signingKey.key.curve}'")
                    }
            }
    val payload = createIssuerAuthPayload(deviceKeyInfo, validityInfo, statusListToken)
    val unsignedDocument = InMemoryDocument(payload.toEncodedCBORElement().toCBOR())
    val unsignedData = service.getDataToSign(unsignedDocument, signatureParameters)

    val privateKey = signingKey.toDSSPrivateKeyAccessEntry(includeRootCA = false)
    val signatureTokenConnection = SimpleSignatureTokenConnection(privateKey)

    val signatureValue =
        withContext(Dispatchers.IO) {
            signatureTokenConnection.sign(unsignedData, signatureParameters.digestAlgorithm, privateKey)
        }
    val signedDocument = service.signDocument(unsignedDocument, signatureParameters, signatureValue)

    val serializedIssuerAuth = signedDocument.openStream().use { it.readBytes() }
    val issuerAuth = Cbor.decodeFromByteArray(COSESign1.serializer(), serializedIssuerAuth)

    return build(issuerAuth, null)
}

private fun MDocBuilder.createIssuerAuthPayload(
    deviceKeyInfo: DeviceKeyInfo,
    validityInfo: ValidityInfo,
    statusListToken: StatusListToken?,
): MapElement {
    val mso = MSO.createFor(nameSpacesMap, deviceKeyInfo, docType, validityInfo)
    return if (null != statusListToken) {
        buildMap {
            mso
                .toMapElement()
                .value.entries
                .forEach { put(it.key, it.value) }
            put(MapKey(TokenStatusListSpec.STATUS), statusListToken.toMsoStatus())
        }.toDataElement()
    } else {
        mso.toMapElement()
    }
}

private class SimpleSignatureTokenConnection(
    private val key: DSSPrivateKeyEntry,
) : AbstractSignatureTokenConnection() {
    override fun close() {
        // no-op
    }

    override fun getKeys(): List<DSSPrivateKeyEntry> = listOf(key)
}

private fun IssuerSigningKey.toDSSPrivateKeyAccessEntry(includeRootCA: Boolean): DSSPrivateKeyAccessEntry =
    object : DSSPrivateKeyAccessEntry {
        override fun getPrivateKey(): PrivateKey = this@toDSSPrivateKeyAccessEntry.key.toECPrivateKey()

        override fun getCertificate(): CertificateToken = CertificateToken(this@toDSSPrivateKeyAccessEntry.certificate)

        override fun getCertificateChain(): Array<CertificateToken> =
            this@toDSSPrivateKeyAccessEntry
                .key
                .let {
                    if (includeRootCA) {
                        it.parsedX509CertChain
                    } else {
                        it.parsedX509CertChain.dropRootCA()
                    }
                }.map { CertificateToken(it) }
                .toTypedArray()

        override fun getEncryptionAlgorithm(): EncryptionAlgorithm =
            EncryptionAlgorithm.forKey(this@toDSSPrivateKeyAccessEntry.key.toECPrivateKey())
    }

private fun deviceKeyInfo(deviceKey: ECKey): DeviceKeyInfo {
    val key = OneKey(deviceKey.toECPublicKey(), null)
    val deviceKeyDataElement: MapElement = DataElement.Companion.fromCBOR(key.AsCBOR().EncodeToBytes())
    return DeviceKeyInfo(deviceKeyDataElement, null, null)
}

/**
 * Build and sign the mdoc document
 * @param validityInfo Validity information of this issued document
 * @param deviceKeyInfo Info of device key, to which this document is bound (holder key)
 * @param statusListToken Status List Token to include in the document
 * @param cryptoProvider COSE crypto provider impl to use for signing this document
 * @param keyID ID of the key to use for signing, if required by crypto provider
 */
private fun MDocBuilder.sign(
    validityInfo: ValidityInfo,
    deviceKeyInfo: DeviceKeyInfo,
    statusListToken: StatusListToken?,
    cryptoProvider: COSECryptoProvider,
    keyID: String? = null,
): MDoc {
    val payload = createIssuerAuthPayload(deviceKeyInfo, validityInfo, statusListToken)
    val issuerAuth = cryptoProvider.sign1(payload.toEncodedCBORElement().toCBOR(), null, null, keyID)
    return build(issuerAuth)
}

/**
 * Converts this [StatusListToken] to a `Status` Map Element as defined in
 * [12.3.4 Signing method and structure for MSO](https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20ISO_IEC_18013-5_second-edition_CD_ballot_resolution_v3.pdf)
 */
private fun StatusListToken.toMsoStatus(): MapElement {
    fun StatusListToken.toDE(): MapElement =
        buildMap {
            put(MapKey(TokenStatusListSpec.IDX), index.toDataElement())
            put(MapKey(TokenStatusListSpec.URI), statusList.toString().toDataElement())
        }.toDataElement()

    return buildMap {
        put(MapKey(TokenStatusListSpec.STATUS_LIST), toDE())
    }.toDataElement()
}
