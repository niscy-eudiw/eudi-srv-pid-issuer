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
package eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc

import arrow.core.raise.context.result
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.EncodeAttributesInSdJwtVcLogging.logDebug
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.pidissuer.adapter.out.x509.dropRootCA
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.asJwsJsonObject
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.serialize
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObject
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObjectBuilder
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import eu.europa.esig.dss.enumerations.*
import eu.europa.esig.dss.jades.JAdESSignatureParameters
import eu.europa.esig.dss.jades.JAdESSigningTimeType
import eu.europa.esig.dss.jades.signature.JAdESService
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection
import eu.europa.esig.dss.token.DSSPrivateKeyAccessEntry
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import eu.europa.esig.dss.token.SignatureTokenConnection
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.security.PrivateKey
import java.util.*
import kotlin.time.Instant
import kotlin.time.toJavaInstant

enum class SdJwtVcSerialization {
    Compact,
    JwsJson,
}

typealias GenerateJwtId = suspend () -> String

fun <Attr> encodeAttestationAttributesInSdJwtVc(
    sdJwtVcSerialization: SdJwtVcSerialization = SdJwtVcSerialization.Compact,
    digestsHashAlgorithm: HashAlgorithm = HashAlgorithm.SHA_256,
    issuerSigningKey: IssuerSigningKey,
    vct: SdJwtVcType,
    issuer: CredentialIssuerId? = null,
    generateJwtId: GenerateJwtId? = null,
    build: SdJwtObjectBuilder.(Attr) -> Unit,
): EncodeAttestationAttributes<Attr> =
    EncodeAttestationAttributesInSdJwtVc(
        digestsHashAlgorithm,
        sdJwtVcSerialization,
        issuerSigningKey,
        vct,
        issuer,
        generateJwtId,
        build,
    )

private class EncodeAttestationAttributesInSdJwtVc<in Attr>(
    private val digestsHashAlgorithm: HashAlgorithm,
    private val sdJwtVcSerialization: SdJwtVcSerialization,
    private val issuerSigningKey: IssuerSigningKey,
    private val vct: SdJwtVcType,
    private val issuer: CredentialIssuerId?,
    private val generateJwtId: GenerateJwtId?,
    private val build: SdJwtObjectBuilder.(Attr) -> Unit,
) : EncodeAttestationAttributes<Attr> {
    override suspend fun invoke(attestationAttributes: AttestationAttributes<Attr>): JsonElement {
        val (attributes, issuedAt, expiresAt, notBefore, deviceKey, status) = attestationAttributes
        val spec =
            sdJwt {
                claim(SdJwtVcSpec.VCT, vct.value)
                claim(RFC7519.ISSUED_AT, issuedAt.epochSeconds)
                claim(RFC7519.EXPIRATION_TIME, expiresAt.epochSeconds)
                issuer?.let { claim(RFC7519.ISSUER, it.externalForm) }
                notBefore?.let { claim(RFC7519.NOT_BEFORE, it.epochSeconds) }
                generateJwtId?.invoke()?.let { claim(RFC7519.JWT_ID, it) }
                deviceKey?.let { cnf(it) }
                status?.let {
                    objClaim("status") {
                        objClaim("status_list") {
                            claim("idx", it.index.toInt())
                            claim("uri", it.statusList.toString())
                        }
                    }
                }
                build(attributes)
            }
        return context(issuedAt) {
            encode(spec)
        }
    }

    context(issuedAt: Instant)
    private suspend fun encode(spec: SdJwtObject): JsonElement =
        context(issuerSigningKey, digestsHashAlgorithm, sdJwtVcSerialization, NimbusSdJwtOps) {
            val issuer = sdJwtVcIssuer(digestsHashAlgorithm)
            val sdJwt = issuer.issue(spec).getOrThrow().also { it.logDebug() }
            when (sdJwtVcSerialization) {
                SdJwtVcSerialization.Compact -> JsonPrimitive(sdJwt.serialize())
                SdJwtVcSerialization.JwsJson -> sdJwt.asJwsJsonObject(JwsSerializationOption.Flattened)
            }
        }
}

context(issuerSigningKey: IssuerSigningKey, issuedAt: Instant)
private fun sdJwtVcIssuer(digestsHashAlgorithm: HashAlgorithm): SdJwtIssuer<SignedJWT> =
    SdJwtIssuer { spec ->
        result {
            val parameters =
                JAdESSignatureParameters().apply {
                    signatureLevel = SignatureLevel.JAdES_BASELINE_B
                    signaturePackaging = SignaturePackaging.ENVELOPING

                    jwsSerializationType = JWSSerializationType.COMPACT_SERIALIZATION

                    issuerSigningKey.signatureAlgorithm.let {
                        encryptionAlgorithm = it.encryptionAlgorithm
                        digestAlgorithm = it.digestAlgorithm
                    }

                    signingCertificate = CertificateToken(issuerSigningKey.key.parsedX509CertChain.first())
                    isIncludeKeyIdentifier = true
                    signingCertificateDigestMethod = DigestAlgorithm.SHA256

                    certificateChain =
                        issuerSigningKey.key.parsedX509CertChain
                            .dropRootCA()
                            .map { CertificateToken(it) }
                    isIncludeCertificateChain = true
                    x5CHeaderPlacement = JAdESSignatureParameters.X5CHeaderPlacement.protectedHeader

                    signatureType = SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT
                    isIncludeSignatureType = true

                    bLevel().apply {
                        signingDate = Date.from(issuedAt.toJavaInstant())
                    }
                    jadesSigningTimeType = JAdESSigningTimeType.IAT
                }

            val service = JAdESService(CommonCertificateVerifier())

            val factory = SdJwtFactory(digestsHashAlgorithm)
            val (claims, disclosures) = factory.createSdJwt(spec).getOrThrow()
            val unsignedDocument = InMemoryDocument(jsonSupport.encodeToString(claims).encodeToByteArray())
            val dataToSign = service.getDataToSign(unsignedDocument, parameters)

            val signature =
                issuerSigningKey.signatureTokenConnection.sign(
                    dataToSign,
                    parameters.digestAlgorithm,
                    issuerSigningKey.privateKeyAccessEntry,
                )
            val signedDocument = service.signDocument(unsignedDocument, parameters, signature)

            val issuerSignedJwt = SignedJWT.parse(signedDocument.openStream().bufferedReader().use { it.readText() })
            SdJwt(issuerSignedJwt, disclosures)
        }
    }

private val IssuerSigningKey.signatureAlgorithm: SignatureAlgorithm
    get() =
        when (val curve = key.curve) {
            Curve.P_256 -> SignatureAlgorithm.ECDSA_SHA256
            Curve.P_384 -> SignatureAlgorithm.ECDSA_SHA384
            Curve.P_521 -> SignatureAlgorithm.ECDSA_SHA512
            else -> error("Unsupported ECKey Curve '$curve'")
        }

private val IssuerSigningKey.privateKeyAccessEntry: DSSPrivateKeyAccessEntry
    get() =
        object : DSSPrivateKeyAccessEntry {
            override fun getPrivateKey(): PrivateKey = key.toECPrivateKey()

            override fun getCertificate(): CertificateToken = CertificateToken(key.parsedX509CertChain.first())

            override fun getCertificateChain(): Array<CertificateToken> =
                key.parsedX509CertChain
                    .map {
                        CertificateToken(it)
                    }.toTypedArray()

            override fun getEncryptionAlgorithm(): EncryptionAlgorithm = EncryptionAlgorithm.forKey(key.toECPrivateKey())
        }

private val IssuerSigningKey.privateKeyEntry: DSSPrivateKeyEntry
    get() =
        object : DSSPrivateKeyEntry {
            override fun getCertificate(): CertificateToken = CertificateToken(key.parsedX509CertChain.first())

            override fun getCertificateChain(): Array<CertificateToken> =
                key.parsedX509CertChain
                    .map {
                        CertificateToken(it)
                    }.toTypedArray()

            override fun getEncryptionAlgorithm(): EncryptionAlgorithm = EncryptionAlgorithm.forKey(key.toECPrivateKey())
        }

private val IssuerSigningKey.signatureTokenConnection: SignatureTokenConnection
    get() =
        object : AbstractSignatureTokenConnection() {
            override fun getKeys(): List<DSSPrivateKeyEntry> = listOf(privateKeyEntry)

            override fun close() {
                // no-op
            }
        }

private object EncodeAttributesInSdJwtVcLogging {
    private val json = Json { prettyPrint = true }
    private val log = LoggerFactory.getLogger(EncodeAttributesInSdJwtVcLogging::class.java)

    private fun JsonElement.pretty(): String = json.encodeToString(this)

    fun SdJwt<SignedJWT>.logDebug() {
        log.debug(prettyPrint())
    }

    fun SdJwt<SignedJWT>.prettyPrint(): String {
        var str = "\nSD-JWT with ${disclosures.size} disclosures\n"
        disclosures.forEach { d ->
            val kind =
                when (d) {
                    is Disclosure.ArrayElement -> "\t - ArrayEntry ${d.claim().value().pretty()}"
                    is Disclosure.ObjectProperty -> "\t - ObjectProperty ${d.claim().first} = ${d.claim().second}"
                }
            str += kind + "\n"
        }
        str += "SD-JWT payload\n"
        str +=
            json.parseToJsonElement(jwt.jwtClaimsSet.toString()).run {
                json.encodeToString(this)
            }
        return str
    }
}
