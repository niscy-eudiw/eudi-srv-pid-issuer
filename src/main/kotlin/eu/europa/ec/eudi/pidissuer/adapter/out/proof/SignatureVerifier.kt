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
package eu.europa.ec.eudi.pidissuer.adapter.out.proof

import arrow.core.NonEmptyList
import arrow.core.raise.result
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jwt.SignedJWT
import eu.europa.esig.dss.enumerations.Indication
import eu.europa.esig.dss.enumerations.ValidationLevel
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor
import eu.europa.esig.dss.spi.x509.CertificateSource
import eu.europa.esig.dss.spi.x509.CommonCertificateSource
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.validation.SignedDocumentValidator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.cert.X509Certificate
import java.util.*
import kotlin.time.Instant
import kotlin.time.toJavaInstant

fun interface SignatureVerifier : suspend (String, NonEmptyList<X509Certificate>, Instant) -> SignatureVerificationResult {
    companion object {
        private fun certificateVerifier(certificateSource: CertificateSource): CommonCertificateVerifier =
            CommonCertificateVerifier(true).apply {
                val trustedCertificateSource =
                    CommonTrustedCertificateSource().apply {
                        importAsTrusted(certificateSource)
                    }
                setTrustedCertSources(trustedCertificateSource)
            }

        fun jadesBBValidator(): SignatureVerifier =
            { jwt, certificates, at ->
                result {
                    withContext(Dispatchers.IO) {
                        val certificateSource: CertificateSource =
                            CommonCertificateSource().apply {
                                certificates.forEach { certificate -> addCertificate(CertificateToken(certificate)) }
                            }

                        val certificateVerifier = certificateVerifier(certificateSource)

                        val validator =
                            SignedDocumentValidator.fromDocument(InMemoryDocument(jwt.toByteArray())).apply {
                                setCertificateVerifier(certificateVerifier)
                                setValidationLevel(ValidationLevel.BASIC_SIGNATURES)
                                setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE)
                                setValidationTime(Date.from(at.toJavaInstant()))
                            }

                        val report = validator.validateDocument().simpleReport
                        check(null != report.signatureIdList.singleOrNull()) { "JWT can not contain more than one signature" }

                        val signatureId = report.firstSignatureId
                        val indication = report.getIndication(signatureId)
                        if (indication == Indication.TOTAL_PASSED) {
                            SignatureVerificationResult.Passed
                        } else {
                            SignatureVerificationResult.Failed(
                                "JAdES B-B signature verification failed: indication=$indication, " +
                                    "subIndication=${report.getSubIndication(signatureId)}",
                            )
                        }
                    }
                }.getOrElse {
                    SignatureVerificationResult.Failed(
                        "JAdES B-B signature could not be verified",
                        it,
                    )
                }
            }

        fun jwsValidator(): SignatureVerifier =
            { jwt, certificates, _ ->
                result {
                    withContext(Dispatchers.IO) {
                        val signedJwt = SignedJWT.parse(jwt)
                        val publicKey = certificates.head.publicKey
                        val verifier = DefaultJWSVerifierFactory().createJWSVerifier(signedJwt.header, publicKey)
                        check(signedJwt.verify(verifier)) { "JWS signature is not valid" }
                        SignatureVerificationResult.Passed
                    }
                }.getOrElse { SignatureVerificationResult.Failed("JWS signature could not be verified", it) }
            }
    }
}

sealed interface SignatureVerificationResult {
    data object Passed : SignatureVerificationResult

    class Failed(
        val message: String,
        val cause: Throwable? = null,
    ) : SignatureVerificationResult
}
