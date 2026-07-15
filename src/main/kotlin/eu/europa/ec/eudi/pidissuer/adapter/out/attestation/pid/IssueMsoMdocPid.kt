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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid

import arrow.core.nonEmptySetOf
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.IssueMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.coseAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.*
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import java.util.Locale.ENGLISH
import kotlin.time.Clock
import kotlin.time.Duration

val PidMsoMdocScope: Scope = Scope("eu.europa.ec.eudi.pid_mso_mdoc")

private const val PID_DOCTYPE = "eu.europa.ec.eudi.pid"

private fun pidDocType(v: Int?): String =
    if (v == null)
        PID_DOCTYPE
    else
        "$PID_DOCTYPE.$v"

@Suppress("SameParameterValue")
fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

@Suppress("UNUSED")
private fun pidDomesticNameSpace(
    v: Int?,
    countryCode: String,
): MsoNameSpace =
    if (v == null)
        "$PID_DOCTYPE.$countryCode"
    else
        "$PID_DOCTYPE.$countryCode.$v"

val PidMsoMdocV1CredentialConfigurationId: CredentialConfigurationId = CredentialConfigurationId(PidMsoMdocScope.value)

internal fun pidMsoMdocV1(
    credentialSigningAlgorithm: CoseAlgorithm,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = PidMsoMdocV1CredentialConfigurationId,
        docType = pidDocType(1),
        display =
            listOf(
                CredentialDisplay(
                    name = DisplayName("PID (MSO MDoc)", ENGLISH),
                ),
            ),
        claims = MsoMdocPidClaims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(credentialSigningAlgorithm),
        scope = PidMsoMdocScope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Pid,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )

@Suppress("FunctionName")
fun IssueMsoMdocPid(
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    deviceBinding: DeviceBinding.Required,
    validity: Duration,
    clock: Clock,
    validateProof: ValidateProof,
    generateNotificationId: GenerateNotificationId?,
    storeIssuedCredential: StoreIssuedCredential,
    getAttestationAttributes: GetAttestationAttributes<PidAttributes>,
    allocateStatus: AllocateStatus,
    issuerSigningKey: IssuerSigningKey,
): IssueMdoc<PidAttributes> {
    val configuration =
        pidMsoMdocV1(issuerSigningKey.coseAlgorithm, deviceBinding, credentialReusePolicy, validity)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        EncodeAttestationAttributesInMdoc(issuerSigningKey, configuration.docType) { pidAttributes(it) },
    )
}

private fun MsoMdocBuilder.pidAttributes(pidAttributes: PidAttributes) {
    put(MsoMdocPidClaims.nameSpace) {
        put(pidAttributes.pid)
        put(pidAttributes.metaData)
    }
}

private fun MsoMdocNameSpaceBuilder.put(pid: Pid) {
    put(MsoMdocPidClaims.FamilyName.name, pid.familyName.value)
    put(MsoMdocPidClaims.GivenName.name, pid.givenName.value)
    put(MsoMdocPidClaims.BirthDate.name, pid.birthDate)

    val placeOfBirth: MsoMdocAttribute.MapAttribute =
        with(pid.placeOfBirth) {
            buildMsoMdocMap {
                country?.let { put("country", it.value) }
                region?.let { put("region", it.value) }
                locality?.let { put("locality", it.value) }
            }
        }
    put(MsoMdocPidClaims.PlaceOfBirth.name, placeOfBirth)

    put(MsoMdocPidClaims.Nationality.name, pid.nationalities.map { it.value.toMsoMdoc() }.toMsoMdoc())
    pid.residentAddress?.let { put(MsoMdocPidClaims.ResidenceAddress.name, it) }
    pid.residentCountry?.let { put(MsoMdocPidClaims.ResidenceCountry.name, it.value) }
    pid.residentState?.let { put(MsoMdocPidClaims.ResidenceState.name, it.value) }
    pid.residentCity?.let { put(MsoMdocPidClaims.ResidenceCity.name, it.value) }
    pid.residentPostalCode?.let { put(MsoMdocPidClaims.ResidencePostalCode.name, it.value) }
    pid.residentStreet?.let { put(MsoMdocPidClaims.ResidenceStreet.name, it.value) }
    pid.residentHouseNumber?.let { put(MsoMdocPidClaims.ResidenceHouseNumber.name, it) }
    pid.portrait?.let {
        val value =
            when (it) {
                is PortraitImage.JPEG -> it.value
                is PortraitImage.JPEG2000 -> it.value
            }
        put(MsoMdocPidClaims.Portrait.name, value)
    }
    pid.familyNameBirth?.let { put(MsoMdocPidClaims.FamilyNameBirth.name, it.value) }
    pid.givenNameBirth?.let { put(MsoMdocPidClaims.GivenNameBirth.name, it.value) }
    pid.sex?.let { put(MsoMdocPidClaims.Sex.name, it.value) }
    pid.emailAddress?.let { put(MsoMdocPidClaims.EmailAddress.name, it) }
    pid.mobilePhoneNumber?.let { put(MsoMdocPidClaims.MobilePhoneNumberAttribute.name, it.value) }
    pid.personalAdministrativeNumber?.let { put(MsoMdocPidClaims.PersonalAdministrativeNumber.name, it.value) }
}

private fun MsoMdocNameSpaceBuilder.put(metaData: PidMetaData) {
    put(MsoMdocPidClaims.ExpiryDate.name, metaData.expiryDate)
    when (val issuingAuthority = metaData.issuingAuthority) {
        is IssuingAuthority.MemberState -> {
            put(MsoMdocPidClaims.IssuingAuthority.name, issuingAuthority.code.value)
        }

        is IssuingAuthority.AdministrativeAuthority -> {
            put(MsoMdocPidClaims.IssuingAuthority.name, issuingAuthority.value)
        }
    }
    put(MsoMdocPidClaims.IssuingCountry.name, metaData.issuingCountry.value)
    metaData.documentNumber?.let { put(MsoMdocPidClaims.DocumentNumber.name, it.value) }
    metaData.issuingJurisdiction?.let { put(MsoMdocPidClaims.IssuingJurisdiction.name, it) }
    metaData.issuanceDate?.let { put(MsoMdocPidClaims.IssuanceDate.name, it) }
    metaData.attestationLegalCategory?.let {
        put(MsoMdocPidClaims.AttestationLegalCategory.name, it)
    }
}
