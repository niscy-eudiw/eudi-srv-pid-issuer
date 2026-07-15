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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl

import arrow.core.nel
import arrow.core.nonEmptySetOf
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.IssueMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.DrivingPrivilege.Restriction.GenericRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.DrivingPrivilege.Restriction.ParameterizedRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.coseAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.*
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import kotlinx.datetime.toKotlinLocalDate
import java.time.ZoneOffset
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.toKotlinInstant

@Suppress("FunctionName")
fun IssueMobileDrivingLicence(
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    deviceBinding: DeviceBinding.Required,
    validity: Duration,
    clock: Clock,
    validateProof: ValidateProof,
    generateNotificationId: GenerateNotificationId?,
    storeIssuedCredential: StoreIssuedCredential,
    getAttestationAttributes: GetAttestationAttributes<MobileDrivingLicence>,
    allocateStatus: AllocateStatus,
    issuerSigningKey: IssuerSigningKey,
): IssueMdoc<MobileDrivingLicence> {
    val configuration =
        mdlV1Cfg(issuerSigningKey.coseAlgorithm, deviceBinding, credentialReusePolicy, validity)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        EncodeAttestationAttributesInMdoc(issuerSigningKey, configuration.docType) { put(it) },
    )
}

internal fun mdlV1Cfg(
    credentialSigningAlgorithm: CoseAlgorithm,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): MsoMdocCredentialConfiguration {
    val scope = Scope(mdlDocType(1u))
    return MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(scope.value),
        docType = mdlDocType(1u),
        display = CredentialDisplay(DisplayName.en("Mobile Driving Licence (MSO MDoc)")).nel(),
        claims = MsoMdocMdlV1Claims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(credentialSigningAlgorithm),
        scope = scope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Eaa,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )
}

private fun MsoMdocBuilder.put(licence: MobileDrivingLicence) {
    put(MsoMdocMdlV1Claims.nameSpace) {
        put(licence.driver)
        put(licence.issueAndExpiry)
        put(licence.issuer)
        put(MsoMdocMdlV1Claims.DocumentNumber.name, licence.documentNumber.value)
        put(MsoMdocMdlV1Claims.DrivingPrivileges.name, licence.privileges.map { it.toMsoMdoc() }.toMsoMdoc())
        licence.administrativeNumber?.let { put(MsoMdocMdlV1Claims.AdministrativeNumber.name, it.value) }
    }
}

private fun MsoMdocNameSpaceBuilder.put(driver: Driver) {
    put(MsoMdocMdlV1Claims.FamilyName.name, driver.familyName.latin.value)
    put(MsoMdocMdlV1Claims.GivenName.name, driver.givenName.latin.value)
    put(MsoMdocMdlV1Claims.BirthDate.name, driver.birthDate.toKotlinLocalDate())
    put(MsoMdocMdlV1Claims.Portrait.name, driver.portrait.image.content)
    driver.portrait.capturedAt?.let {
        put(
            MsoMdocMdlV1Claims.PortraitCaptureDate.name,
            it.toInstant(ZoneOffset.UTC).toKotlinInstant(),
        )
    }
    driver.sex?.let { put(MsoMdocMdlV1Claims.Sex.name, it.code) }
    driver.height?.let { put(MsoMdocMdlV1Claims.Height.name, it.value) }
    driver.weight?.let { put(MsoMdocMdlV1Claims.Weight.name, it.value) }
    driver.eyeColour?.let { put(MsoMdocMdlV1Claims.EyeColour.name, it.code) }
    driver.hairColour?.let { put(MsoMdocMdlV1Claims.HairColour.name, it.code) }
    driver.birthPlace?.let { put(MsoMdocMdlV1Claims.BirthPlace.name, it.value) }
    driver.residence?.let { residence ->
        residence.address?.let { put(MsoMdocMdlV1Claims.ResidentAddress.name, it.value) }
        residence.city?.let { put(MsoMdocMdlV1Claims.ResidentCity.name, it.value) }
        residence.state?.let { put(MsoMdocMdlV1Claims.ResidentState.name, it.value) }
        residence.postalCode?.let { put(MsoMdocMdlV1Claims.ResidentPostalCode.name, it.value) }
        put(MsoMdocMdlV1Claims.ResidentCountry.name, residence.country.code)
    }
    driver.age?.let { age ->
        put(MsoMdocMdlV1Claims.AgeInYears.name, age.value.value)
        age.birthYear?.let { put(MsoMdocMdlV1Claims.AgeBirthYear.name, it.value) }
        put(MsoMdocMdlV1Claims.AgeOver18.name, age.over18)
        put(MsoMdocMdlV1Claims.AgeOver21.name, age.over21)
    }
    driver.nationality?.let { put(MsoMdocMdlV1Claims.Nationality.name, it.code) }
    driver.familyName.utf8?.let { put(MsoMdocMdlV1Claims.FamilyNameNationalCharacter.name, it) }
    driver.givenName.utf8?.let { put(MsoMdocMdlV1Claims.GivenNameNationalCharacter.name, it) }
    driver.signature?.let { put(MsoMdocMdlV1Claims.SignatureUsualMark.name, it.content) }
}

private fun MsoMdocNameSpaceBuilder.put(issueAndExpiry: IssueAndExpiry) {
    put(MsoMdocMdlV1Claims.IssueDate.name, issueAndExpiry.issuedAt.toKotlinLocalDate())
    put(MsoMdocMdlV1Claims.ExpiryDate.name, issueAndExpiry.expiresAt.toKotlinLocalDate())
}

private fun MsoMdocNameSpaceBuilder.put(issuer: Issuer) {
    put(MsoMdocMdlV1Claims.IssuingCountry.name, issuer.country.countryCode.code)
    put(MsoMdocMdlV1Claims.IssuingAuthority.name, issuer.authority.value)
    put(MsoMdocMdlV1Claims.IssuingCountryDistinguishingSign.name, issuer.country.distinguishingSign.code)
    issuer.jurisdiction?.let { put(MsoMdocMdlV1Claims.IssuingJurisdiction.name, it.value) }
}

private fun DrivingPrivilege.toMsoMdoc(): MsoMdocAttribute.MapAttribute =
    buildMsoMdocMap {
        put("vehicle_category_code", vehicleCategory.code)
        issueAndExpiry?.let { issueAndExpiry ->
            put("issue_date", issueAndExpiry.issuedAt.toKotlinLocalDate())
            put("expiry_date", issueAndExpiry.expiresAt.toKotlinLocalDate())
        }
        restrictions?.let { restrictions ->
            put("codes", restrictions.map { it.toMsoMdoc() }.toMsoMdoc())
        }
    }

private fun DrivingPrivilege.Restriction.toMsoMdoc(): MsoMdocAttribute.MapAttribute =
    buildMsoMdocMap {
        val (code, sign, value) =
            when (this@toMsoMdoc) {
                is GenericRestriction -> {
                    Triple(code, null, null)
                }

                is ParameterizedRestriction.VehiclePower -> {
                    Triple(
                        code,
                        value.code,
                        value.value.value,
                    )
                }

                is ParameterizedRestriction.VehicleAuthorizedMass -> {
                    Triple(
                        code,
                        value.code,
                        value.value.value,
                    )
                }

                is ParameterizedRestriction.VehicleCylinderCapacity -> {
                    Triple(
                        code,
                        value.code,
                        value.value.value,
                    )
                }

                is ParameterizedRestriction.VehicleAuthorizedPassengerSeats -> {
                    Triple(
                        code,
                        value.code,
                        value.value.value,
                    )
                }
            }

        put("code", code)
        sign?.let { put("sign", it) }
        value?.let { put("value", it.toString()) }
    }
