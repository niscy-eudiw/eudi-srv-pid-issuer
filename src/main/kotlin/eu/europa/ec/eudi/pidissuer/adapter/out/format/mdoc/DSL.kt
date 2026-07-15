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

import eu.europa.ec.eudi.pidissuer.domain.MsoNameSpace
import kotlinx.datetime.LocalDate
import kotlin.time.Instant

@DslMarker
@Target(AnnotationTarget.CLASS)
annotation class MsoMdocDslMarker

@MsoMdocDslMarker
class MsoMdocBuilder {
    val nameSpaces: Map<MsoNameSpace, Map<String, MsoMdocAttribute<*>>>
        field = mutableMapOf()

    fun put(
        nameSpace: MsoNameSpace,
        builderAction: MsoMdocNameSpaceBuilder.() -> Unit,
    ) {
        nameSpaces[nameSpace] = buildMsoMdocNameSpace(builderAction)
    }
}

fun buildMsoMdoc(builderAction: MsoMdocBuilder.() -> Unit): Map<MsoNameSpace, Map<String, MsoMdocAttribute<*>>> =
    MsoMdocBuilder().apply(builderAction).nameSpaces

@MsoMdocDslMarker
class MsoMdocNameSpaceBuilder {
    val attributes: Map<String, MsoMdocAttribute<*>>
        field = mutableMapOf()

    fun put(
        name: String,
        value: MsoMdocAttribute<*>,
    ) {
        attributes[name] = value
    }

    fun put(
        name: String,
        value: String,
    ) {
        put(name, MsoMdocAttribute.StringAttribute(value))
    }

    fun put(
        name: String,
        value: Int,
    ) {
        put(name, MsoMdocAttribute.IntAttribute(value))
    }

    fun put(
        name: String,
        value: UInt,
    ) {
        put(name, MsoMdocAttribute.UIntAttribute(value))
    }

    fun put(
        name: String,
        value: Double,
    ) {
        attributes[name] = MsoMdocAttribute.DoubleAttribute(value)
    }

    fun put(
        name: String,
        value: Float,
    ) {
        put(name, MsoMdocAttribute.FloatAttribute(value))
    }

    fun put(
        name: String,
        value: Boolean,
    ) {
        put(name, MsoMdocAttribute.BooleanAttribute(value))
    }

    fun put(
        name: String,
        value: LocalDate,
        format: MsoMdocAttribute.LocalDateAttribute.Format = MsoMdocAttribute.LocalDateAttribute.Format.FullDateString,
    ) {
        put(name, MsoMdocAttribute.LocalDateAttribute(value, format))
    }

    fun put(
        name: String,
        value: Instant,
        format: MsoMdocAttribute.InstantAttribute.Format = MsoMdocAttribute.InstantAttribute.Format.TDate,
    ) {
        put(name, MsoMdocAttribute.InstantAttribute(value, format))
    }

    fun put(
        name: String,
        value: ByteArray,
    ) {
        put(name, MsoMdocAttribute.ByteArrayAttribute(value))
    }

    fun putList(
        name: String,
        builderAction: MsoMdocListAttributeBuilder.() -> Unit,
    ) {
        put(name, buildMsoMdocList(builderAction))
    }

    fun putMap(
        name: String,
        builderAction: MsoMdocMapAttributeBuilder.() -> Unit,
    ) {
        put(name, buildMsoMdocMap(builderAction))
    }
}

fun buildMsoMdocNameSpace(builderAction: MsoMdocNameSpaceBuilder.() -> Unit): Map<String, MsoMdocAttribute<*>> =
    MsoMdocNameSpaceBuilder().apply(builderAction).attributes

sealed interface MsoMdocAttribute<out V> {
    val value: V

    data class StringAttribute(
        override val value: String,
    ) : MsoMdocAttribute<String>

    data class IntAttribute(
        override val value: Int,
    ) : MsoMdocAttribute<Int>

    data class UIntAttribute(
        override val value: UInt,
    ) : MsoMdocAttribute<UInt>

    data class DoubleAttribute(
        override val value: Double,
    ) : MsoMdocAttribute<Double>

    data class FloatAttribute(
        override val value: Float,
    ) : MsoMdocAttribute<Float>

    data class BooleanAttribute(
        override val value: Boolean,
    ) : MsoMdocAttribute<Boolean>

    data class LocalDateAttribute(
        override val value: LocalDate,
        val format: Format,
    ) : MsoMdocAttribute<LocalDate> {
        enum class Format(
            val tag: Long,
        ) {
            FullDateString(1004L),
            FullDateInt(100L),
        }
    }

    data class InstantAttribute(
        override val value: Instant,
        val format: Format,
    ) : MsoMdocAttribute<Instant> {
        enum class Format(
            val tag: Long,
        ) {
            TDate(0L),
            TTimeInt(1L),
            TTimeFloat(1L),
            TTimeDouble(1L),
        }
    }

    data class ByteArrayAttribute(
        override val value: ByteArray,
    ) : MsoMdocAttribute<ByteArray> {
        override fun equals(other: Any?): Boolean = value.contentEquals((other as? ByteArrayAttribute)?.value)

        override fun hashCode(): Int = value.contentHashCode()
    }

    data class ListAttribute(
        override val value: List<MsoMdocAttribute<*>>,
    ) : MsoMdocAttribute<List<MsoMdocAttribute<*>>>

    data class MapAttribute(
        override val value: Map<String, MsoMdocAttribute<*>>,
    ) : MsoMdocAttribute<Map<String, MsoMdocAttribute<*>>>
}

fun String.toMsoMdoc(): MsoMdocAttribute.StringAttribute = MsoMdocAttribute.StringAttribute(this)

fun Int.toMsoMdoc(): MsoMdocAttribute.IntAttribute = MsoMdocAttribute.IntAttribute(this)

fun UInt.toMsoMdoc(): MsoMdocAttribute.UIntAttribute = MsoMdocAttribute.UIntAttribute(this)

fun Double.toMsoMdoc(): MsoMdocAttribute.DoubleAttribute = MsoMdocAttribute.DoubleAttribute(this)

fun Float.toMsoMdoc(): MsoMdocAttribute.FloatAttribute = MsoMdocAttribute.FloatAttribute(this)

fun Boolean.toMsoMdoc(): MsoMdocAttribute.BooleanAttribute = MsoMdocAttribute.BooleanAttribute(this)

fun LocalDate.toMsoMdoc(
    format: MsoMdocAttribute.LocalDateAttribute.Format = MsoMdocAttribute.LocalDateAttribute.Format.FullDateString,
): MsoMdocAttribute.LocalDateAttribute = MsoMdocAttribute.LocalDateAttribute(this, format)

fun Instant.toMsoMdoc(
    format: MsoMdocAttribute.InstantAttribute.Format = MsoMdocAttribute.InstantAttribute.Format.TDate,
): MsoMdocAttribute.InstantAttribute = MsoMdocAttribute.InstantAttribute(this, format)

fun ByteArray.toMsoMdoc(): MsoMdocAttribute.ByteArrayAttribute = MsoMdocAttribute.ByteArrayAttribute(this)

fun Iterable<MsoMdocAttribute<*>>.toMsoMdoc(): MsoMdocAttribute.ListAttribute = toList().toMsoMdoc()

fun List<MsoMdocAttribute<*>>.toMsoMdoc(): MsoMdocAttribute.ListAttribute = MsoMdocAttribute.ListAttribute(this)

fun Map<String, MsoMdocAttribute<*>>.toMsoMdoc(): MsoMdocAttribute.MapAttribute = MsoMdocAttribute.MapAttribute(this)

@MsoMdocDslMarker
class MsoMdocListAttributeBuilder {
    val attributes: List<MsoMdocAttribute<*>>
        field = mutableListOf()

    fun add(value: MsoMdocAttribute<*>) {
        attributes += value
    }

    fun add(value: String) {
        add(MsoMdocAttribute.StringAttribute(value))
    }

    fun add(value: Int) {
        add(MsoMdocAttribute.IntAttribute(value))
    }

    fun add(value: UInt) {
        add(MsoMdocAttribute.UIntAttribute(value))
    }

    fun add(value: Double) {
        add(MsoMdocAttribute.DoubleAttribute(value))
    }

    fun add(value: Float) {
        add(MsoMdocAttribute.FloatAttribute(value))
    }

    fun add(value: Boolean) {
        add(MsoMdocAttribute.BooleanAttribute(value))
    }

    fun add(
        value: LocalDate,
        format: MsoMdocAttribute.LocalDateAttribute.Format = MsoMdocAttribute.LocalDateAttribute.Format.FullDateString,
    ) {
        add(MsoMdocAttribute.LocalDateAttribute(value, format))
    }

    fun add(
        value: Instant,
        format: MsoMdocAttribute.InstantAttribute.Format = MsoMdocAttribute.InstantAttribute.Format.TDate,
    ) {
        add(MsoMdocAttribute.InstantAttribute(value, format))
    }

    fun add(value: ByteArray) {
        add(MsoMdocAttribute.ByteArrayAttribute(value))
    }

    fun addList(builderAction: MsoMdocListAttributeBuilder.() -> Unit) {
        add(buildMsoMdocList(builderAction))
    }

    fun addMap(builderAction: MsoMdocMapAttributeBuilder.() -> Unit) {
        add(buildMsoMdocMap(builderAction))
    }
}

fun buildMsoMdocList(builderAction: MsoMdocListAttributeBuilder.() -> Unit): MsoMdocAttribute.ListAttribute =
    MsoMdocAttribute.ListAttribute(MsoMdocListAttributeBuilder().apply(builderAction).attributes)

@MsoMdocDslMarker
class MsoMdocMapAttributeBuilder {
    val attributes: Map<String, MsoMdocAttribute<*>>
        field = mutableMapOf()

    fun put(
        name: String,
        value: MsoMdocAttribute<*>,
    ) {
        attributes[name] = value
    }

    fun put(
        name: String,
        value: String,
    ) {
        put(name, MsoMdocAttribute.StringAttribute(value))
    }

    fun put(
        name: String,
        value: Int,
    ) {
        put(name, MsoMdocAttribute.IntAttribute(value))
    }

    fun put(
        name: String,
        value: UInt,
    ) {
        put(name, MsoMdocAttribute.UIntAttribute(value))
    }

    fun put(
        name: String,
        value: Double,
    ) {
        put(name, MsoMdocAttribute.DoubleAttribute(value))
    }

    fun put(
        name: String,
        value: Float,
    ) {
        put(name, MsoMdocAttribute.FloatAttribute(value))
    }

    fun put(
        name: String,
        value: Boolean,
    ) {
        put(name, MsoMdocAttribute.BooleanAttribute(value))
    }

    fun put(
        name: String,
        value: LocalDate,
        format: MsoMdocAttribute.LocalDateAttribute.Format = MsoMdocAttribute.LocalDateAttribute.Format.FullDateString,
    ) {
        put(name, MsoMdocAttribute.LocalDateAttribute(value, format))
    }

    fun put(
        name: String,
        value: Instant,
        format: MsoMdocAttribute.InstantAttribute.Format = MsoMdocAttribute.InstantAttribute.Format.TDate,
    ) {
        put(name, MsoMdocAttribute.InstantAttribute(value, format))
    }

    fun put(
        name: String,
        value: ByteArray,
    ) {
        put(name, MsoMdocAttribute.ByteArrayAttribute(value))
    }

    fun putList(
        name: String,
        builderAction: MsoMdocListAttributeBuilder.() -> Unit,
    ) {
        put(name, buildMsoMdocList(builderAction))
    }

    fun putMap(
        name: String,
        builderAction: MsoMdocMapAttributeBuilder.() -> Unit,
    ) {
        put(name, buildMsoMdocMap(builderAction))
    }
}

fun buildMsoMdocMap(builderAction: MsoMdocMapAttributeBuilder.() -> Unit): MsoMdocAttribute.MapAttribute =
    MsoMdocAttribute.MapAttribute(MsoMdocMapAttributeBuilder().apply(builderAction).attributes)
