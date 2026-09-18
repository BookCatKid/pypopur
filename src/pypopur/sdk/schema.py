"""Device schema model — ports of ``SchemaBean`` and the per-type property
beans populated by ``SchemaMapper.to*Schema`` (fastjson ``parseObject``).

smali sources:
- smali_classes3/com/thingclips/smart/android/device/bean/SchemaBean.smali
- .../bean/{Bool,Enum,String,Value,Bitmap}SchemaBean.smali
- smali_classes3/com/thingclips/smart/home/sdk/utils/SchemaMapper.smali

``SchemaBean.property`` is the raw JSON string from the product schema; the
per-type mappers parse it lazily at validation time — and a malformed
property makes validation fail (the exception propagates into the caller's
catch-all).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# DataTypeEnum.getType()
DATA_TYPE_OBJ = "obj"
DATA_TYPE_RAW = "raw"

# ModeEnum.getType()
MODE_RW = "rw"
MODE_WR = "wr"
MODE_RO = "ro"


@dataclass
class SchemaBean:
    """``com.thingclips.smart.android.device.bean.SchemaBean``.

    ``schema_type`` and ``ext_content`` default to ``""`` in the Java ctor;
    every other field defaults to null.
    """

    code: str | None = None
    ext_content: str = ""
    iconname: str | None = None
    id: str | None = None
    mode: str | None = None
    name: str | None = None
    passive: bool | None = None
    property: str | None = None  # raw JSON string
    schema_type: str = ""
    type: str | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> SchemaBean:
        """fastjson-style field binding: camelCase keys, missing → defaults."""

        return cls(
            code=obj.get("code"),
            ext_content=obj.get("extContent", "") or "",
            iconname=obj.get("iconname"),
            id=obj.get("id"),
            mode=obj.get("mode"),
            name=obj.get("name"),
            passive=obj.get("passive"),
            property=obj.get("property"),
            schema_type=obj.get("schemaType", "") or "",
            type=obj.get("type"),
        )


@dataclass
class BoolSchemaBean:
    pass


@dataclass
class EnumSchemaBean:
    """``range`` is a ``java.util.Set`` — ``None`` when the property JSON lacks
    it (which fails enum validation)."""

    range: set[str] | None = None


@dataclass
class StringSchemaBean:
    maxlen: int = 0


@dataclass
class ValueSchemaBean:
    max: int = 0
    min: int = 0
    scale: int = 0
    step: int = 0
    unit: str | None = None


@dataclass
class BitmapSchemaBean:
    label: list[str] | None = None
    maxlen: int = 0


@dataclass
class ArraySchemaBean:
    """``ArraySchemaBean`` — ``elementTypeSpec`` is the raw spec object
    (a JSONObject at runtime), ``maxSize`` the declared bound."""

    type: str = "array"
    element_type_spec: Any = None
    max_size: int = 0


@dataclass
class StructPropertyBean:
    """``StructPropertyBean`` — one struct field; ``type_spec`` is the raw
    spec object (a JSONObject at runtime)."""

    name: str | None = None
    type_spec: Any = None


@dataclass
class StructSchemaBean:
    """``StructSchemaBean`` — ``properties`` maps field name →
    ``StructPropertyBean``."""

    type: str = "struct"
    properties: dict[str, StructPropertyBean] | None = None


def _parse_property(prop: str | None) -> dict[str, Any] | None:
    """fastjson ``parseObject(String)`` — null/empty input returns null like
    fastjson; malformed JSON raises (the validators' catch-all then fails the
    command). A non-object JSON value yields ``None`` fields downstream."""

    if prop is None or prop == "":
        return None
    parsed = json.loads(prop)
    if parsed is None:
        return None
    if not isinstance(parsed, dict):
        # fastjson parseObject(non-object, Bean.class) throws JSONException.
        raise ValueError(f"property JSON is not an object: {prop!r}")  # noqa: TRY004 - JSONException maps to ValueError
    return parsed


def to_enum_schema(prop: str | None) -> EnumSchemaBean | None:
    """``SchemaMapper.toEnumSchema`` — null property → null bean."""

    obj = _parse_property(prop)
    if obj is None:
        return None
    rng = obj.get("range")
    return EnumSchemaBean(range=set(rng) if rng is not None else None)


def to_string_schema(prop: str | None) -> StringSchemaBean | None:
    """``SchemaMapper.toStringSchema`` — null property → null bean."""

    obj = _parse_property(prop)
    if obj is None:
        return None
    return StringSchemaBean(maxlen=int(obj.get("maxlen") or 0))


def to_value_schema(prop: str | None) -> ValueSchemaBean | None:
    """``SchemaMapper.toValueSchema`` — null property → null bean."""

    obj = _parse_property(prop)
    if obj is None:
        return None
    return ValueSchemaBean(
        max=int(obj.get("max") or 0),
        min=int(obj.get("min") or 0),
        scale=int(obj.get("scale") or 0),
        step=int(obj.get("step") or 0),
        unit=obj.get("unit"),
    )


def to_bitmap_schema(prop: str | None) -> BitmapSchemaBean | None:
    """``SchemaMapper.toBitmapSchema`` — null property → null bean."""

    obj = _parse_property(prop)
    if obj is None:
        return None
    label = obj.get("label")
    return BitmapSchemaBean(
        label=list(label) if label is not None else None,
        maxlen=int(obj.get("maxlen") or 0),
    )


def to_array_schema(prop: str | None) -> ArraySchemaBean | None:
    """``SchemaMapper.toArraySchema`` — fastjson ``parseObject``; the
    ``elementTypeSpec`` field arrives as a nested JSONObject."""

    obj = _parse_property(prop)
    if obj is None:
        return None
    return ArraySchemaBean(
        element_type_spec=obj.get("elementTypeSpec"),
        max_size=int(obj.get("maxSize") or 0),
    )


def to_struct_schema(prop: str | None) -> StructSchemaBean | None:
    """``SchemaMapper.toStructSchema`` — ``properties`` is a
    ``Map<String, StructPropertyBean>`` (fastjson deserializes each value's
    ``typeSpec`` as a JSONObject)."""

    obj = _parse_property(prop)
    if obj is None:
        return None
    raw_props = obj.get("properties")
    props: dict[str, StructPropertyBean] | None = None
    if raw_props is not None:
        props = {
            k: StructPropertyBean(
                name=(v or {}).get("name") if isinstance(v, dict) else None,
                type_spec=(v or {}).get("typeSpec") if isinstance(v, dict) else None,
            )
            for k, v in raw_props.items()
        }
    return StructSchemaBean(properties=props)
