"""Small stdlib-only validator for the JSON Schema keywords used in schemas/."""


_TYPE_CHECKS = {
    "object": lambda value: isinstance(value, dict),
    "array": lambda value: isinstance(value, list),
    "string": lambda value: isinstance(value, str),
    "integer": lambda value: type(value) is int,
    "number": lambda value: type(value) in (int, float),
    "boolean": lambda value: type(value) is bool,
    "null": lambda value: value is None,
}


def validate(instance, schema, path="$"):
    """Return validation errors for type/required/properties/enum/items/additionalProperties/minItems."""
    errors = []
    expected = schema.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        if not any(_TYPE_CHECKS[name](instance) for name in expected_types):
            return ["{}: expected {}, got {}".format(path, " or ".join(expected_types), type(instance).__name__)]

    if "enum" in schema and instance not in schema["enum"]:
        errors.append("{}: value {!r} is not in enum".format(path, instance))

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append("{}: missing required property {!r}".format(path, key))
        properties = schema.get("properties", {})
        for key, child_schema in properties.items():
            if key in instance:
                errors.extend(validate(instance[key], child_schema, "{}.{}".format(path, key)))
        if schema.get("additionalProperties") is False:
            extras = set(instance) - set(properties)
            for key in sorted(extras):
                errors.append("{}.{}: additional property is not allowed".format(path, key))

    if isinstance(instance, list):
        minimum = schema.get("minItems")
        if minimum is not None and len(instance) < minimum:
            errors.append("{}: expected at least {} items".format(path, minimum))
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                errors.extend(validate(item, item_schema, "{}[{}]".format(path, index)))
    return errors
