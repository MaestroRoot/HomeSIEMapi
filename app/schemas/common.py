from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class CamelModel(BaseModel):
    """Base ya schemas zote.

    Python inatumia snake_case, frontend (TypeScript) inatumia camelCase.
    `alias_generator=to_camel` inatoa `mfaEnabled`, `createdAt` n.k. kwenye JSON,
    huku `populate_by_name=True` ikiruhusu client kutuma umbo lolote kati ya hayo.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class Message(CamelModel):
    detail: str
    code: str | None = None
