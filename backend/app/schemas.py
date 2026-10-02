from pydantic import BaseModel

class LogResponse(BaseModel):

    id: int

    filename: str

    log_type: str

    class Config:
        from_attributes = True