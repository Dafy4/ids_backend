from pydantic import BaseModel

class NetworkRequest(BaseModel):
    duration : float
    protocol_type : str
    service: str
    flag: str
    src_bytes: int
    dst_bytes: int