from datetime import date
from pydantic import BaseModel
from typing import Optional, Any

##############auth################

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenPayload(BaseModel):
    sub: Optional[str] = None

# Shared properties
class UserBase(BaseModel):
    username: Optional[str] = None
    is_active: Optional[bool] = True
    is_superuser: bool = False
    is_admin: bool = False
    full_name: Optional[str] = None
    has_team: Optional[bool] = None
    
# Properties to receive via API on creation
class UserCreate(UserBase):
    username: str
    password: str


# Properties to receive via API on update
class UserUpdate(UserBase):
    password: Optional[str] = None


class UserInDBBase(UserBase):
    id: Optional[int] = None

    class Config:
        orm_mode = True


# Additional properties to return via API
class User(UserInDBBase):
    pass


# Additional properties stored in DB
class UserInDB(UserInDBBase):
    hashed_password: str

##############auth################

###########TOURNAMENT#############
class TournamentBase(BaseModel):   
    name: str
    status: Optional[str] = "not_started"

# Properties to receive on item creation
class TournamentCreate(TournamentBase):
    name: str
    status: Optional[str] = "not_started"
    
# Properties to receive on item update
class TournamentUpdate(TournamentBase):
    pass

# Properties shared by models stored in DB
class TournamentInDBBase(TournamentBase):
    id: int
    name: str
    is_active: bool
    status: str

    class Config:
        orm_mode = True

# Properties to return to client
class Tournament(TournamentInDBBase):
    pass

# Properties properties stored in DB
class TournamentInDB(TournamentInDBBase):
    pass

###########GAMEWEEK#############
class GameWeekBase(BaseModel):   
    name: str
    status: Optional[str] = "not_started"
    current: Optional[bool] = False

# Properties to receive on item creation
class GameWeekCreate(GameWeekBase):
    name: str
    status: Optional[str] = "not_started"
    current: Optional[bool] = False

# Properties to receive on item update
class GameWeekUpdate(GameWeekBase):
    pass

# Properties shared by models stored in DB
class GameWeekInDBBase(GameWeekBase):
    id: int
    name: str
    is_active: bool
    current: bool
    status: str
    tournament_id: int

    class Config:
        orm_mode = True

# Properties to return to client
class GameWeek(GameWeekInDBBase):
    pass

# Properties properties stored in DB
class GameWeekInDB(GameWeekInDBBase):
    pass

###########MATCHES#############
class MatchBase(BaseModel):   
    description: str
    score: Optional[str] = "not_started"

# Properties to receive on item creation
class MatchCreate(MatchBase):
    description: str
    score: Optional[str] = "not_started"

# Properties to receive on item update
class MatchUpdate(MatchBase):
    pass

# Properties shared by models stored in DB
class MatchInDBBase(MatchBase):
    id: int
    description: str
    is_active: bool
    score: str
    game_week_id: int

    class Config:
        orm_mode = True

# Properties to return to client
class Match(MatchInDBBase):
    pass

# Properties properties stored in DB
class MatchInDB(MatchInDBBase):
    pass

###########PREDICTIONS#############
class PredictionBase(BaseModel):
    score: str
    match_id: int
    user_id: int

# Properties to receive on item creation
class PredictionCreate(PredictionBase):
    score: str
    match_id: int
    user_id: int

# Properties to receive on item update
class PredictionUpdate(PredictionBase):
    pass

# Properties shared by models stored in DB
class PredictionInDBBase(PredictionBase):
    id: int
    score: str
    match_id: int
    user_id: int

    class Config:
        orm_mode = True

# Properties to return to client
class Prediction(PredictionInDBBase):
    pass

# Properties properties stored in DB
class PredictionInDB(PredictionInDBBase):
    pass