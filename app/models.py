from sqlalchemy import Boolean, Column, Integer, ForeignKey, String, Table
from sqlalchemy.orm import relationship
from sqlalchemy.types import Date, DateTime
from .database import Base
import datetime

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean(), default=True)
    is_superuser = Column(Boolean(), default=False)
    is_admin = Column(Boolean(), default=False)
    predictions = relationship("Prediction", back_populates="user")
    created_at = Column(DateTime, default=datetime.datetime.now)

class Tournament(Base):
    __tablename__ = 'tournaments'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, nullable=False)
    is_active = Column(Boolean(), default=True)
    game_weeks = relationship("GameWeek", back_populates="tournament")
    created_at = Column(DateTime, default=datetime.datetime.now)

class TournamentsUsers(Base):
    __tablename__ = 'tournaments__users'
    id = Column(Integer, primary_key=True, index=True)
    tournament_id = Column(Integer, ForeignKey("tournaments.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.datetime.now)


class GameWeek(Base):
    __tablename__ = 'game_weeks'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    is_active = Column(Boolean(), default=True)
    matches = relationship("Match", back_populates="game_week")
    status = Column(String, nullable=False)
    current = Column(Boolean(), default=True)

    tournament_id = Column(Integer, ForeignKey("tournaments.id"))
    tournament = relationship("Tournament", back_populates="game_weeks")
    init_time = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now)

class Match(Base):
    __tablename__ = 'matches'
    id = Column(Integer, primary_key=True, index=True)
    description = Column(String, nullable=False)
    score = Column(String)
    is_active = Column(Boolean(), default=True)
    game_week_id = Column(Integer, ForeignKey("game_weeks.id"))
    game_week = relationship("GameWeek", back_populates="matches")
    predictions = relationship("Prediction", back_populates="match")
    created_at = Column(DateTime, default=datetime.datetime.now)

class Prediction(Base):
    __tablename__ = 'predictions'
    id = Column(Integer, primary_key=True, index=True)
    score = Column(String)
    #matchid
    #userid
    match_id = Column(Integer, ForeignKey("matches.id"))
    match = relationship("Match", back_populates="predictions")

    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="predictions")
    created_at = Column(DateTime, default=datetime.datetime.now)

'''
user
    name

tournament
    name
    enabled

tournament_user
    tournament_id
    user_id

gameweek
    name
    current? or in config
    enabled

match
    description
    gameweek_id
    tournament_id
    enabled
    score

prediction
    match_id
    user_id
    score ! check name
'''