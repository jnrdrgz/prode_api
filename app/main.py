from typing import List

from fastapi import Depends, Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse
from fastapi.encoders import jsonable_encoder

from . import models, schemas, security, deps
from .database import SessionLocal, engine
from datetime import date, timedelta

from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

origins = [
    "http://localhost:3074",
    "http://192.168.1.23:3074",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#################UTILS
def ErrorResponse(error_str, message=""):
    return {"error": error_str, "message": message}

#################END_UTILS

# Dependency
def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


@app.get("/api/test")
async def root():
    return {"message": "Hello World"}

#@app.post("/api/test/post")
#async def create_item(record: schemas.Record):
#    return record


##import datetime
#datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=3)

@app.get("/api/table")
def get_table():
    a = {"test": "test"}
    if True:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    return a


@app.post("/api/register", )#response_model=schemas.User
def register(*, db: Session = Depends(get_db), password: str = Body(...), username: str = Body(...), full_name: str = Body(...),):
    """
    Create new user without the need to be logged in.
    """
    #if not settings.USERS_OPEN_REGISTRATION:
    #    raise HTTPException(
    #        status_code=403,
    #        detail="Open user registration is forbidden on this server",
    #    )
    user = db.query(models.User).filter(models.User.username == username).first()
    if user:
        return ErrorResponse("Ya hay un usuario con el mismo nombre.")
        #raise HTTPException(
        #    status_code=400,
        #    detail="The user with this username already exists in the system",
        #)
    user_in = schemas.UserCreate(password=password,username=username,full_name=full_name,)
    if username == "juan":
        user_in.is_admin = True

    db_obj = models.User(
        username=user_in.username,
        hashed_password=security.get_password_hash(user_in.password),
        full_name=user_in.full_name,
        is_superuser=user_in.is_superuser,
        is_admin=user_in.is_admin,
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)    

    return db_obj

@app.post("/api/login/access-token") #, response_model=schemas.Token
def login_access_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    print(form_data)
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    #user = crud.user.authenticate(db, email=form_data.username, password=form_data.password)
    #user = self.get_by_email(db, email=email)
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user:
        return ErrorResponse("Usuario inexistente")
    if not security.verify_password(form_data.password, user.hashed_password):
        return ErrorResponse("Nombre de usuario o contraseña equivocada")
    #return user

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    access_token_expires = timedelta(minutes=60*24*60)
    print(user.id, access_token_expires)
    return {
        "access_token": security.create_access_token(f'{user.id}-{user.username}', expires_delta=access_token_expires),
        "token_type": "bearer",
        "user": {
            "id": user.id, 
            "username": user.username, 
            "full_name": user.full_name,
            "is_superuser": user.is_superuser,
            "is_active": user.is_active,
            "is_admin": user.is_admin,        
        },
    }

#def get_unique_team(db, user_id):
#    return db.query(models.UserUniqueTeam).filter(models.UserUniqueTeam.owner_id == user_id).first().id

@app.post("/api/login/test-token", )#response_model=schemas.User
def test_token(db: Session = Depends(get_db),current_user: models.User = Depends(deps.get_current_user)):
    """
    Test access token
    """
    if not current_user:
        return ErrorResponse("Forbidden")

    obj = {
        "id": current_user.id,
        "is_superuser": current_user.is_superuser,
        "is_active": current_user.is_active,
        "full_name": current_user.full_name,
        "username":  current_user.username,
        "is_admin": current_user.is_admin,
    }

    #print("asdf", )
    ##user_unique_team_id = db.query(models.UserUniqueTeam).filter(models.UserUniqueTeam.owner_id == current_user.id).first().id
    ##print("user_unique_id", user_unique_team_id)
    return schemas.User(**obj)

###########################################
##############init utils###################
###########################################

def user_is_in_tournament(db, user_id, tournament_id):
    user_in_tournament = db.query(models.TournamentsUsers).filter(models.TournamentsUsers.user_id == user_id).filter(models.TournamentsUsers.tournament_id == tournament_id).first()

    if user_in_tournament:
        return True

    return False

def add_matches_bulk_special():
    a = '''Plzen - Inter
    Sporting - Tottenham
    Bayer Leverkusen - Atl. Madrid
    Bayern Munich - Barcelona
    Porto - Club Brugge KV
    Liverpool - Ajax
    Marseille - Eintracht Frankfurt
    AC Milan - Dinamo Zagreb
    Shakhtar Donetsk - Celtic
    Chelsea - Salzburg
    FC Copenhagen - Sevilla
    Juventus - Benfica
    Maccabi Haifa - Paris SG
    Manchester City - Dortmund
    Rangers - Napoli
    Real Madrid - RB Leipzig'''
    b=[(x.split("-")[0].strip(), x.split("-")[1].strip()) for x in a.split("\n")]
    c={"matches": [{"description": f"{x[0]}-{x[1]}","game_week_id": 1} for x in b]}
    return c 

def add_matches_bulk_str(matches_str, game_week_id):
    a = matches_str
    b=[(x.split("-")[0].strip(), x.split("-")[1].strip()) for x in a.split("\n")]
    c={"matches": [{"description": f"{x[0]}-{x[1]}","game_week_id": game_week_id} for x in b]}
    return c 


def change_current_current(db, tournament_id):
    game_week = db.query(models.GameWeek).filter_by(current=True).filter_by(tournament_id=tournament_id).first()
    if game_week:
        game_week.current = False
        db.commit()

def change_game_week_status(db, game_week_id, status, current):
    game_week = db.query(models.GameWeek).filter_by(id=game_week_id).first()
    if game_week:
        game_week.status = status
        game_week.current = current
        db.commit()

def add_prediction(db, match_id, score, user_id):
    db_obj = models.Prediction(
        match_id=match_id,
        score=score,
        user_id=user_id,
    )
    
    return add_to_db(db, db_obj)
        
def get_points(pscore, mscore):
    pscore_h = int(pscore.split("-")[0])
    pscore_a = int(pscore.split("-")[1])
    mscore_h = int(mscore.split("-")[0])
    mscore_a = int(mscore.split("-")[1])

    if pscore == mscore:
        return {"puntos": 3, "plenos": 1, "goles": pscore_h+pscore_a}

    if pscore_h == pscore_a and mscore_h == mscore_a:
        return {"puntos": 1, "plenos": 0, "goles": 0}

    if pscore_h > pscore_a and mscore_h > mscore_a:
        return {"puntos": 1, "plenos": 0, "goles": 0}

    if pscore_h < pscore_a and mscore_h < mscore_a:
        return {"puntos": 1, "plenos": 0, "goles": 0}

    return {"puntos": 0, "plenos": 0, "goles": 0}

def get_description_short(description):
    equipos = description.split("-")
    return f'{equipos[0][:3].upper()}-{equipos[1][:3].upper()}'

###########################################
##############end utils###################
###########################################

@app.get("/api/tournaments")
def get_tournamets(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user)):

    if not current_user:
        return ErrorResponse("Forbidden")

    tournaments = db.query(models.Tournament).all()

    if current_user.is_admin:
        return tournaments

    tournaments_users = db.query(models.TournamentsUsers).filter(models.TournamentsUsers.user_id == current_user.id).all()
    user_tournaments = [t for t in tournaments if t.id in [x.tournament_id for x in tournaments_users]]

    return user_tournaments

def add_to_db(db, db_obj):
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)    

    return db_obj

def add_match(db, description, game_week_id):
    db_obj = models.Match(
        description=description,
        game_week_id=game_week_id,
    )
    
    return add_to_db(db, db_obj)

@app.post("/api/tournaments")
def post_tournamet(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not current_user.is_admin:
        return ErrorResponse("Forbidden")

    tournament_in = schemas.TournamentCreate(name=body["name"])
    
    db_obj = models.Tournament(
        name=tournament_in.name,
        status="not_started",
    )

    return add_to_db(db, db_obj)


@app.get("/api/tournaments/{tournament_id}/game_weeks", )
def get_tournament_game_weeks(tournament_id, db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not user_is_in_tournament(db, current_user.id, tournament_id) and not current_user.is_admin:
        return ErrorResponse("Forbidden")

    game_weeks = db.query(models.GameWeek).filter(models.GameWeek.tournament_id == tournament_id).all()

    return game_weeks


@app.get("/api/tournaments/{tournament_id}/game_weeks/{game_week_id}", )
def get_tournament_game_week_data(tournament_id, game_week_id, db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not user_is_in_tournament(db, current_user.id, tournament_id) and not current_user.is_admin:
        return ErrorResponse("Forbidden")

    game_week = db.query(models.GameWeek).filter(models.GameWeek.tournament_id == tournament_id).filter(models.GameWeek.id == game_week_id).first()

    if not game_week:
        return {"game_week": None, "matches": None, "predictions": None}

    #if game_week.status ==

    matches = db.query(models.Match).filter(models.Match.game_week_id == game_week.id).all()
    predictions = []
    for match in matches:
        predictions.append(db.query(models.Prediction).filter(models.Prediction.match_id == match.id).filter(models.Prediction.user_id == current_user.id).first())
        predictions = [x for x in predictions if x]
    #if predictions[0] == None:
    #    predictions = None

    return {"game_week": game_week, "matches": matches, "predictions": predictions}

@app.get("/api/tournaments/{tournament_id}/current_game_week", )
def get_tournament_current_game_week(tournament_id, db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not user_is_in_tournament(db, current_user.id, tournament_id) and not current_user.is_admin:
        return ErrorResponse("Forbidden")

    game_week = db.query(models.GameWeek).filter(models.GameWeek.tournament_id == tournament_id).filter(models.GameWeek.current == True).first()

    if not game_week:
        return {"game_week": None, "matches": None, "predictions": None}

    #if game_week.status ==

    matches = db.query(models.Match).filter(models.Match.game_week_id == game_week.id).all()
    predictions = []
    for match in matches:
        predictions.append(db.query(models.Prediction).filter(models.Prediction.match_id == match.id).filter(models.Prediction.user_id == current_user.id).first())
        predictions = [x for x in predictions if x]
    #if predictions[0] == None:
    #    predictions = None

    return {"game_week": game_week, "matches": matches, "predictions": predictions}


@app.post("/api/game_week")
def post_tournamet(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not current_user.is_admin:        
        return ErrorResponse("Forbidden")

    #if not current_user.is_admin:
    #    return ErrorResponse("only admins can add game weeks")

    if not "tournament_id" in body.keys():
        return ErrorResponse("no tournament id specified")

    game_week_in = schemas.GameWeekCreate(name=body["name"], )
    
    db_obj = models.GameWeek(
        name=game_week_in.name,
        tournament_id=body["tournament_id"],
        status="not_started",
        current=False,
    )
    
    return add_to_db(db, db_obj)
    
@app.post("/api/matches")
def post_matches(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not current_user.is_admin:        
        return ErrorResponse("Forbidden")

    #if not current_user.is_admin:
    #    return ErrorResponse("only admins can add game weeks")

    if not "game_week_id" in body.keys():
        return ErrorResponse("no game week id specified")
    
    db_obj = models.Match(
        description=body["description"],
        game_week_id=body["game_week_id"],
    )
    
    return add_to_db(db, db_obj)

@app.patch("/api/game_week/status")
def patch_game_week_status(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not current_user.is_admin:        
        return ErrorResponse("Forbidden")

    try:
        change_game_week_status(db, body["game_week_id"], body["status"], body["current"])
        return {"data": "ok"}
    except Exception as inst:
        return ErrorResponse("Server error",  f"server error: {type(inst)} {inst}")


@app.post("/api/matches/bulk_str")
def post_matches_bulk_str(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not current_user.is_admin:        
        return ErrorResponse("Forbidden")

    #if not current_user.is_admin:
    #    return ErrorResponse("only admins can add game weeks")

    ##add game week
    try:
        game_week_in = schemas.GameWeekCreate(name=body["game_week_name"], )
        
        is_current = False
        if body["is_current"]:
            is_current = True
            change_current_current(db, body["tournament_id"])

        db_obj = models.GameWeek(
            name=game_week_in.name,
            tournament_id=body["tournament_id"],
            status="not_started",
            current=is_current,
        )
        
        gmweek = add_to_db(db, db_obj)

        matches = add_matches_bulk_str(body["matches"], gmweek.id)
        print("MATCHES", matches)
        matches_list = []
        for match in matches["matches"]:
            print("MATCH", match)
            match = add_match(db, match["description"], match["game_week_id"])
            matches_list.append(match.id)

        #make query with id array to get the matches
        return {"matches": matches_list}
    except Exception as inst:
        return ErrorResponse("Server error",  f"server error: {type(inst)} {inst}")

@app.post("/api/matches/bulk")
def post_matches_bulk(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not current_user.is_admin:        
        return ErrorResponse("Forbidden")

    #if not current_user.is_admin:
    #    return ErrorResponse("only admins can add game weeks")
    try:
        matches = []
        for match in body["matches"]:
            match = add_match(db, match["description"], match["game_week_id"])
            matches.append(match.id)

        #make query with id array to get the matches
        return {"matches": matches}
    except Exception as inst:
         return ErrorResponse("Server error",  f"server error: {type(inst)} {inst}")

@app.post("/api/predictions/bulk")
def post_predictions_bulk(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not "predictions" in body.keys():
        return ErrorResponse("no predictions id specified")

    #FIXME: check if user does not have predictions in every match

    predictions = []
    for prediction in body["predictions"]:
        add_prediction(db, prediction["match_id"], prediction["score"], current_user.id)
        #match = add_match(db, match["description"], match["game_week_id"])
        #matches.append(match.id)

    #make query with id array to get the matches
    return {"predictions": predictions}

@app.patch("/api/matches/scores/bulk")
def patch_matches_bulk(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not current_user.is_admin:        
        return ErrorResponse("Forbidden")

    try:
        if not "scores" in body.keys():
            return ErrorResponse("no scores id specified")

        matches = []
        for score in body["scores"]:
            match = db.query(models.Match).filter_by(id=score["match_id"]).first()
            if match:
                match.score = score["score"]
                db.commit()
                matches.append(match)

        return {"matches": matches}
    except Exception as inst:
        return ErrorResponse("Server error",  f"server error: {type(inst)} {inst}")

@app.get("/api/tournaments/{tournament_id}/standings", )
def get_tournament_standings(tournament_id, db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not user_is_in_tournament(db, current_user.id, tournament_id) and not current_user.is_admin:
        return ErrorResponse("Forbidden")

    #get tournament participantes
    participantes = db.query(models.TournamentsUsers).filter(models.TournamentsUsers.tournament_id == tournament_id).all()
    game_weeks = db.query(models.GameWeek).filter(models.GameWeek.tournament_id == tournament_id).all()
    game_weeks_ids = [x.id for x in game_weeks]

    table_data = []

    for participante in participantes:
        predictions = db.query(models.Prediction).filter(models.Prediction.user_id == participante.user_id).all()
        points = 0
        plenos = 0
        goles = 0
        for prediction in predictions:
            match = db.query(models.Match).filter(models.Match.id == prediction.match_id).first()
            if match.score and (match.game_week_id in game_weeks_ids):
                #print(prediction.score, match.score, get_points(prediction.score, match.score))
                points_dict = get_points(prediction.score, match.score)
                points += points_dict["puntos"]
                plenos += points_dict["plenos"]
                goles += points_dict["goles"]

        #print(participante.user_id, points)

        table_data.append({
            "participante": db.query(models.User).filter(models.User.id == participante.user_id).first().full_name,
            "puntos": points,
            "plenos": plenos,
            "goles": goles,
        })


    table_data = sorted(table_data, key=lambda x : (x["puntos"], x["plenos"], x["goles"]), reverse=True)

    return {"standings": table_data}

@app.get("/api/tournaments/{tournament_id}/standings/{game_week_id}", )
def get_tournament_standings(tournament_id, game_week_id, db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not user_is_in_tournament(db, current_user.id, tournament_id) and not current_user.is_admin:
        return ErrorResponse("Forbidden")

    #get tournament participantes
    participantes = db.query(models.TournamentsUsers).filter(models.TournamentsUsers.tournament_id == tournament_id).all()
    #print("asfasdsd", len(participantes))
    game_weeks = db.query(models.GameWeek).filter(models.GameWeek.tournament_id == tournament_id).all()
  
    table_data = []

    all_predictions = []

    for participante in participantes:


        predictions = db.query(models.Prediction).filter(models.Prediction.user_id == participante.user_id).all()
        predictions__ = db.query(models.Prediction).filter(models.Prediction.user_id == 1031).all()

        points = 0
        plenos = 0
        goles = 0

        participante_name = db.query(models.User).filter(models.User.id == participante.user_id).first().full_name,
        user_predictions = {}
        for prediction in predictions:
            match = db.query(models.Match).filter(models.Match.id == prediction.match_id).first()
            if int(match.game_week_id) == int(game_week_id):
                user_predictions[get_description_short(match.description)] = prediction.score
                print("PREDICTIONS", prediction.id, " - ", prediction.score)
                if match.score:
                    #print(prediction.score, match.score, get_points(prediction.score, match.score))
                    points_dict = get_points(prediction.score, match.score)
                    points += points_dict["puntos"]
                    plenos += points_dict["plenos"]
                    goles += points_dict["goles"]

        all_predictions.append({"participante": participante_name, "predictions": user_predictions})
        #print(participante.user_id, points)

        table_data.append({
            "participante": participante_name,
            "puntos": points,
            "plenos": plenos,
            "goles": goles,
        })

    table_data = sorted(table_data, key=lambda x : (x["puntos"], x["plenos"], x["goles"]), reverse=True)
    matches = [{"short": get_description_short(x.description), "score": x.score} for x in db.query(models.Match).filter(models.Match.game_week_id == game_week_id).all()]

    return {"standings": table_data, "predictions": all_predictions, "matches": matches, "game_weeks": game_weeks}


@app.post("/api/add_user_to_tournament")
def add_user_to_tournament(db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user), body = Body(...)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not current_user.is_admin:        
        return ErrorResponse("Forbidden")

    #if not current_user.is_admin:
    #    return ErrorResponse("only admins can add game weeks")
    try:
        if not "user_id" in body.keys():
            return ErrorResponse("no user id specified")
        if not "tournament_id" in body.keys():
            return ErrorResponse("no tournament_id id specified")
        
        db_obj = models.TournamentsUsers(
            tournament_id=body["tournament_id"],
            user_id=body["user_id"],
        )
        
        return add_to_db(db, db_obj)
    except Exception as inst:
        return ErrorResponse("Server error",  f"server error: {type(inst)} {inst}")

@app.get("/api/{tournament_id}/users", )
def get_users(tournament_id, db: Session = Depends(get_db), current_user: models.User = Depends(deps.get_current_user)):
    if not current_user:
        return ErrorResponse("Forbidden")

    if not user_is_in_tournament(db, current_user.id, tournament_id) and not current_user.is_admin:
        return ErrorResponse("Forbidden")

    try:
        users = db.query(models.User).all()
        tusers = []
        for user in users:
            del user.hashed_password
            del user.is_admin
            del user.is_superuser
            u = db.query(models.TournamentsUsers).filter(models.TournamentsUsers.user_id == user.id).filter(models.TournamentsUsers.tournament_id == tournament_id).first()
            if u:
                tusers.append(user)

        return {"users": users, "tournament_users": tusers}
    except Exception as inst:
        return ErrorResponse("Server error",  f"server error: {type(inst)} {inst}")


#app.mount("/", StaticFiles(directory="webapp", html=True), name="webapp")

#try:
#except Exception as inst:
#return ErrorResponse("Server error",  f"server error: {type(inst)} {inst}")