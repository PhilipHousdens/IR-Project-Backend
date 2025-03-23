import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, streaming_bulk
from fastapi.security import OAuth2PasswordBearer
from database.db import get_db
from model.dbModels import Recipe, User, UserCreate, UserResponse
from utils.passswordHash import hash_password, verify_password  # Assuming these functions are implemented
from utils.JWTToken import verify_token, create_access_token

app = FastAPI()

# Elasticsearch client setup
es = Elasticsearch("https://localhost:9200", basic_auth=("elastic", os.getenv("ES_PASSWORD")), ca_certs="./http_ca.crt")

# CORS configuration to allow frontend to communicate with the backend
origins = [
    "http://localhost:5173",  # Add the URL where your frontend is served
    "https://localhost:9200"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2PasswordBearer to handle token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Define a helper function to check the current user using JWT token
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = verify_token(token)
    if payload is None:
        raise credentials_exception
    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if user is None:
        raise credentials_exception
    return user

# Endpoint to create the recipe index in Elasticsearch
BATCH_SIZE = 5000  # Instead of loading 540,000 into memory


@app.post("/run_indexer")
def run_indexer(db: Session = Depends(get_db)):
    """
    Fetches recipes from PostgreSQL in batches and indexes them into Elasticsearch.
    """
    total_indexed = 0
    try:
        # Pagination loop to fetch data in batches
        offset = 0
        while True:
            recipes = db.query(Recipe).offset(offset).limit(BATCH_SIZE).all()
            if not recipes:
                break  # No more recipes to fetch

            # Prepare actions for bulk indexing
            actions = (
                {
                    "_index": "recipes",
                    "_id": recipe.RecipeId,
                    "_source": {
                        "RecipeId": recipe.RecipeId,
                        "Name": recipe.Name,
                        "Description": recipe.Description,
                        "image_link": recipe.image_link,
                        "Keywords": recipe.Keywords,
                        "RecipeInstructions": recipe.RecipeInstructions,
                    },
                }
                for recipe in recipes
            )

            # Stream the bulk request
            success, failed = 0, 0
            for ok, response in streaming_bulk(es, actions):
                if ok:
                    success += 1
                else:
                    failed += 1
                    print(f"❌ Failed to index document: {response}")  # <-- Add this line

            print(f"✅ Indexed {success} recipes, ❌ Failed {failed}")

            offset += BATCH_SIZE  # Move to the next batch

        return {"message": f"Successfully indexed {total_indexed} recipes."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error indexing data: {str(e)}")

# Endpoint to index recipes from PostgreSQL into Elasticsearch

@app.get("/test")
def test_endpoint():
    return {"message": "Test successful"}

# Endpoint to search recipes in Elasticsearch
@app.get("/recipes/search/")
def search_recipes(query: str = None, page: int = 1, size: int = 10):
    if not query:
        raise HTTPException(status_code=400, detail="No query provided")

    try:
        es_query = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["Name", "Description", "RecipeInstructions"],
                }
            },
            "from": (page - 1) * size,  # Pagination start point
            "size": size
        }

        response = es.search(index="recipes", body=es_query)
        results = [hit['_source'] for hit in response['hits']['hits']]

        return {"page": page, "size": size, "total": response['hits']['total']['value'], "results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/create_index")
def create_recipes_index():
    index_body = {
        "mappings": {
            "properties": {
                "RecipeId": {"type": "integer"},
                "Name": {"type": "text"},
                "Description": {"type": "text"},
                "image_link": {"type": "keyword"},
                "Keywords": {"type": "text"},
                "RecipeInstructions": {"type": "text"}
            }
        }
    }

    try:
        if es.indices.exists(index="recipes"):
            return {"message": "Index already exists"}

        response = es.indices.create(index="recipes", body=index_body)
        if response.get("acknowledged", False):
            return {"message": "Elasticsearch index created successfully"}
        else:
            raise HTTPException(status_code=500, detail="Index creation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating index: {str(e)}")


# Endpoint to get all recipes from
@app.get("/recipes/")
def get_all_recipes(db: Session = Depends(get_db)):
    try:
        recipes = db.query(Recipe).all()
        return recipes
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint to get a recipe by its ID from PostgreSQL
@app.get("/recipes/{recipe_id}")
def read_recipe(recipe_id: int, db: Session = Depends(get_db)):
    try:
        recipe = db.query(Recipe).filter(Recipe.RecipeId == recipe_id).first()
        if recipe is None:
            raise HTTPException(status_code=404, detail="Recipe not found")
        return recipe
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint for user registration
@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash the password and save user
    hashed_password = hash_password(user.password)
    db_user = User(username=user.username, email=user.email, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

class LoginRequest(BaseModel):
    username: str
    password: str

# Endpoint for user login and JWT token generation
@app.post("/login")
def login_for_access_token(form_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create JWT token
    access_token = create_access_token(data={"sub": user.user_id})
    return {"access_token": access_token, "token_type": "bearer"}
