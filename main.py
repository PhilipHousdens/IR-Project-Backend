import os
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, streaming_bulk
from fastapi.security import OAuth2PasswordBearer
from database.db import get_db
from model.dbModels import Recipe, User, UserCreate, UserResponse, Folder, Bookmark, BookmarkResponse, BookmarkRequest
from utils.passswordHash import hash_password, verify_password  # Assuming these functions are implemented
from utils.JWTToken import verify_token, create_access_token
from model.dbModels import FolderCreate, FolderResponse
from utils.FolderCRUD import create_folder, get_folders, delete_folder

app = FastAPI()

# Elasticsearch client setup
es = Elasticsearch("https://localhost:9200", basic_auth=("elastic", os.getenv("ES_PASSWORD")), ca_certs="./http_ca.crt")

# CORS configuration to allow frontend to communicate with the backend
origins = [
    "http://localhost:5173",  # Add the URL where your frontend is served
    "https://localhost:9200",
    "http://localhost:8080"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2PasswordBearer to handle token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Define a helper function to check the current user using JWT token
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    print(f"Received token: {token}")
    print(f"Secret Key being used: {os.getenv('SECRET_KEY')}")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = verify_token(token)
    if payload is None:
        raise credentials_exception
    print(f"Decoded Payload: {payload}")  # add this line.
    user = db.query(User).filter(User.user_id == payload.get("sub")).first()
    print(f"User from Database: {user}")  # add this line
    if user is None:
        raise credentials_exception
    return user


def calculate_average_rating(db: Session, folder_id: int) -> float:
    # Get all bookmarks in the folder
    bookmarks = db.query(Bookmark).filter(Bookmark.folder_id == folder_id).all()

    if not bookmarks:
        return None  # No bookmarks, so average can't be calculated

    # Calculate the average rating
    total_rating = sum(bookmark.rating for bookmark in bookmarks)
    average_rating = total_rating / len(bookmarks)
    return average_rating


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
    access_token = create_access_token(data={"sub": user.user_id, "name": user.username})
    print(f"Access Token: {access_token}")  # Debugging line

    return {"access_token": access_token, "token_type": "bearer"}

# Create a folder
@app.post("/folders/", response_model=FolderResponse)
def create_new_folder(folder: FolderCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return create_folder(db, folder, current_user.user_id)

# Get all folders for a user
@app.get("/folders/", response_model=List[FolderResponse])
def get_user_folders(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return get_folders(db, current_user.user_id)

@app.get("/folders/{folder_id}/", response_model=FolderResponse)
def get_folder_details(
    folder_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    # Retrieve folder and associated bookmarks for a specific folder
    folder = db.query(Folder).filter(Folder.folder_id == folder_id, Folder.user_id == current_user.user_id).first()
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found or you do not have permission to view it")

    return folder

# Delete a folder
@app.delete("/folders/{folder_id}", response_model=FolderResponse)
def delete_user_folder(folder_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    folder = delete_folder(db, folder_id, current_user.user_id)
    if folder is None:
        raise HTTPException(status_code=404, detail="Folder not found")
    return folder


@app.put("/folders/{folder_id}", response_model=FolderResponse)
def update_folder(
        folder_id: int,
        folder: FolderCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
):
    # Check if the folder exists and belongs to the user
    existing_folder = db.query(Folder).filter(Folder.folder_id == folder_id,
                                              Folder.user_id == current_user.user_id).first()
    if not existing_folder:
        raise HTTPException(status_code=404, detail="Folder not found or you do not have permission to edit it")

    # Update folder details
    existing_folder.folder_name = folder.folder_name
    existing_folder.description = folder.description
    db.commit()
    db.refresh(existing_folder)
    return existing_folder

# Bookmark
@app.post("/bookmarks/", response_model=BookmarkResponse)
def bookmark_recipe(
    bookmark_data: BookmarkRequest,  # This will be passed as a JSON body
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Extract data from the request body
    recipe_id = bookmark_data.recipe_id
    folder_id = bookmark_data.folder_id
    rating = bookmark_data.rating

    if rating < 1 or rating > 5:
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")

    # Check if the folder exists and belongs to the user
    folder = db.query(Folder).filter(Folder.folder_id == folder_id, Folder.user_id == current_user.user_id).first()
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found or you do not have permission to use this folder")

    # Check if the recipe exists
    recipe = db.query(Recipe).filter(Recipe.RecipeId == recipe_id).first()
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")

    # Create bookmark
    bookmark = Bookmark(user_id=current_user.user_id, recipe_id=recipe.RecipeId, rating=rating, folder_id=folder_id)
    db.add(bookmark)
    db.commit()
    db.refresh(bookmark)

    # Recalculate the average rating for the folder
    average_rating = calculate_average_rating(db, folder_id)

    # Update the folder's average rating
    folder.average_rating = average_rating
    db.commit()
    db.refresh(folder)

    return bookmark


@app.get("/bookmarks/", response_model=List[BookmarkResponse])
def get_all_bookmarks(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Retrieve all bookmarks for the authenticated user.
    """
    bookmarks = db.query(Bookmark).filter(Bookmark.user_id == current_user.user_id).all()
    return bookmarks

@app.delete("/bookmarks/{bookmark_id}", response_model=BookmarkResponse)
def delete_bookmark(bookmark_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Retrieve the bookmark to delete
    bookmark = db.query(Bookmark).filter(Bookmark.bookmark_id == bookmark_id, Bookmark.user_id == current_user.user_id).first()
    if not bookmark:
        raise HTTPException(status_code=404, detail="Bookmark not found")

    # Get the folder id from the bookmark
    folder_id = bookmark.folder_id

    # Delete the bookmark
    db.delete(bookmark)
    db.commit()

    # Recalculate the average rating for the folder
    average_rating = calculate_average_rating(db, folder_id)

    # Update the folder's average rating
    folder = db.query(Folder).filter(Folder.folder_id == folder_id).first()
    if folder:
        folder.average_rating = average_rating
        db.commit()

    return bookmark

@app.delete("/bookmarks/", response_model=BookmarkResponse)
def delete_bookmark(bookmark_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Retrieve the bookmark to delete
    bookmark = db.query(Bookmark)
    if not bookmark:
        raise HTTPException(status_code=404, detail="Bookmark not found")
    return bookmark



@app.get("/folders/{folder_id}/bookmarks/", response_model=List[BookmarkResponse])
def get_bookmarks_for_folder(
    folder_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    folder = db.query(Folder).filter(Folder.folder_id == folder_id, Folder.user_id == current_user.user_id).first()
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found or you do not have permission to view bookmarks")

    # Fetch bookmarks in the folder
    bookmarks = db.query(Bookmark).filter(Bookmark.folder_id == folder_id).all()
    return bookmarks