from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Date, Boolean, DateTime
from sqlalchemy.dialects.mysql import NUMERIC
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class Recipe(Base):
    __tablename__ = 'recipes'
    __table_args__ = {'schema': 'recipes_tb'}
    
    RecipeId = Column(Integer, primary_key=True, index=True)
    Name = Column(String)
    AuthorId = Column(Integer)
    CookTime = Column(String)
    PrepTime = Column(String)
    TotalTime = Column(String)
    DatePublished = Column(Date)
    Description = Column(String)
    Images = Column(String)
    RecipeCategory = Column(String)
    Keywords = Column(String)
    AggregatedRating = Column(Float)
    ReviewCount = Column(Integer)
    Calories = Column(Integer)
    FatContent = Column(Integer)
    SaturatedFatContent = Column(Integer)
    CholesterolContent = Column(Integer)
    SodiumContent = Column(Integer)
    CarbohydrateContent = Column(Integer)
    FiberContent = Column(Integer)
    SugarContent = Column(Integer)
    ProteinContent = Column(Integer)
    RecipeServings = Column(Integer)
    RecipeYield = Column(String)
    RecipeInstructions = Column(String)
    image_link = Column(String)
    text = Column(String)

    bookmarks = relationship("Bookmark", back_populates="recipe")


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_active = Column(Boolean, default=True)

    # Use string reference for relationship
    bookmarks = relationship("Bookmark", back_populates="user") # Define in user.py
    folders = relationship("Folder", back_populates="user")


# Pydantic model for user creation
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

# Pydantic model for user response (without password)
class UserResponse(BaseModel):
    user_id: int
    username: str
    email: str

    class Config:
        orm_mode = True

# Bookmark model
class Bookmark(Base):
    __tablename__ = "bookmarks"
    __table_args__ = {'schema': 'recipes_tb'}  # specify schema for this table

    bookmark_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))  # ForeignKey referencing User's id without schema prefix
    recipe_id = Column(Integer, ForeignKey('recipes_tb.recipes.RecipeId'))  # ForeignKey referencing Recipe's id without schema prefix
    folder_id = Column(Integer, ForeignKey('recipes_tb.folders.folder_id'))
    rating = Column(Integer)  # Rating between 1-5

    # Relationships
    user = relationship("User", back_populates="bookmarks")
    recipe = relationship("Recipe", back_populates="bookmarks")
    folder = relationship("Folder", back_populates="bookmarks")

class BookmarkResponse(BaseModel):
    bookmark_id: int
    recipe_id: int
    user_id: int
    rating: int
    folder_id: Optional[int]  # Optional if needed, you can link to the Folder

    class Config:
        orm_mode = True  # This ensures the model is compatible with SQLAlchemy ORM objects


class BookmarkRequest(BaseModel):
    recipe_id: int
    folder_id: int
    rating: float

class Folder(Base):
    __tablename__ = "folders"
    __table_args__ = {'schema': 'recipes_tb'}

    folder_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    folder_name = Column(String)
    description = Column(String)
    created_at = Column(DateTime, default=datetime)
    average_rating = Column(NUMERIC, nullable=True)  # New column to store average rating

    #Relationships
    user = relationship("User", back_populates="folders")
    bookmarks = relationship("Bookmark", back_populates="folder")

class FolderCreate(BaseModel):
    folder_name: str
    description: str

class FolderResponse(BaseModel):
    folder_id: int
    folder_name: str
    description: str
    created_at: datetime
    average_rating: Optional[float]

    class Config:
        orm_mode = True
