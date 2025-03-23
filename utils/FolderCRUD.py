from datetime import datetime

from sqlalchemy.orm import Session
from model.dbModels import Folder, FolderCreate, FolderResponse

# Create Folder
def create_folder(db: Session, folder: FolderCreate, user_id: int):
    db_folder = Folder(
        folder_name=folder.folder_name,
        description=folder.description,
        user_id=user_id,
        created_at=datetime.now()  # Ensure the datetime is set
    )
    db.add(db_folder)
    db.commit()
    db.refresh(db_folder)
    return db_folder

# Get Folders for a user
def get_folders(db: Session, user_id: int):
    return db.query(Folder).filter(Folder.user_id == user_id).all()

# Get Folder by id
def get_folder_details(db: Session, folder_id: int, user_id: int):
    return db.query(Folder).filter(Folder.user_id == user_id).filter(Folder.folder_id == folder_id).all()

# Delete Folder
def delete_folder(db: Session, folder_id: int, user_id: int):
    folder_to_delete = db.query(Folder).filter(Folder.folder_id == folder_id, Folder.user_id == user_id).first()
    if folder_to_delete:
        db.delete(folder_to_delete)
        db.commit()
    return folder_to_delete
