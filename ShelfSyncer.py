# -*- coding: utf-8 -*-

VERSION = "1.0.1"

# Maya imports
import maya.cmds as cmds
import maya.mel as mel
import maya.OpenMaya as OpenMaya
import maya.OpenMayaMPx as OpenMayaMPx

# Standard libraries imports
import os
import json
import base64
import re
import shutil
import hashlib
from collections import Counter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

# ---------------------------------- PLUGINS -----------------------------------

# Plugin information
kPluginVersion = VERSION
kPluginAuthor = "ZSPFX"

kTabName = "ShelfSync"
kMenuName = "ShelfSyncerMenu"
kPrefKey = "ShelfSyncerTeams"

BLACKLIST_DEFAULT_SHELVES = [
    "shelf_Animation.mel", "shelf_Curves.mel", "shelf_MotionGraphics.mel",
    "shelf_Sculpting.mel", "shelf_XGen.mel", "shelf_Arnold.mel", "shelf_FX.mel",
    "shelf_Polygons.mel", "shelf_Surfaces.mel", "shelf_Bifrost.mel", "shelf_FXCaching.mel",
    "shelf_Rendering.mel", "uvShelf_Custom.mel", "shelf_Bullet.mel", "shelf_MASH.mel",
    "shelf_Rigging.mel", "shelf_UVEditing.mel", "shelf_Redshift.mel",
    "shelf_Example.mel"
]

# --- Key-pair generation and Loaders ---

def generate_private_public_key_pair(password_bytes):
    """
    Generates the RSA private/public key pair.

    Args:
        password_bytes (bytes): The password to encrypt the private key.

    Returns:
        tuple:
            - bytes: Encrypted private key in PEM format.
            - bytes: Public key in PEM format.
    """
    # Generate new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize and encrypt the private key with given password
    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )

    # Get public key
    public_key = private_key.public_key()

    # Serialize public key
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_pem_private_key, pem_public_key

def load_private_key(pem_private_key_bytes, password_bytes):
    """
    Loads the encrypted PEM private key.

    Args:
        pem_private_key_bytes (bytes): Encrypted private key in PEM format.
        password_bytes (bytes): Password used to encrypt the private key.

    Returns:
        RSAPrivateKey object or None: Private key or None if fail
    """
    try:
        private_key = serialization.load_pem_private_key(
            pem_private_key_bytes,
            password=password_bytes
        )

        if not isinstance(private_key, rsa.RSAPrivateKey):
             OpenMaya.MGlobal.displayError("[ShelfSyncer] Error: Loaded key is not an RSA private key.")
             return None

        return private_key
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error loading private key: {e}")
        return None

def load_public_key(pem_public_key_bytes):
    """
    Loads a PEM public key.

    Args:
        pem_public_key_bytes (bytes): The public key in PEM format.

    Returns:
        RSAPublicKey object or None: Public key or None if fail
    """
    try:
        public_key = serialization.load_pem_public_key(
            pem_public_key_bytes,
        )

        if not isinstance(public_key, rsa.RSAPublicKey):
             OpenMaya.MGlobal.displayError("[ShelfSyncer] Error: Loaded key is not an RSA public key.")
             return None

        return public_key
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error loading public key: {e}")
        return None

# --- Directory Signing and Verification ---

def sign_directory(directory_path, private_key):
    """
    Scans and hash each file (shelves) in the directories then save them as `.sig` file.

    Args:
        directory_path (str): Path to the directory containing files or shelves to sign.
        private_key (RSAPrivateKey): The loaded RSA private key object.

    Returns:
        bool: True if ok, False if failed
    """
    if not os.path.isdir(directory_path):
        OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error: Directory not found: {directory_path}")
        return False
    if not private_key:
        OpenMaya.MGlobal.displayError("[ShelfSyncer] Error: Invalid private key provided.")
        return False

    all_successful = True
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Signing files in directory: {directory_path}")

    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)

        # Skip directories and signature files
        if os.path.isdir(file_path) or filename.endswith(".sig"):
            continue

        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer]   Processing: {filename}...")
        try:
            # Read file
            with open(file_path, "rb") as f:
                file_data = f.read()

            # Hash content
            hasher = hashlib.sha256()
            hasher.update(file_data)
            digest = hasher.digest()

            # Sign hash
            signature = private_key.sign(
                digest,
                padding.PSS( # PSS padding
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256() # Hash algorithm
            )

            # Save signature to .sig file
            signature_path = file_path + ".sig"
            with open(signature_path, "wb") as sig_file:
                sig_file.write(signature)
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Signature saved to: {filename}.sig")

        except Exception as e:
            OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error processing file {filename}: {e}")
            all_successful = False

    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Signing process completed.")
    return all_successful

def verify_directory(directory_path, public_key):
    """
    Verifies the integrity and authenticity of files in a directory using their '.sig' files and the public key.

    Args:
        directory_path (str): Path to the directory containing files and signatures.
        public_key (RSAPublicKey): The loaded RSA public key object.

    Returns:
        dict: A dictionary where keys are filenames and values are booleans
              indicating if verification was successful (True) or failed/skipped (False).
    """
    results = {}
    if not os.path.isdir(directory_path):
        OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error: Directory not found: {directory_path}")
        return results
    if not public_key:
        OpenMaya.MGlobal.displayError("[ShelfSyncer] Error: Invalid public key provided.")
        return results

    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Verifying files in directory: {directory_path}")

    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        signature_path = file_path + ".sig"

        # Skip directories and signature files
        if os.path.isdir(file_path) or filename.endswith(".sig"):
            continue

        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer]   Verifying: {filename}...")
        results[filename] = False # Default to False

        # Check if signature file exists
        if not os.path.exists(signature_path):
            OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] Warning: Signature file not found: {filename}.sig. Skipping.")
            continue # Cannot verify without signature

        try:
            # Read file
            with open(file_path, "rb") as f:
                file_data = f.read()

            # Hash content
            hasher = hashlib.sha256()
            hasher.update(file_data)
            digest = hasher.digest()

            # Read signature
            with open(signature_path, "rb") as sig_file:
                signature = sig_file.read()

            # Verify signature
            try:
                public_key.verify(
                    signature,
                    digest,
                    padding.PSS( # PSS padding
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256() # Hash algorithm
                )
                OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] OK: Signature is valid.")
                results[filename] = True # Verification successful
            except InvalidSignature:
                OpenMaya.MGlobal.displayError(f"[ShelfSyncer] FAILED: Signature is invalid! File may have been tampered with.")
            except Exception as e: # Verification errors/failed
                 OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error during verification for {filename}: {e}")


        except Exception as e:
            OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error processing file {filename} for verification: {e}")

    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Verification process completed.")

    isValid = all(results.values())
    return isValid

def prompt_password():
    """
    Ask the user for a password before publishing the shelves.

    The password is used to unlock private key for signing the 256 hases.

    Returns:
        str: The password entered by the user.
    """

    result = cmds.promptDialog(
        title='Admin Password',
        message='Enter Admin Password:',
        button=['OK', 'Cancel'],
        defaultButton='OK',
        cancelButton='Cancel',
        dismissString='Cancel')

    if result == 'OK':
        return cmds.promptDialog(query=True, text=True)
    return None

# ---------------- SYNC SHELVES ---------------

def silently_delete_shelf_tab(shelf_name, shelf_dest):
    """
    Silently delete the existing shelves tab from the UI without asking for user permission in a safe way.

    Replicate normal Maya behavior where deleted shelf will be renamed into <file>.mel.deleted rather than actually deleting it.
    
    Args:
        shelf_name (str): The name of the shelf tab to delete.
        shelf_dest (str): Path to the Autodesk Maya preference > shelf .mel file.
    """

    # Remove from UI
    if cmds.shelfLayout(shelf_name, exists=True):
        cmds.deleteUI(shelf_name, layout=True)
        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Shelf layout '{shelf_name}' removed from UI.")

    # Rename .mel file to prevent reloading
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Trying to delete old shelf layout.. Path: {shelf_dest}")

    if os.path.exists(shelf_dest):
        new_path = shelf_dest + ".deleted"

        # If .deleted version already exists, remove it first
        if os.path.exists(new_path):
            os.remove(new_path)
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Existing deleted file '{new_path}' removed.")

        os.rename(shelf_dest, new_path)
        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Renamed old shelf file to '{new_path}'.")
    else:
        OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] No .mel file found for shelf '{shelf_name}'.")

    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Successfully deleted old shelf.")

    return True

def sync_shelves():
    """
    Look-up all added teams from Maya preference and sync their shelves one by one.
    Signature checking happens here.
    """

    teams = get_team_from_maya_preference()
    
    user_pref_dir = cmds.internalVar(userPrefDir=True)
    shelves_dir = os.path.join(user_pref_dir, "shelves")

    # Scan shelves
    for team_name, team_data in teams.items():
        repository_path = os.path.join(team_data["folder"], "repository")
        shelves_path = os.path.join(repository_path, "shelves")
        icons_path = os.path.join(repository_path, "icons")

        state_file = os.path.join(team_data["folder"], ".shelfsync")
        if not os.path.exists(state_file):
            OpenMaya.MGlobal.displayError("[ShelfSyncer] Missing .shelfsync file for team: " + team_name)
            return False
        
        with open(state_file, "r") as f:
            data = json.load(f)

        # local public key (rather than remote)
        encoded_pub_key = team_data["public_key"]

        # Load public key
        public_key = load_public_key(base64.b64decode(encoded_pub_key))
        if not public_key:
            OpenMaya.MGlobal.displayError("[ShelfSyncer] Error loading public key, skipping team: " + team_name)
            continue
        else:
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Loaded public key for team: {team_name}")

        # Verify signature
        ok = verify_directory(shelves_path, public_key)
        if not ok:
            OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error verifying directory for team: {team_name} (has the files been tempered with?), skipping team: " + team_name)
            continue
        else:
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Directory has valid signature for team: {team_name}")

        # Scan shelves
        for shelf in data["shelves"]:
            shelf_path = os.path.join(shelves_path, f"shelf_{shelf}.mel")
            if not os.path.exists(shelf_path):
                OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Shelf '{shelf}' not found in {shelf_path}")
                continue

            # Read file content
            with open(shelf_path, 'r') as f:
                shelf_content = f.read()
                # Replaces placeholder to actual path
                shelf_content = shelf_content.replace("$REPOSITORY_PATH$", icons_path.replace("\\", "/"))
            
            # mel.eval(f'deleteShelfTab  "{shelf}";')
            shelf_dest = os.path.join(shelves_dir, f"shelf_{shelf}.mel")
            
            silently_delete_shelf_tab(shelf, shelf_dest)

            OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Trying to create new shelf.")

            # Write file to destination
            with open(shelf_dest, 'w') as f:
                f.write(shelf_content)

            # Tell Maya to load shelf
            shelf_dest = shelf_dest.replace("\\", "/")
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Loading shelf: {shelf_dest}...")
            mel.eval(f'loadNewShelf "{shelf_dest}";')
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Loaded shelf: {shelf_dest}!")

        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Scanning shelves for team: {team_name} - {team_data}")
    
    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Successfully synced shelves.")

# ---------------- PUBLISH SHELVES ---------------

def remove_unused_shelves(shelves, team_folder):
    """
    Remove shelves and .sig that are not selected by the user from the destination folder.

    (Icons left untouched, it should be managed by the user themselves)

    Args:
        shelves (list): List of shelf names.
        team_folder (str): Path to the destination folder.
    """
    
    dest_dir = os.path.join(team_folder, "repository", "shelves")
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Removing unused shelves from destination folder: {dest_dir}")

    # List all files in the destination directory
    try:
        all_files = os.listdir(dest_dir)
    except Exception as e:
        OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error reading directory: {e}")
        return

    # Filter out files that are not shelves or signatures
    shelf_files = [f for f in all_files if f.endswith(".mel") or f.endswith(".sig")]

    # Filter out files that are not in the shelves list
    filtered_files = [f for f in shelf_files if f not in shelves]

    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Filtered files: {filtered_files}")

    # Remove files that are not in the shelves list
    for f in filtered_files:
        file_path = os.path.join(dest_dir, f)

        # [SAFEGUARD]: Make sure the file is within dest_dir and ends with expected extension
        if file_path.startswith(dest_dir) and (file_path.endswith(".mel") or file_path.endswith(".sig")):
            if os.path.isfile(file_path):
                try:
                    os.remove(file_path)
                    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Removed unused file: {file_path}")
                except Exception as e:
                    OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] Warning: Failed to remove file: {file_path} ({e})")
            else:
                OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] Warning: File not found or not a regular file: {file_path}")
        else:
            OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] Skipped unsafe file: {file_path}")

def copy_shelves_icons_dependencies_to_dest(shelf_path, team_folder):
    """
    Scan for -image and -image1 commands in the shelf file and copy the referenced icons to the destination folder.

    Args:
        shelf_path (str): Path to the Autodesk Maya's preferences > shelf .mel file.
        team_folder (str): Path to the team folder.
    """

    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Getting icons dependencies for shelf: {shelf_path}")

    # Read shelf file
    with open(shelf_path, 'r') as f:
        shelf_content = f.read()

    # Find -image and -image1 commands
    image_commands = re.findall(r'-image\s+"([^"]+)"', shelf_content)

    icons_path = [] # Paths to custom icons
    icons_file = [] # Built-in icons with no path

    for image in image_commands:
        is_path = os.path.exists(image) or "/" in image
        if is_path:
            icons_path.append(image)

            icon_file = os.path.basename(image)
            OpenMaya.MGlobal.displayInfo (f"Icon_file: {icon_file}")
            shelf_content = shelf_content.replace(f'-image "{image}"', f'-image "$REPOSITORY_PATH$/{icon_file}"')
            shelf_content = shelf_content.replace(f'-image1 "{image}"', f'-image1 "$REPOSITORY_PATH$/{icon_file}"')
        else:
            icons_file.append(image)

    OpenMaya.MGlobal.displayInfo(icons_path)
    OpenMaya.MGlobal.displayInfo(icons_file)

    # Copy icons to destination
    dest_dir = os.path.join(team_folder, "repository", "icons")
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    
    for icon in icons_path:
        # check if is the same file
        try:
            shutil.copy(icon, dest_dir)
        except shutil.SameFileError:
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Already exists: {icon}")
        except Exception as e:
            OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Error copying icon file: {icon}")
    
    return shelf_content
    
def copy_shelf_files_to_dest(shelves, team_folder):
    """
    Copy shelf files to the destination repository directory.

    (icon path gets replaced with $REPOSITORY_PATH$/ placeholder prefix)
    The placeholder will be replaced again in syncing stage.

    Args:
        shelves (list): List of shelf names.
        team_folder (str): Path to the team folder.
    """

    dest_dir = os.path.join(team_folder, "repository", "shelves")

    """Copy shelf files to destination directory."""
    # Check if the destination directory exists
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    # Copy shelf files
    user_pref_dir = cmds.internalVar(userPrefDir=True)
    shelves_dir = os.path.join(user_pref_dir, "shelves")

    # Gather shelves
    if os.path.exists(shelves_dir):
        for f in os.listdir(shelves_dir):
            if f.startswith("shelf_") and f.endswith(".mel"):
                shelf_name = f[6:-4] # Stripped out prefix/suffix
                if shelf_name in shelves:
                    shelf_path = os.path.join(shelves_dir, f)

                    shelf_content = copy_shelves_icons_dependencies_to_dest(shelf_path, team_folder)
                   
                    # write shelf content to shelf_{NAME}.mel
                    with open(os.path.join(dest_dir, f"shelf_{shelf_name}.mel"), 'w') as f:
                        f.write(shelf_content)
    
    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Successfully copied shelves to destination.")

def publish_shelves(folder_path, selected_shelves=None):
    """
    Publish the shelves to the destination folder.

    Admin password is required at this stage to decrypt and use the private key for signature signing.
    Required files and dependencies will be copied to the destination folder.

    Args:
        folder_path (str): Path to the folder containing the .shelfsync file.
    
    Returns:
        bool: True if ok, false if fails.
    """

    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Publishing shelves to folder: {folder_path} with selected shelves: {selected_shelves}")

    state_file = os.path.join(folder_path, ".shelfsync")
    if not os.path.exists(state_file):
        OpenMaya.MGlobal.displayError("[ShelfSyncer] Missing .shelfsync file")
        return False

    with open(state_file, "r") as f:
        data = json.load(f)

    team_name = data.get('team_name')
    shelves = data.get('shelves')
    encoded_priv_key = data.get('private_key')
    encoded_pub_key = data.get('public_key')

    private_key = None
    while private_key is None:
        password = prompt_password()
        if not password:
            OpenMaya.MGlobal.displayError("[ShelfSyncer] Password entry cancelled.")
            return False

        private_key = load_private_key(base64.b64decode(encoded_priv_key), password.encode())
        if private_key is None:
            OpenMaya.MGlobal.displayError("[ShelfSyncer] Incorrect password. Please try again.")

    # Success — continue with logic
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Team: {team_name}")
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Shelves: {shelves}")
    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Private key successfully decrypted.")
    
    # Update .shelfsync file if selected shelves has been modified from the original.
    if selected_shelves is not None and has_single_common_element_only_once(selected_shelves, shelves) == False:
        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Shelves have been modified from the original. Updating .shelfsync file.")
       
        # Update .shelfsync file with the selected shelves
        with open(state_file, "w") as f:
            f.write(json.dumps({
                'team_name': team_name,
                'shelves': selected_shelves,
                'private_key': encoded_priv_key,
                'public_key': encoded_pub_key
            }))
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Updated .shelfsync file with selected shelves: {selected_shelves}")

        # Update shelves variable with the modified selected shelves
        shelves = selected_shelves

        remove_unused_shelves(shelves, folder_path)

    # Copy shelf files
    copy_shelf_files_to_dest(shelves, folder_path)

    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Successfully copied shelves to destination.")

    # Create a new signature
    dest_dir = os.path.join(folder_path, "repository", "shelves")

    ok = sign_directory(dest_dir, private_key)
    if not ok:
        OpenMaya.MGlobal.displayError("[ShelfSyncer] Error signing directory.")
        return False
    else:
        OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Directory signed.")

    # Load public key   
    public_key = load_public_key(base64.b64decode(encoded_pub_key))
    if not public_key:
        OpenMaya.MGlobal.displayError("[ShelfSyncer] Error loading public key.")
        return False
    
    # Verify signature
    ok = verify_directory(dest_dir, public_key)
    if not ok:
        OpenMaya.MGlobal.displayError("[ShelfSyncer] Error verifying directory.")
        return False
    else:
        OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Directory verified.")

    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Successfully published shelves.")

    return True

# ---------------- HELPER FUNCTIONS ---------------

# Preview: {'ZSPFX': {'folder': 'C:/Users/manag/Desktop/TestShelfTeam', 'shelves': ['ZSPFX']}}
def get_team_from_maya_preference():
    teams = {}
    if cmds.optionVar(exists=kPrefKey):
        teams_json = cmds.optionVar(q=kPrefKey)
        try:
            teams = json.loads(teams_json)
        except Exception:
            teams = {}
    print(teams)
    return teams


def has_single_common_element_only_once(arr1, arr2):
    count1 = Counter(arr1)
    count2 = Counter(arr2)
    
    common_elements = set(count1.keys()) & set(count2.keys())
    
    return (
        len(common_elements) == 1 and
        all(count1[elem] == 1 and count2[elem] == 1 for elem in common_elements)
    )

def _get_custom_shelves():
    """Finds custom user shelves, excluding Maya defaults."""
    user_pref_dir = cmds.internalVar(userPrefDir=True)
    shelves_dir = os.path.join(user_pref_dir, "shelves")

    shelves = []
    if os.path.exists(shelves_dir):
        for f in os.listdir(shelves_dir):
            if f.startswith("shelf_") and f.endswith(".mel") and f not in BLACKLIST_DEFAULT_SHELVES:
                 file_path = os.path.join(shelves_dir, f)
                 if os.path.isfile(file_path):
                    shelves.append(f[6:-4])  # strip prefix/suffix "shelf_" and ".mel"

    shelves.sort()

    return shelves, shelves_dir

# --- This UI component is heavily AI assisted, writing a Maya is quite a pain and too time consuming. This is more of a misc feature. ---
class ShelfSelectorPreview:

    def __init__(self, parent_layout, shelves, shelves_dir, default_selected_shelves=None):
        """
        Args:
            parent_layout (str): Name of the parent Maya UI layout.
            shelves (list): List of shelf names (without prefix/suffix).
            shelves_dir (str): Path to the user's shelves directory.
            default_selected_shelves (list, optional): List of shelf names that should be checked by default initially. Defaults to None (no defaults).
        """
        self.shelves = shelves
        self.shelves_dir = shelves_dir
        self.default_selected = set(default_selected_shelves or [])
        self.shelf_checkboxes = {}
        self.preview_grid = None # Will be created later
        self.parent_layout = parent_layout

        # Create the UI elements
        self._create_ui()

        cmds.evalDeferred(self.on_preview)


    def _create_ui(self):
        """Builds the UI elements under the parent layout."""

        if cmds.layout(self.parent_layout, exists=True):
             cmds.setParent(self.parent_layout)
        else:
             OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] Warning: Parent layout '{self.parent_layout}' does not exist.")
             return


        # --- Shelf Selection Section ---
        # Check if the frame layout already exists (ex: if the class was re-initialized without cleaning parent)
        shelf_select_frame_name = "shelfSelectFrame_" + str(id(self))
        if cmds.frameLayout(shelf_select_frame_name, exists=True):
             cmds.deleteUI(shelf_select_frame_name)

        cmds.frameLayout(shelf_select_frame_name, label="Select Shelves", collapsable=True, marginWidth=10, parent=self.parent_layout)
        scroll_layout = cmds.scrollLayout("shelfSelectScroll", height=80)
        checkbox_column = cmds.columnLayout("shelfCheckboxColumn", adjustableColumn=True, parent=scroll_layout)

        if not self.shelves:
             cmds.text(label="No custom shelves found.", parent=checkbox_column)
        else:
            for shelf in self.shelves:
                # Check if should the initial checked state based on defaults
                initial_value = shelf in self.default_selected

                # Create the checkbox with the initial value
                # Store the checkbox widget name associated with the shelf name
                self.shelf_checkboxes[shelf] = cmds.checkBox(
                    label=shelf,
                    value=initial_value, # Set initial checked state
                    changeCommand=self.on_preview, # Update preview when checkbox changes
                    parent=checkbox_column
                )

        cmds.setParent('..') # Back to scroll_layout
        cmds.setParent('..') # Back to shelfSelectFrame


        # --- Shelf Preview Section ---
        # Check if the frame layout already exists
        shelf_preview_frame_name = "shelfPreviewFrame_" + str(id(self))
        if cmds.frameLayout(shelf_preview_frame_name, exists=True):
             cmds.deleteUI(shelf_preview_frame_name)

        cmds.frameLayout(shelf_preview_frame_name, label="Preview Shelves", collapsable=True, marginWidth=10, parent=self.parent_layout)
        preview_scroll = cmds.scrollLayout("shelfPreviewScroll", height=200)
        # Store the grid layout name for later use
        self.preview_grid = cmds.gridLayout(
            "shelfPreviewGrid",
            numberOfColumns=4,
            cellWidthHeight=(80, 80),
            parent=preview_scroll
        )
        cmds.setParent('..') # Back to preview_scroll
        cmds.setParent('..') # Back to shelfPreviewFrame

    def on_preview(self, *args):
        """Updates the preview grid based on selected checkboxes."""
        # Added check for grid existence at the start
        if not self.preview_grid or not cmds.gridLayout(self.preview_grid, exists=True):
             OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] Warning: Preview grid does not exist or is not ready for update.")
             # Attempt to find it again - useful if called via evalDeferred
             if cmds.control("shelfPreviewGrid", exists=True):
                  self.preview_grid = "shelfPreviewGrid"
             else:
                  return # Cannot proceed without the grid

        # Clear previous previews
        children = cmds.gridLayout(self.preview_grid, query=True, childArray=True) or []
        for child in children:
            if cmds.control(child, exists=True): # Check existence before deleting
                 try:
                     cmds.deleteUI(child)
                 except RuntimeError as e:
                      OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] Warning: Minor error deleting UI element {child}: {e}")
            else:
                 OpenMaya.MGlobal.displayWarning(f"[ShelfSyncer] Warning: Attempted to delete non-existent UI element: {child}")


        # Gather selected shelves based on the *current* checkbox states
        selected = self.get_selected_shelves()

        # Populate preview grid if there are selected shelves
        if not selected:
            # Add a placeholder text if no shelves are selected
             cmds.setParent(self.preview_grid)
             cmds.text(label="No shelves selected for preview.", align="center")
             # Fill remaining cells in the first row with empty text to center the message
             for _ in range(4 - 1): # Adjust range based on numberOfColumns
                  cmds.text(label="")
             return # No need to parse if nothing is selected


        cmds.setParent(self.preview_grid)

        for name in selected:
            mel_path = os.path.join(self.shelves_dir, f"shelf_{name}.mel")
            if not os.path.exists(mel_path):
                OpenMaya.MGlobal.displayWarning(f"Warning: Shelf file not found for preview: {mel_path}")
                continue

            try:
                with open(mel_path, 'r') as f:
                    content = f.read()
            except IOError as e:
                OpenMaya.MGlobal.displayError(f"Error reading shelf file {mel_path}: {e}")
                continue
            except Exception as e: # Catch other potential file reading errors
                 OpenMaya.MGlobal.displayError(f"Unexpected error reading shelf file {mel_path}: {e}")
                 continue

            # Find all shelfButton blocks
            # Use non-greedy match (-[^;]+?) to avoid issues with nested semicolons or multiple buttons
            # Look for -image or -label first, then annotation, to try and get a useful label/tooltip
            button_pattern = re.compile(r'shelfButton\s+(-[^;]+?);', re.DOTALL)
            image_pattern = re.compile(r'-image\s+"([^"]+)"')
            annotation_pattern = re.compile(r'-annotation\s+"([^"]+)"')
            label_pattern = re.compile(r'-label\s+"([^"]+)"')


            for match in button_pattern.finditer(content):
                block = match.group(1)
                # Extract icon and annotation/label
                icon_match = image_pattern.search(block)
                ann_match = annotation_pattern.search(block)
                label_match = label_pattern.search(block)

                icon_name = icon_match.group(1) if icon_match else 'commandButton.png' # Default icon
                # Prioritize annotation > label > shelf name as tooltip/label
                display_label = ann_match.group(1) if ann_match else (label_match.group(1) if label_match else "Cmd") 
                tooltip = ann_match.group(1) if ann_match else (label_match.group(1) if label_match else f"Shelf: {name}")


                # Create preview button in the grid
                try:
                    if cmds.gridLayout(self.preview_grid, exists=True):
                         cmds.iconTextButton(
                             parent=self.preview_grid,
                             style='iconAndTextVertical',
                             image=icon_name,
                             label=display_label, # Use the extracted label
                             width=75, # Adjust slightly for padding
                             height=75,
                             annotation=tooltip # Set annotation for tooltip
                         )
                except RuntimeError as e:
                      # Catch potential errors if UI elements are unexpectedly deleted
                      OpenMaya.MGlobal.displayError(f"Error creating preview button for '{display_label}': {e}")
                except TypeError as e:
                      # Likely missing image file or incorrect attribute
                      OpenMaya.MGlobal.displayError(f"Error (likely missing image file '{icon_name}' or invalid attribute) creating preview button for '{display_label}': {e}")
                      # Create a placeholder button with default icon
                      if cmds.gridLayout(self.preview_grid, exists=True):
                           cmds.iconTextButton(
                               parent=self.preview_grid,
                               style='iconAndTextVertical',
                               image='commandButton.png', # Use default icon
                               label=display_label,
                               width=75,
                               height=75,
                               annotation=f"Error loading icon for {display_label}"
                           )


    def get_selected_shelves(self):
        """Returns a list of names of the currently selected shelves."""
        selected = []
        # Use items() for potentially slightly cleaner iteration
        for shelf_name, checkbox_widget in self.shelf_checkboxes.items():
            # Check if the checkbox widget still exists before querying
            if cmds.control(checkbox_widget, exists=True): # Use cmds.control for a more general check
                try:
                    if cmds.checkBox(checkbox_widget, query=True, value=True):
                        selected.append(shelf_name)
                except RuntimeError:
                     # Handle cases where the control might exist but isn't a checkbox anymore
                     OpenMaya.MGlobal.displayWarning(f"Warning: Control '{checkbox_widget}' found but is not a valid checkbox.")
            else:
                 OpenMaya.MGlobal.displayWarning(f"Warning: Checkbox widget for shelf '{shelf_name}' not found during selection query.")
        return selected

    def update_selection(self, new_default_shelves):
        """
        Updates the checkbox selection based on a new list of default shelves
        and refreshes the preview.

        Args:
            new_default_shelves (list): A list of shelf names that should now
                                         be checked.
        """
        # Convert the new list to a set for efficient lookup
        new_default_set = set(new_default_shelves or [])

        # Iterate through all checkboxes managed by this instance
        for shelf_name, checkbox_widget in self.shelf_checkboxes.items():
            if cmds.control(checkbox_widget, exists=True):
                # Check if this shelf name is in the new default list
                should_be_checked = shelf_name in new_default_set

                # Check the current state of the checkbox
                current_value = cmds.checkBox(checkbox_widget, query=True, value=True)

                # Update the checkbox value *only if* it needs to change
                if current_value != should_be_checked:
                    try:
                        cmds.checkBox(checkbox_widget, edit=True, value=should_be_checked)
                    except RuntimeError as e:
                         OpenMaya.MGlobal.displayError(f"Error updating checkbox for '{shelf_name}': {e}")
            else:
                 OpenMaya.MGlobal.displayWarning(f"Warning: Checkbox widget for shelf '{shelf_name}' not found during selection update.")


        cmds.evalDeferred(self.on_preview)

# ---------------- TEAM MANAGEMENT ---------------
           
def create_team(folder_path):
    """
    Handle the creation of a new team in a completely empty folder, with shelf items preview.

    User will be asked for new team name and admin password.

    Once ready a .shelfsync file will be created in the folder containing the required metadata.

    Args:
        folder_path (str): Path to the folder to create the team in.
    """

    """Handle the creation of a new team in a completely empty folder, with shelf preview."""
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Creating team in folder: {folder_path}")

    # User preferences and shelves directory
    user_pref_dir = cmds.internalVar(userPrefDir=True)
    shelves_dir = os.path.join(user_pref_dir, "shelves")

    # Blacklist default Maya shelves (filtering them out)
    shelves = []
    if os.path.exists(shelves_dir):
        for f in os.listdir(shelves_dir):
            if f.startswith("shelf_") and f.endswith(".mel") and f not in BLACKLIST_DEFAULT_SHELVES:
                shelves.append(f[6:-4])  # strip prefix/suffix

    window_name = "createTeamWindow"
    if cmds.window(window_name, exists=True):
        cmds.deleteUI(window_name)
    window = cmds.window(window_name, title="Create Team & Share Shelves", widthHeight=(480, 620))
    main_layout = cmds.columnLayout("createTeamMainLayout", adjustableColumn=True, rowSpacing=8)

    cmds.text(label="Team Name:")
    team_name_field = cmds.textField()
    cmds.text(label="Admin Password:")
    admin_pass_field = cmds.textField()

    # --- Use the Reusable Class ---
    shelves, shelves_dir = _get_custom_shelves()
    shelf_selector = ShelfSelectorPreview(
        main_layout,
        shelves,
        shelves_dir,
    )

    def on_create_team(*args):
        """
            This is where the process of creating .shelfsync file happens.
            As well as generating the private/public key pair for signing.
        """

        team = cmds.textField(team_name_field, query=True, text=True)
        pwd = cmds.textField(admin_pass_field, query=True, text=True)
        if not team or not pwd:
            OpenMaya.MGlobal.displayError("[ShelfSyncer] Team name and password are required.")
            return

        selected_shelves = shelf_selector.get_selected_shelves() # Get selected shelves
        priv, pub = generate_private_public_key_pair(pwd.encode())
        with open(os.path.join(folder_path, ".shelfsync"), 'w') as f:
            f.write(json.dumps({
                'team_name': team,
                'shelves': selected_shelves,
                'private_key': base64.b64encode(priv).decode(),
                'public_key': base64.b64encode(pub).decode()
            }))

        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Team '{team}' created with shelves: {selected_shelves}")
        add_team(folder_path)

        ok = publish_shelves(folder_path, None)
        if ok:
            cmds.deleteUI(window, window=True)
            sync_shelves()

    cmds.button(label="Create Team & Publish Shelves", command=on_create_team)
    cmds.showWindow(window)

def add_team(folder_path):
    """
    Handle adding a team to the preference when a '.shelfsync' file already exists.

    Args:
        folder_path (str): Path to the folder containing the .shelfsync file.
    """
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Adding team in folder: {folder_path}")

    # Read .shelfsync file
    state_file = os.path.join(folder_path, ".shelfsync")
    with open(state_file, "r") as f:
        data = json.load(f)

    # Get the team name and list of selected shelves
    team_name = data["team_name"]
    selected_shelves = data["shelves"]
    encoded_pub_key = data["public_key"]

    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Adding team '{team_name}' with shelves: {selected_shelves}")

    # Store the team data in Maya preferences
    teams = get_team_from_maya_preference()

    # Add or update the team information.
    teams[team_name] = {
        "folder": folder_path,
        "public_key": encoded_pub_key,
    }

    # Save the updated teams dictionary back into the Maya pref
    cmds.optionVar(stringValue=(kPrefKey, json.dumps(teams)))
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Team '{team_name}' stored in preferences.")

def remove_team(team_name, window_name):
    """
    Remove a team from preferences and refresh the UI.

    Args:
        team_name (str): The name of the team to remove.
        window_name (str): The name of the UI window to refresh.
    """

    teams = get_team_from_maya_preference()

    if team_name in teams:
        del teams[team_name]
        cmds.optionVar(stringValue=(kPrefKey, json.dumps(teams)))
        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Removed team '{team_name}' from preferences.")
    else:
        OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Team '{team_name}' not found in preferences.")

    # Refresh the window: close it and reopen.
    if cmds.window(window_name, exists=True):
        cmds.deleteUI(window_name)
    action_manage_teams_popup()

# ---------------- TAB ACTIONS ---------------

def action_add_team_popup():
    """Add a new team to the shelf syncer."""
    OpenMaya.MGlobal.displayInfo("[ShelfSyncer] Adding a new team")

    # Open Maya's file dialog for selecting a folder
    folder_path = cmds.fileDialog2(dialogStyle=2, fileMode=3, caption="Select an Empty Folder")

    # Check if a folder was selected
    if not folder_path:
        OpenMaya.MGlobal.displayError("[ShelfSyncer] No folder selected.")
        return

    folder_path = folder_path[0]  # fileDialog2 returns a list, get the first element

    # List the folder contents
    folder_contents = os.listdir(folder_path)

    # Check if the folder is completely empty
    if not folder_contents:
        create_team(folder_path)
    else:
        # Check if the folder contains the ".shelfsync" file
        if ".shelfsync" in folder_contents:
            add_team(folder_path)
            sync_shelves()
        else:
            OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Selected folder '{folder_path}' is not empty. Operation canceled.")

def action_manage_teams_popup():
    """Manage existing teams in the preferences."""

    teams = get_team_from_maya_preference()

    # Create the main window.
    window_name = "manageTeamsWindow"
    if cmds.window(window_name, exists=True):
        cmds.deleteUI(window_name)
    window = cmds.window(window_name, title="Manage Teams", widthHeight=(500, 400))

    main_layout = cmds.columnLayout(adjustableColumn=True, rowSpacing=10)

    if not teams:
        cmds.text(label="No teams found in preferences.")
    else:
        cmds.scrollLayout(childResizable=True)
        cmds.columnLayout(adjustableColumn=True, rowSpacing=10)
        for team_name, team_data in teams.items():
            folder_path = team_data.get("folder", "Unknown")
            shelves = team_data.get("shelves", [])
            
            state_file = os.path.join(folder_path, ".shelfsync")
            if not os.path.exists(folder_path) or not os.path.exists(state_file):
                folder_status = "Not Found"
            else:
                folder_status = "Healthy"
            
            cmds.frameLayout(label=team_name, collapsable=True, marginWidth=5)
            cmds.columnLayout(adjustableColumn=True)

            cmds.text(label="Folder - {} ({})".format(folder_path, folder_status), align="left")

            shelves_str = ", ".join(shelves) if shelves else "None"
            cmds.text(label="(" + shelves_str + ")", align="left")

            cmds.button(label="Leave Team", command=lambda x, tn=team_name: remove_team(tn, window_name))
            cmds.setParent("..")
            cmds.setParent("..")
        cmds.setParent("..")
        cmds.setParent("..")

    cmds.showWindow(window)

def action_publish_shelves_popup():
    """Display a popup to pick a team and publish shelves."""

    teams = get_team_from_maya_preference()

    # Create the popup window.
    window_name = "publishShelvesWindow"
    if cmds.window(window_name, exists=True):
        cmds.deleteUI(window_name)
    window = cmds.window(window_name, title="Publish Shelves", widthHeight=(480, 620)) # Increased height for preview

    main_layout = cmds.columnLayout("publishMainLayout", adjustableColumn=True, rowSpacing=10, columnAlign="center", parent=window)

    # shelf_selector needs to be accessible by the change command, so define it here
    shelf_selector = None
    team_dropdown = None # Also define dropdown here for scope

    if not teams:
        cmds.text(label="No teams available to publish.", parent=main_layout)
    else:
        team_names = list(teams.keys())
        cmds.text(label="Select a team:", parent=main_layout)
        team_dropdown = cmds.optionMenu("teamDropdown", parent=main_layout)
        for name in team_names:
            cmds.menuItem(label=name)

        # User preferences and shelves directory
        shelves, shelves_dir = _get_custom_shelves()

        # Get the initially selected team
        initial_selected_team = cmds.optionMenu(team_dropdown, query=True, value=True)
        # initial_default_shelves = teams.get(initial_selected_team, {}).get("shelves", []) # Safely get shelves

         # Read .shelfsync file
        state_file = os.path.join(teams.get(initial_selected_team, {}).get("folder", ""), ".shelfsync")
        with open(state_file, "r") as f:
            data = json.load(f)

        # Get the team name and list of selected shelves
        initial_default_shelves = data["shelves"]

        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Initially selected team: {initial_default_shelves}")

        # --- Use the Reusable Class ---
        shelf_selector = ShelfSelectorPreview(
            main_layout, # Parent layout for the ShelfSelectorPreview's UI
            shelves,
            shelves_dir,
            default_selected_shelves=initial_default_shelves
        )

        # Define the function that updates the shelf selector when the team changes
        def on_team_selected(*args):
            """Callback for when the team dropdown value changes."""
            current_team_name = cmds.optionMenu(team_dropdown, query=True, value=True)

            # Read .shelfsync file
            state_file = os.path.join(teams.get(current_team_name, {}).get("folder", ""), ".shelfsync")
            with open(state_file, "r") as f:
                data = json.load(f)

            # Get the team name and list of selected shelves
            selected_shelves = data["shelves"]

            # Update the shelf selector UI if it exists
            if shelf_selector:
                shelf_selector.update_selection(selected_shelves)

        # Set the change command on the dropdown
        cmds.optionMenu(team_dropdown, edit=True, changeCommand=on_team_selected)


        # Define the publish command function
        def on_publish_clicked(*args):
            selected_team = cmds.optionMenu(team_dropdown, query=True, value=True)
            # Get the currently selected shelves from the UI state managed by shelf_selector
            if shelf_selector:
                selected_shelves = shelf_selector.get_selected_shelves()
                OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Publishing shelves: {selected_shelves}")

                ok = publish_shelves(teams.get(selected_team, {}).get("folder", ""), selected_shelves)

                if ok:
                    cmds.deleteUI(window_name)
            else:
                 OpenMaya.MGlobal.displayError("[ShelfSyncer] Error: Shelf selector not initialized.")


        cmds.button(label="Publish Selected Shelves", command=on_publish_clicked, parent=main_layout)

    cmds.showWindow(window)

def action_sync_shelves():
    """Sync the shelves with the server"""
    OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Syncing all shelves")
    sync_shelves()


def create_tab():
    """Create the  tab in Maya's UI"""
    # Check if the tab already exists and delete it if it does
    if cmds.menu(kMenuName, exists=True):
        cmds.deleteUI(kMenuName)
    
    # Find the main Maya window's menubar
    gMainWindow = mel.eval('$temp=$gMainWindow')
    
    # Create a new menu in the menubar (kMenuName)
    menu = cmds.menu(
        kMenuName,
        label=kTabName,
        parent=gMainWindow,
        tearOff=True
    )
    
    cmds.menuItem(
        label="Add Team",
        parent=menu,
        command=lambda x: action_add_team_popup(),
        image="browseFolder"
    )    
    cmds.menuItem(
        label="Manage Team(s)",
        parent=menu,
        command=lambda x: action_manage_teams_popup(),
        image="advancedSettings"
    )    
    
    cmds.menuItem(divider=True, parent=menu)
    
    cmds.menuItem(
        label="Sync Shelves",
        parent=menu,
        command=lambda x: action_sync_shelves(),
        image="refresh"
    )

    cmds.menuItem(
        label="Publish Shelves",
        parent=menu,
        command=lambda x: action_publish_shelves_popup(),
        image="updatePosition"
    )

    return menu

# -------------------------- PLUGIN INITIALIZATION ---------------------------

def initializePlugin(mObject):
    plugin = OpenMayaMPx.MFnPlugin(mObject, kPluginAuthor, kPluginVersion, "Any")
    try:
        create_tab()

        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Successfully initialized plugin!")

        sync_shelves()

    except Exception as e:
        OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Failed to initialize plugin: {str(e)}")

def uninitializePlugin(mObject):
    plugin = OpenMayaMPx.MFnPlugin(mObject)
    try:
        if cmds.menu(kMenuName, exists=True):
            cmds.deleteUI(kMenuName)
            OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Successfully removed {kTabName} tab")
        
        OpenMaya.MGlobal.displayInfo(f"[ShelfSyncer] Successfully uninitialized plugin.")
        
    except Exception as e:
        OpenMaya.MGlobal.displayError(f"[ShelfSyncer] Failed to uninitialize plugin: {str(e)}")