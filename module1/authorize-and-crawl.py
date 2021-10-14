import spotipy
from flask import Flask, request, session, redirect
import pandas as pd
from spotipy.oauth2 import SpotifyOAuth
# STEP 1: Get user authentication access
clientid = '2b90b67f37914c32ad094916156f44aa'
secretid = 'c50524d981934e4c9e1dd88bcc2efacf'
scope = 'playlist-read-private playlist-modify-private playlist-modify-public'
redir = 'http%3A%2F%2Flocalhost%2F~samuelellgass%2F'

myOAuth = SpotifyOAuth(client_id=clientid, client_secret=secretid, redirect_uri=redir, scope=scope)

access = spotipy.Spotify(auth_manager=myOAuth)

# STEP 2: Get ALL user playlists (URL? URI?)
# Data comes in as deeply nested dictionary form

# STEP 3: Collect Data from every song in every playlist into a CSV file or other storage tool

# THEN OUTPUT num_playlist tables of data for module 2 to process using data pipeline

