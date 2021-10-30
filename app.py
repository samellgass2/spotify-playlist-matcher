from flask import Flask, request, url_for, session, redirect, render_template
from flask_session import Session
import os
import uuid
import time
import spotipy
import pandas as pd
from spotipy.oauth2 import SpotifyOAuth
import playlistmatch.playlistmatch as pm
import jsonpickle

app = Flask(__name__)
app.config['SECRET_KEY'] = "VERYSECRET3892093029543042"
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session/'
MODEL = "no model yet initialized"
PIDTONAME = "nothing yet"
CURRENTTRACKID = "none"
UUID = "default"
Session(app)

caches_folder = './.spotify_caches/'
if not os.path.exists(caches_folder):
    os.makedirs(caches_folder)

def create_oauth():
    # TO DO: MAKE THE CLIENT SECRET PRIVATE AND PASS IN VIA SOME PARSING OF A GIT IGNORED FILE
    """
    A function to create a spotify authorization from my client-side content
    :return: a SpotifyOAuth object, initialized for this application and permissions
    """
    return SpotifyOAuth(
        client_id='2b90b67f37914c32ad094916156f44aa',
        client_secret='c50524d981934e4c9e1dd88bcc2efacf',
        scope='playlist-read-private playlist-modify-private playlist-modify-public',
        redirect_uri=url_for('redirectPage', _external=True),
        cache_handler=spotipy.cache_handler.CacheFileHandler(cache_path=session_cache_path()),
        show_dialog=True
    )


def get_token():
    """
    Retrieves the token currently stored in the user's cache, or generates a new one if needed
    :return: token_info for use in authorization
    """
    token_info = session.get('token_info', None)
    if not token_info:
        return url_for("authorize", _external=False)
    now = int(time.time())

    expired = token_info['expires_at'] >= now
    if expired:
        oauth = create_oauth()
        token_info = oauth.refresh_access_token(token_info['refresh_token'])
    return token_info


def session_cache_path():
    return caches_folder + session.get('UUID')


@app.route('/')
def authorize():
    """
    Begins the authorization pipeline
    :return: a redirect to the authorization link
    """
    if not session.get('uuid'):
        session['UUID'] = str(uuid.uuid4())

    cache_handler = spotipy.cache_handler.CacheFileHandler(cache_path=session_cache_path())
    oauth = create_oauth()

    if request.args.get("code"):
        oauth.get_access_token(request.args.get("code"))
        return redirect('/')
    
    if not oauth.validate_token(cache_handler.get_cached_token()):
        oauth_url = oauth.get_authorize_url()
        return redirect(oauth_url)
    
    access = spotipy.Spotify(auth_manager=oauth)
    return access.me()['display_name']


@app.route('/redirect')
def redirectPage():
    """
    After login, or if refreshed, store token info once processed
    :return: a redirect to the main function
    """
    oauth = create_oauth()
    code = request.args.get('code')
    token_info = oauth.get_access_token(code)
    session['token_info'] = token_info
    return redirect(url_for('processuserdata', _external=True))

@app.route('/loadingscreen')
def loadingscreen():
    # TO DO: MAKE THIS ACTUALLY LOAD
    render_template('loadingscreen.html')
    return redirect(url_for('processuserdata', _external=True))


@app.route('/processuserdata')
def processuserdata():
    """
    MAIN FUNCTION - DELEGATES WORK TO MODULES 2 AND 3
    :return: not yet clear *** fix ***
    """

    # return str(access.current_user_playlists(limit=50, offset=1000)['next'])

    # MODULE 2 BEGINS HERE
    # session[PIDTONAME] = pidtoname
    # frozenmodel = jsonpickle.encode(pm.DataPipeline(allpackages))
    # session[MODEL] = frozenmodel

    # token_info = get_token()
    # access = spotipy.Spotify(auth=token_info)
    # return access.me()['display_name']
    # Once model is generated, REDIRECT to a page
    # that allows the user to put in a song & get it added
    return render_template('landing.html')
    # return 'Successfully processed ' + str(len(allpackages)) + ' playlists, with ' + str(sum([p[1].shape[0] for p in allpackages])) + ' total songs and built model with ' + str(len(playlistmodel.pids)) + ' known pids'
    # THIS RETURN WILL REDIRECT

# TO DO - BUILD OUT FUNCTIONALITY FOR 100+ VIA FOR LOOP STYLE REQUESTS
def parse_playlist(pid, access, numsongs=100):
    """
    Takes in a playlistid and permissions and processes a playlist's songs into a dataframe for processing
    :param pid: a spotify playlistid (string)
    :param access: a spotipy.Spotify object with authorization access
    :param numsongs: the number of songs to consider from the playlist
    :return: a list of [pid, pd.DataFrame of track content]
    """
    thetracks = access.playlist_tracks(playlist_id=pid, limit=numsongs, offset=0)
    trackuris = [track['track']['uri'] for track in thetracks['items']]
    trackfeats = access.audio_features(trackuris)
    if None in trackfeats:
        return "Empty"
    else:
        trackframe = pd.DataFrame(trackfeats)
    return [pid, trackframe]

@app.route('/predictandadd')
def predictandadd():
    cache_handler = spotipy.cache_handler.CacheFileHandler(cache_path=session_cache_path())
    access = spotipy.Spotify(auth_manager = create_oauth())
    
    if not create_oauth().validate_token(cache_handler.get_cached_token()):
        return redirect('/')
    # MODULE 2 WORK MOVED HERE
    allplaylists = []
    someplaylists = access.current_user_playlists(limit=50, offset=0)
    allplaylists.extend(someplaylists['items'])
    # Continue processing playlists until no more exist
    index = 1
    while someplaylists['next'] and index <= 1:
        someplaylists = access.current_user_playlists(limit=50, offset=index * 50)
        allplaylists.extend(someplaylists['items'])
        index += 1

    Userid = access.me()['id']

    # TO DO: STORE ALL PLAYLIST NAMES IN THE SAME ORDER IN A MAPPING FROM PID TO NAME
    pidtoname = {}
    allpackages = []
    for playlist in allplaylists:
        if playlist['owner']['id'] == Userid:
            pid = playlist['id']
            # use playlist ID as the key and store all song ID's in tuples = packages
            packagedplaylist = parse_playlist(pid, access)
            if packagedplaylist != "Empty":
                allpackages.append(packagedplaylist)
                pidtoname[pid] = playlist['name']

        # if it's NOT THE USER'S PLAYLIST, do nothing.

    # MODULE 2 WORK MOVED HERE

    model = pm.DataPipeline(allpackages)

    trackstr = request.args.get('trackurl')
    session[CURRENTTRACKID] = trackstr
    num = int(request.args.get('num'))
    # frozenmodel = session.get(MODEL)
    # model = jsonpickle.decode(frozenmodel)
    # pidtoname = session.get(PIDTONAME)

    trackdict = access.audio_features([trackstr])[0]
    predictions = model.predict(trackdict, num)
    # For each returned pid, map to name using pidtoname.get(pid)

    packages = []
    for i in range(len(predictions)):
        package = {}
        package['name'] = pidtoname[predictions[i][0]]
        package['confidence'] = predictions[i][1]
        package['pid'] = predictions[i][0]
        packages.append(package)


    # for each returned pid, display whether or not the song already exists on that playlist
    return render_template('predictandadd.html', packages=packages)
    #access.playlist_add_items('track_uri')
    # This return will eventually be return render_template('predictandadd.html')

@app.route('/addtoplaylist')
def addtoplaylist():
    token_info = get_token()
    access = spotipy.Spotify(auth=token_info['access_token'])
    pid = request.args.get('pid')
    access.playlist_add_items(pid, [session.get(CURRENTTRACKID)])
    return render_template('successfullyadded.html')