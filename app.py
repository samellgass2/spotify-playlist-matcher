from flask import Flask, request, url_for, session, redirect, render_template
import time
import spotipy
import pandas as pd
from spotipy.oauth2 import SpotifyOAuth
import playlistmatch.playlistmatch as pm
import jsonpickle

app = Flask(__name__)
app.secret_key = "VERYSECRET3892093029543042"
app.config['SESSION_COOKIE_NAME'] = 'User Cookie'
TOKEN_INFO = "Token here"
MODEL = "no model yet initialized"
PIDTONAME = "nothing yet"
CURRENTTRACKID = "none"


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
        redirect_uri=url_for('redirectPage', _external=True)
    )


def get_token():
    """
    Retrieves the token currently stored in the user's cache, or generates a new one if needed
    :return: token_info for use in authorization
    """
    token_info = session.get(TOKEN_INFO, None)
    if not token_info:
        return url_for("authorize", _external=False)
    now = int(time.time())

    expired = token_info['expires_at'] >= now
    if expired:
        oauth = create_oauth()
        token_info = oauth.refresh_access_token(token_info['refresh_token'])
    return token_info


@app.route('/')
def authorize():
    """
    Begins the authorization pipeline
    :return: a redirect to the authorization link
    """
    oauth = create_oauth()
    oauth_url = oauth.get_authorize_url()
    return redirect(oauth_url)


@app.route('/redirect')
def redirectPage():
    """
    After login, or if refreshed, store token info once processed
    :return: a redirect to the main function
    """
    oauth = create_oauth()
    session.clear()
    code = request.args.get('code')
    token_info = oauth.get_access_token(code)
    session[TOKEN_INFO] = token_info
    return redirect(url_for('loadingscreen', _external=True))

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
    token_info = get_token()
    access = spotipy.Spotify(auth=token_info['access_token'])

    # return str(access.current_user_playlists(limit=50, offset=1000)['next'])

    # MODULE 2 BEGINS HERE
    # session[PIDTONAME] = pidtoname
    # frozenmodel = jsonpickle.encode(pm.DataPipeline(allpackages))
    # session[MODEL] = frozenmodel


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
    token_info = get_token()
    access = spotipy.Spotify(auth=token_info['access_token'])

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